//! Management API — 核心生命周期管理
//!
//! 提供 quicproxy 核心进程的启动/停止/重启/状态/日志 API。

use axum::{
    Router,
    body::{Body, Bytes},
    extract::{Path, RawQuery, State},
    http::{HeaderMap, HeaderValue, Method, StatusCode, header},
    response::{IntoResponse, Json, Response},
    routing::{any, get, post, put},
};
use serde_json::json;
use std::collections::HashMap;
use std::sync::OnceLock;
use std::time::{Duration, Instant};
use tracing::{debug, error, warn};

use super::common::check_auth;
use super::core_manager::{CoreManager, SetConfigRequest, SetCorePathRequest, StartCoreRequest};

// ─── State ───

#[derive(Clone)]
pub struct ManagementState {
    pub core_manager: CoreManager,
    pub password: String,
}

// ─── Router 构建 ───

pub fn router() -> Router<ManagementState> {
    Router::new()
        .route("/api/core/config", put(handle_core_set_config))
        .route("/api/core/path", put(handle_core_set_path))
        .route("/api/core/start", post(handle_core_start))
        .route("/api/core/stop", post(handle_core_stop))
        .route("/api/core/restart", post(handle_core_restart))
        .route("/api/core/status", get(handle_core_status))
        .route("/api/core/workspace", get(handle_core_workspace))
        .route(
            "/api/core/logs",
            get(handle_core_logs).delete(handle_core_clear_logs),
        )
        .route("/api/core/fetch", get(handle_core_fetch))
        .route("/api/core/proxy/{*path}", any(handle_core_proxy))
}

// ─── HTTP 客户端 ───

/// 访问本机 core API 用：不走环境变量里的代理
fn loopback_client() -> &'static reqwest::Client {
    static CLIENT: OnceLock<reqwest::Client> = OnceLock::new();
    CLIENT.get_or_init(|| {
        reqwest::Client::builder()
            .no_proxy()
            .build()
            .unwrap_or_default()
    })
}

/// 拉取订阅等外部 URL 用
fn fetch_client() -> &'static reqwest::Client {
    static CLIENT: OnceLock<reqwest::Client> = OnceLock::new();
    CLIENT.get_or_init(|| {
        reqwest::Client::builder()
            .timeout(FETCH_TIMEOUT)
            .build()
            .unwrap_or_default()
    })
}

const FETCH_TIMEOUT: Duration = Duration::from_secs(20);
const FETCH_MAX_BODY_BYTES: usize = 16 * 1024 * 1024;
const PROXY_TIMEOUT: Duration = Duration::from_secs(120);
const FETCH_USER_AGENT: &str = "quicproxy/sing-box/clash";

// ─── Handlers ───

async fn handle_core_set_config(
    State(state): State<ManagementState>,
    headers: HeaderMap,
    Json(payload): Json<SetConfigRequest>,
) -> Result<impl IntoResponse, StatusCode> {
    check_auth(&headers, &state.password)?;

    match state.core_manager.set_config(payload.config).await {
        Ok(()) => Ok(Json(json!({ "status": "ok" }))),
        Err(e) => {
            warn!("Invalid config: {}", e);
            Err(StatusCode::BAD_REQUEST)
        }
    }
}

async fn handle_core_set_path(
    State(state): State<ManagementState>,
    headers: HeaderMap,
    Json(payload): Json<SetCorePathRequest>,
) -> Result<impl IntoResponse, StatusCode> {
    check_auth(&headers, &state.password)?;
    state.core_manager.set_core_path(payload.core_path).await;
    Ok(Json(json!({ "status": "ok" })))
}

async fn handle_core_start(
    State(state): State<ManagementState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse, StatusCode> {
    check_auth(&headers, &state.password)?;

    let request = if body.is_empty() {
        StartCoreRequest::default()
    } else {
        serde_json::from_slice::<StartCoreRequest>(&body).map_err(|e| {
            warn!("Invalid start payload: {}", e);
            StatusCode::BAD_REQUEST
        })?
    };

    match state.core_manager.start(request).await {
        Ok(()) => Ok(Json(json!({
            "status": "started",
            "pid": state.core_manager.status().pid,
        }))),
        Err(e) => {
            error!("Failed to start core: {}", e);
            Ok(Json(json!({
                "status": "error",
                "message": e.to_string(),
            })))
        }
    }
}

async fn handle_core_stop(
    State(state): State<ManagementState>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, StatusCode> {
    check_auth(&headers, &state.password)?;

    match state.core_manager.stop().await {
        Ok(()) => Ok(Json(json!({ "status": "stopped" }))),
        Err(e) => {
            error!("Failed to stop core: {}", e);
            Ok(Json(json!({
                "status": "error",
                "message": e.to_string(),
            })))
        }
    }
}

async fn handle_core_restart(
    State(state): State<ManagementState>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, StatusCode> {
    check_auth(&headers, &state.password)?;

    match state
        .core_manager
        .restart(StartCoreRequest::default())
        .await
    {
        Ok(()) => Ok(Json(json!({
            "status": "restarted",
            "pid": state.core_manager.status().pid,
        }))),
        Err(e) => {
            error!("Failed to restart core: {}", e);
            Ok(Json(json!({
                "status": "error",
                "message": e.to_string(),
            })))
        }
    }
}

async fn handle_core_status(
    State(state): State<ManagementState>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, StatusCode> {
    check_auth(&headers, &state.password)?;

    let status = state.core_manager.status();
    Ok(Json(json!({
        "running": status.running,
        "pid": status.pid,
        "core_path": status.core_path,
        "work_dir": status.work_dir,
        "config_api_port": status.config_api_port,
    })))
}

async fn handle_core_workspace(
    State(state): State<ManagementState>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, StatusCode> {
    check_auth(&headers, &state.password)?;
    let status = state.core_manager.status();
    Ok(Json(json!({
        "work_dir": status.work_dir,
    })))
}

#[derive(serde::Deserialize)]
struct LogsQuery {
    #[serde(default = "default_log_tail")]
    tail: usize,
    position: Option<u64>,
}

fn default_log_tail() -> usize {
    200
}

async fn handle_core_logs(
    State(state): State<ManagementState>,
    headers: HeaderMap,
    axum::extract::Query(query): axum::extract::Query<LogsQuery>,
) -> Result<impl IntoResponse, StatusCode> {
    check_auth(&headers, &state.password)?;

    if let Some(position) = query.position {
        return match state.core_manager.read_log(position).await {
            Ok(result) => Ok(Json(json!({
                "content": result.content,
                "position": result.position,
            }))),
            Err(error) => {
                error!("Failed to read core log file: {}", error);
                Err(StatusCode::INTERNAL_SERVER_ERROR)
            }
        };
    }

    let logs = state.core_manager.get_logs(Some(query.tail)).await;
    Ok(Json(json!({ "logs": logs })))
}

async fn handle_core_clear_logs(
    State(state): State<ManagementState>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, StatusCode> {
    check_auth(&headers, &state.password)?;

    match state.core_manager.clear_logs().await {
        Ok(()) => Ok(Json(json!({ "status": "cleared" }))),
        Err(error) => {
            error!("Failed to clear core logs: {}", error);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

// ─── 外部 URL 拉取（Web 端获取订阅） ───

#[derive(serde::Deserialize)]
struct FetchQuery {
    url: String,
}

/// 由管理端直接请求外部 URL，返回与 core `/request` 相同结构的 JSON。
/// Web 前端受浏览器同源策略限制，无法直接拉取订阅，core 未运行时走这里。
async fn handle_core_fetch(
    State(state): State<ManagementState>,
    headers: HeaderMap,
    axum::extract::Query(query): axum::extract::Query<FetchQuery>,
) -> Result<impl IntoResponse, StatusCode> {
    check_auth(&headers, &state.password)?;

    let url = reqwest::Url::parse(query.url.trim()).map_err(|_| StatusCode::BAD_REQUEST)?;
    if !matches!(url.scheme(), "http" | "https") {
        return Err(StatusCode::BAD_REQUEST);
    }

    let start = Instant::now();
    let response = fetch_client()
        .get(url)
        .header(header::USER_AGENT, FETCH_USER_AGENT)
        .send()
        .await
        .map_err(|e| {
            warn!("Fetch failed: {}", e);
            if e.is_timeout() {
                StatusCode::GATEWAY_TIMEOUT
            } else {
                StatusCode::BAD_GATEWAY
            }
        })?;

    if response
        .content_length()
        .is_some_and(|len| len as usize > FETCH_MAX_BODY_BYTES)
    {
        return Err(StatusCode::PAYLOAD_TOO_LARGE);
    }

    let status = response.status().as_u16();
    let mut resp_headers = HashMap::new();
    for (key, value) in response.headers() {
        if let Ok(value) = value.to_str() {
            resp_headers.insert(key.as_str().to_string(), value.to_string());
        }
    }

    let mut body = Vec::new();
    let mut response = response;
    while let Some(chunk) = response.chunk().await.map_err(|e| {
        warn!("Fetch body read failed: {}", e);
        StatusCode::BAD_GATEWAY
    })? {
        if body.len() + chunk.len() > FETCH_MAX_BODY_BYTES {
            return Err(StatusCode::PAYLOAD_TOO_LARGE);
        }
        body.extend_from_slice(&chunk);
    }

    Ok(Json(json!({
        "status": status,
        "headers": resp_headers,
        "body": String::from_utf8_lossy(&body),
        "duration_ms": start.elapsed().as_millis() as u64,
    })))
}

// ─── core API 转发 ───

/// 把 `/api/core/proxy/<path>` 转发到本机 core API（`127.0.0.1:<api.port>/<path>`），
/// 并替换为 core 配置里的 API 密码。
///
/// Web 前端只需访问管理端一个地址：core API 只监听在服务器本机回环地址，
/// 浏览器在其他机器上时无法直连；core 重启、端口变化也不影响前端。
async fn handle_core_proxy(
    State(state): State<ManagementState>,
    Path(path): Path<String>,
    RawQuery(query): RawQuery,
    method: Method,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, StatusCode> {
    check_auth(&headers, &state.password)?;

    if !state.core_manager.status().running {
        return Err(StatusCode::SERVICE_UNAVAILABLE);
    }

    let (port, password) = state.core_manager.api_endpoint().await;
    let mut url = format!("http://127.0.0.1:{}/{}", port, path.trim_start_matches('/'));
    if let Some(query) = query.filter(|q| !q.is_empty()) {
        url.push('?');
        url.push_str(&query);
    }

    let mut request = loopback_client()
        .request(method, &url)
        .timeout(PROXY_TIMEOUT);
    if !password.is_empty() {
        request = request.header(header::AUTHORIZATION, password);
    }
    if let Some(content_type) = headers.get(header::CONTENT_TYPE) {
        request = request.header(header::CONTENT_TYPE, content_type.clone());
    }
    if !body.is_empty() {
        request = request.body(body);
    }

    let response = request.send().await.map_err(|e| {
        debug!("Core API proxy to {} failed: {}", url, e);
        if e.is_timeout() {
            StatusCode::GATEWAY_TIMEOUT
        } else {
            StatusCode::BAD_GATEWAY
        }
    })?;

    let status = response.status();
    let content_type = response.headers().get(header::CONTENT_TYPE).cloned();
    let bytes = response.bytes().await.map_err(|_| StatusCode::BAD_GATEWAY)?;

    let mut out = Response::new(Body::from(bytes));
    *out.status_mut() = status;
    if let Some(content_type) = content_type {
        out.headers_mut().insert(header::CONTENT_TYPE, content_type);
    } else {
        out.headers_mut().insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/octet-stream"),
        );
    }
    Ok(out)
}
