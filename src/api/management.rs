//! Management API — 核心生命周期管理
//!
//! 提供 quicproxy 核心进程的启动/停止/重启/状态/日志 API。

use axum::{
    Router,
    body::Bytes,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Json},
    routing::{get, post, put},
};
use serde_json::json;
use tracing::{error, warn};

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
}

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
