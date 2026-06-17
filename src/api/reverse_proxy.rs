//! 反向代理 — 将核心 API 请求转发到子进程
//!
//! 管理模式下的 quicproxy 将 `/observe`、`/outbounds` 等端点
//! 反向代理到子核心进程的 API 端口。

use axum::{
    extract::State,
    http::{HeaderMap, HeaderName, StatusCode},
    response::{IntoResponse, Response},
};
use reqwest::Client;
use tracing::warn;

use super::core_manager::CoreManager;

// ─── State ───

#[derive(Clone)]
pub struct ProxyState {
    pub core_manager: CoreManager,
    pub client: Client,
}

/// 反向代理 handler：将请求转发到子核心进程
pub async fn proxy_to_core(
    State(state): State<ProxyState>,
    req: axum::extract::Request,
) -> Response {
    let status = state.core_manager.status();
    if !status.running {
        return (StatusCode::SERVICE_UNAVAILABLE, "core not running").into_response();
    }

    let api_port = status.config_api_port;
    let path_and_query = req
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/");
    let target_url = format!("http://127.0.0.1:{}{}", api_port, path_and_query);

    let (parts, body) = req.into_parts();
    let method = parts.method.clone();

    // 收集需要转发的请求头
    let mut req_headers = reqwest::header::HeaderMap::new();
    for (key, value) in &parts.headers {
        if let Ok(v) = value.to_str() {
            if let Ok(k) = reqwest::header::HeaderName::from_bytes(key.as_str().as_bytes()) {
                req_headers.insert(k, reqwest::header::HeaderValue::from_str(v).unwrap());
            }
        }
    }

    let body_bytes = axum::body::to_bytes(body, 1024 * 1024) // 1MB limit
        .await
        .unwrap_or_default();

    let result = match &method {
        m if m == axum::http::Method::GET => {
            state
                .client
                .get(&target_url)
                .headers(req_headers)
                .send()
                .await
        }
        m if m == axum::http::Method::PUT => {
            state
                .client
                .put(&target_url)
                .headers(req_headers)
                .body(body_bytes)
                .send()
                .await
        }
        m if m == axum::http::Method::DELETE => {
            state
                .client
                .delete(&target_url)
                .headers(req_headers)
                .send()
                .await
        }
        m if m == axum::http::Method::POST => {
            state
                .client
                .post(&target_url)
                .headers(req_headers)
                .body(body_bytes)
                .send()
                .await
        }
        _ => {
            return (StatusCode::METHOD_NOT_ALLOWED, "unsupported method").into_response();
        }
    };

    match result {
        Ok(resp) => {
            let resp_status =
                StatusCode::from_u16(resp.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);

            let mut response_headers = HeaderMap::new();
            for (key, value) in resp.headers() {
                if let Some(key) = HeaderName::from_bytes(key.as_str().as_bytes()).ok() {
                    if let Ok(v) = value.to_str() {
                        if let Ok(v) = axum::http::HeaderValue::from_str(v) {
                            response_headers.insert(key, v);
                        }
                    }
                }
            }

            match resp.bytes().await {
                Ok(body) => {
                    let mut response = Response::builder()
                        .status(resp_status)
                        .body(axum::body::Body::from(body))
                        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response());
                    response.headers_mut().extend(response_headers);
                    response
                }
                Err(e) => {
                    warn!("Failed to read upstream body: {}", e);
                    StatusCode::BAD_GATEWAY.into_response()
                }
            }
        }
        Err(e) => {
            warn!("Upstream request to {} failed: {}", target_url, e);
            (StatusCode::BAD_GATEWAY, format!("upstream error: {}", e)).into_response()
        }
    }
}
