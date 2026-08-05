//! Persist API — 持久化存储 CRUD
//!
//! 提供 web 前端跨标签页/跨设备的状态共享。

use axum::{
    Router,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Json},
    routing::{delete, get},
};
use serde_json::json;

use super::common::check_auth;
use super::persist_store::{PersistStore, SetValueRequest};

// ─── State ───

#[derive(Clone)]
pub struct PersistHandlerState {
    pub persist_store: PersistStore,
    pub password: String,
}

// ─── Router 构建 ───

pub fn router() -> Router<PersistHandlerState> {
    Router::new()
        .route(
            "/api/persist/{key}",
            get(handle_persist_get)
                .put(handle_persist_put)
                .delete(handle_persist_delete),
        )
        .route("/api/persist", delete(handle_persist_delete_multi))
}

// ─── Handlers ───

async fn handle_persist_get(
    State(state): State<PersistHandlerState>,
    headers: HeaderMap,
    Path(key): Path<String>,
) -> Result<impl IntoResponse, StatusCode> {
    check_auth(&headers, &state.password)?;
    match state.persist_store.get(&key) {
        Some(value) => Ok(Json(json!({ "value": value }))),
        None => Err(StatusCode::NOT_FOUND),
    }
}

async fn handle_persist_put(
    State(state): State<PersistHandlerState>,
    headers: HeaderMap,
    Path(key): Path<String>,
    Json(payload): Json<SetValueRequest>,
) -> Result<impl IntoResponse, StatusCode> {
    check_auth(&headers, &state.password)?;
    state.persist_store.set_and_flush(key, payload.value);
    Ok(StatusCode::OK)
}

async fn handle_persist_delete(
    State(state): State<PersistHandlerState>,
    headers: HeaderMap,
    Path(key): Path<String>,
) -> Result<impl IntoResponse, StatusCode> {
    check_auth(&headers, &state.password)?;
    if state.persist_store.delete_and_flush(&key) {
        Ok(StatusCode::OK)
    } else {
        Err(StatusCode::NOT_FOUND)
    }
}

async fn handle_persist_delete_multi(
    State(state): State<PersistHandlerState>,
    headers: HeaderMap,
    Json(keys): Json<Vec<String>>,
) -> Result<impl IntoResponse, StatusCode> {
    check_auth(&headers, &state.password)?;
    state.persist_store.delete_multi_and_flush(keys);
    Ok(StatusCode::OK)
}
