//! Core API — 实时监控代理状态、切换节点/模式
//!
//! 仅在 quicproxy 核心进程运行时可用。

use crate::proxy::outbound::{OUTBOUNDS_MAP, get_outbound_by_tag};
use crate::proxy::{
    observe::{Observer, get_observer},
    router::get_router,
};
use crate::utils::http_outbound::request_via_outbound;
use crate::{
    config::RouterMode,
    proxy::inbound::create_tcp_listener,
};
use axum::{
    Router,
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Json},
    routing::{get, put},
};
use hashbrown::HashMap;
use hyper::http::Method;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::mpsc::Sender;
use tracing::{debug, error, info};

use super::common::{check_auth, cors_middleware};

// ─── State ───

#[derive(Clone)]
pub struct CoreApiState {
    pub password: String,
    pub observer: Arc<Observer>,
    pub router: Arc<crate::proxy::router::Router>,
    pub shutdown_tx: Sender<()>,
}

// ─── Router 构建 ───

use anyhow::{Result, bail};
use crate::utils::shutdown;

pub async fn init_core_api(cfg: &crate::config::Config) -> Result<Option<tokio::sync::mpsc::Receiver<()>>> {
    let api = match &cfg.api {
        Some(r) => r.clone(),
        None => {
            debug!("init_core_api");
            return Ok(None);
        }
    };

    let addr_str = format!("{}:{}", api.address, api.port);
    let addr: SocketAddr = addr_str
        .parse()
        .map_err(|e| std::io::Error::other(format!("Invalid API address '{}': {}", addr_str, e)))?;

    let (shutdown_tx, shutdown_rx) = tokio::sync::mpsc::channel(1);

    let app = Router::new()
        .route("/observe", get(get_observe))
        .route("/outbounds", get(get_outbounds))
        .route("/selector", put(put_selector))
        .route("/mode", get(get_mode).put(put_mode))
        .route(
            "/connections",
            get(get_connections).delete(delete_connections),
        )
        .route("/trace", get(get_trace))
        .route("/request", get(get_request))
        .route("/quit", get(get_quit))
        .route("/traffic", get(get_traffic))
        .layer(axum::middleware::from_fn(cors_middleware))
        .with_state(CoreApiState {
            password: api.password,
            shutdown_tx,
            router: get_router(),
            observer: match get_observer() {
                Some(o) => o,
                None => {
                    bail!("require observer.");
                }
            },
        });

    let listener = create_tcp_listener(addr).await?;

    shutdown::spawn(async move {
        info!("Core API server listening on {}", addr);
        if let Err(e) = axum::serve(listener, app).await {
            error!("Core API server error: {}", e);
        }
        info!("Core API server exited");
    });
    debug!("init_core_api");
    Ok(Some(shutdown_rx))
}

// ─── Handler: Connections ───

#[derive(Deserialize)]
struct DeleteConnectionParams {
    id: Option<String>,
    outbound: Option<String>,
    #[serde(default)]
    all: bool,
}

async fn delete_connections(
    State(state): State<CoreApiState>,
    headers: HeaderMap,
    Query(params): Query<DeleteConnectionParams>,
) -> Result<impl IntoResponse, StatusCode> {
    check_auth(&headers, &state.password)?;

    if params.all {
        state.observer.kill_all_connections();
    } else if let Some(id) = &params.id {
        state.observer.kill_connection(id);
    } else if let Some(outbound) = &params.outbound {
        state.observer.kill_connections_by_outbound(outbound);
    } else {
        return Err(StatusCode::BAD_REQUEST);
    }

    Ok(StatusCode::NO_CONTENT)
}

async fn get_connections(
    State(state): State<CoreApiState>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, StatusCode> {
    check_auth(&headers, &state.password)?;

    let connections = state.observer.get_all_connections();
    let data: Vec<ConnectionData> = connections
        .iter()
        .map(|c| ConnectionData {
            id: c.id.clone(),
            inbound_tag: c.inbound_tag.clone(),
            outbound_tag: c.outbound_tag.clone(),
            matched_rule_index: c.matched_rule_index,
            dst: c.final_target.to_string(),
            ip: c.origin_target.to_string(),
            is_fakeip: c.is_fakeip,
            is_udp: c.is_udp,
            upload: c.upload.load(std::sync::atomic::Ordering::Relaxed),
            download: c.download.load(std::sync::atomic::Ordering::Relaxed),
            start_time: c.start_time,
        })
        .collect();
    Ok(Json(data))
}

// ─── Handler: Observe ───

async fn get_observe(
    State(state): State<CoreApiState>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, StatusCode> {
    check_auth(&headers, &state.password)?;

    let mut inbounds = HashMap::new();
    for (tag, node) in state.observer.get_all_inbounds() {
        inbounds.insert(
            tag.clone(),
            StatsData {
                protocol: node.protocol.clone(),
                tcp_conns: node.stats.get_active_tcp_conns(),
                udp_sessions: node.stats.get_active_udp_sessions(),
                upload: node.stats.get_upload_bytes(),
                download: node.stats.get_download_bytes(),
                latency: 0,
                ip: String::new(),
                loc: String::new(),
                outbounds: None,
                selected_node: None,
            },
        );
    }

    let mut outbounds = HashMap::new();
    for (tag, node) in state.observer.get_all_outbounds() {
        let trace = state.observer.get_outbound_trace(&tag);
        let latency = trace
            .as_ref()
            .map(|t| t.latency_us)
            .unwrap_or_else(|| node.stats.get_latency_us());
        let ip = trace.as_ref().map(|t| t.ip.clone()).unwrap_or_default();
        let loc = trace.as_ref().map(|t| t.loc.clone()).unwrap_or_default();
        let (selector_outbounds, selected_node) = OUTBOUNDS_MAP
            .get(&tag)
            .and_then(|entry| {
                let selector = entry.value().as_selector()?;
                Some((
                    Some(selector.get_outbound_tags()),
                    selector.get_selected_tag().map(|s| s.to_string()),
                ))
            })
            .unwrap_or((None, None));

        outbounds.insert(
            tag.clone(),
            StatsData {
                protocol: node.protocol.clone(),
                tcp_conns: node.stats.get_active_tcp_conns(),
                udp_sessions: node.stats.get_active_udp_sessions(),
                upload: node.stats.get_upload_bytes(),
                download: node.stats.get_download_bytes(),
                latency,
                ip,
                loc,
                outbounds: selector_outbounds,
                selected_node,
            },
        );
    }

    let global_stats = state.observer.get_global_stats();
    let memory_usage = crate::utils::system::get_memory_usage().unwrap_or(0);
    let response = ObserveResponse {
        inbounds,
        outbounds,
        dns_avg_time_us: global_stats.get_dns_avg_time_us(),
        route_avg_time_us: global_stats.get_route_avg_time_us(),
        memory_usage,
    };

    Ok(Json(response))
}

// ─── Handler: Mode ───

async fn get_mode(
    State(state): State<CoreApiState>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, StatusCode> {
    check_auth(&headers, &state.password)?;

    let mode = state.router.get_mode().await;
    Ok(Json(serde_json::json!({ "mode": mode })))
}

#[derive(Deserialize)]
struct ModeUpdate {
    mode: RouterMode,
}

async fn put_mode(
    State(state): State<CoreApiState>,
    headers: HeaderMap,
    Json(payload): Json<ModeUpdate>,
) -> Result<impl IntoResponse, StatusCode> {
    check_auth(&headers, &state.password)?;
    state.router.set_mode(payload.mode).await;
    Ok(StatusCode::OK)
}

// ─── Handler: Outbounds ───

async fn get_outbounds(
    State(state): State<CoreApiState>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, StatusCode> {
    check_auth(&headers, &state.password)?;

    // Collect all entries first to avoid lifetime issues with DashMap iterator
    let entries: Vec<_> = OUTBOUNDS_MAP
        .iter()
        .map(|entry| {
            let tag = entry.key().clone();
            let outbound = entry.value().clone();
            (tag, outbound)
        })
        .collect();

    let mut list = Vec::new();
    for (tag, outbound) in entries {
        let default_latency = state
            .observer
            .get_outbound_stats(&tag)
            .map(|n| n.stats.get_latency_us())
            .unwrap_or(0);

        let trace = state.observer.get_outbound_trace(&tag);
        let latency = trace
            .as_ref()
            .map(|t| t.latency_us)
            .unwrap_or(default_latency);
        let ip = trace.as_ref().map(|t| t.ip.clone()).unwrap_or_default();
        let loc = trace.as_ref().map(|t| t.loc.clone()).unwrap_or_default();
        let (selector_outbounds, selected_node) = outbound
            .as_selector()
            .map(|selector| {
                (
                    Some(selector.get_outbound_tags()),
                    selector.get_selected_tag().map(|s| s.to_string()),
                )
            })
            .unwrap_or((None, None));

        let uplink_path_stats = trace.as_ref().and_then(|t| t.uplink_path_stats.clone());
        let downlink_path_stats = trace.as_ref().and_then(|t| t.downlink_path_stats.clone());

        list.push(OutboundInfo {
            tag,
            protocol: outbound.protocol().to_string(),
            latency,
            ip,
            loc,
            outbounds: selector_outbounds,
            selected_node,
            uplink_path_stats,
            downlink_path_stats,
        });
    }

    Ok(Json(list))
}

// ─── Handler: Selector ───

#[derive(Deserialize)]
struct SelectorUpdate {
    outbound: String,
    selected: String,
}

async fn put_selector(
    State(state): State<CoreApiState>,
    headers: HeaderMap,
    Json(payload): Json<SelectorUpdate>,
) -> Result<impl IntoResponse, StatusCode> {
    check_auth(&headers, &state.password)?;

    if let Some(entry) = OUTBOUNDS_MAP.get(&payload.outbound) {
        if let Some(selector) = entry.value().as_selector() {
            if selector.select_by_tag(&payload.selected) {
                return Ok(StatusCode::OK);
            }
            return Err(StatusCode::BAD_REQUEST);
        }
    }
    Err(StatusCode::NOT_FOUND)
}

// ─── Handler: Quit ───

async fn get_quit(
    State(state): State<CoreApiState>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, StatusCode> {
    check_auth(&headers, &state.password)?;
    let _ = state.shutdown_tx.send(()).await;
    Ok(StatusCode::OK)
}

// ─── Handler: Trace ───

#[derive(Deserialize)]
struct TraceParams {
    tag: String,
}

#[derive(Serialize)]
pub struct TraceResponse {
    pub ip: String,
    pub loc: String,
    pub duration_ms: u64,
    pub uplink_path_stats: Option<crate::proxy::outbound::PathState>,
    pub downlink_path_stats: Option<crate::proxy::outbound::PathState>,
}

async fn get_trace(
    State(state): State<CoreApiState>,
    headers: HeaderMap,
    Query(params): Query<TraceParams>,
) -> Result<impl IntoResponse, StatusCode> {
    check_auth(&headers, &state.password)?;

    if let Ok(r) = get_outbound_info(&params.tag, state.observer.clone()).await {
        return Ok(Json(r));
    }
    Err(StatusCode::BAD_GATEWAY)
}

pub async fn get_outbound_info(
    outbound_tag: &str,
    observer: Arc<Observer>,
) -> Result<TraceResponse> {
    let start = std::time::Instant::now();
    let outbound = get_outbound_by_tag(outbound_tag);

    let response = request_via_outbound(
        outbound.clone(),
        Method::GET,
        "https://www.cloudflare.com/cdn-cgi/trace",
        outbound.connect_timeout(),
        3,
        None,
    )
    .await?;

    if !response.status.is_success() {
        bail!("failed to get response")
    }

    let response = String::from_utf8_lossy(&response.body);

    let mut ip = String::new();
    let mut loc = String::new();

    for line in response.lines() {
        if let Some((key, value)) = line.split_once('=') {
            match key.trim() {
                "ip" => ip = value.trim().to_string(),
                "loc" => loc = value.trim().to_string(),
                _ => {}
            }
        }
    }

    if ip.is_empty() || loc.is_empty() {
        bail!("failed to get response")
    }

    let duration_ms = (start.elapsed().as_millis() / 2) as u64;
    let uplink_path_stats = outbound.get_uplink_state().await;
    let downlink_path_stats = outbound.get_downlink_state().await;
    observer.update_outbound_trace(
        outbound_tag,
        duration_ms * 1000,
        ip.clone(),
        loc.clone(),
        uplink_path_stats.clone(),
        downlink_path_stats.clone(),
    );

    Ok(TraceResponse {
        ip,
        loc,
        duration_ms,
        uplink_path_stats,
        downlink_path_stats,
    })
}

// ─── Handler: Request ───

#[derive(Deserialize)]
struct RequestParams {
    tag: String,
    url: String,
    #[serde(default = "default_max_redirects")]
    max_redirects: usize,
}

fn default_max_redirects() -> usize {
    5
}

#[derive(Serialize)]
struct RequestResponse {
    status: u16,
    headers: HashMap<String, String>,
    body: String,
    duration_ms: u64,
}

async fn get_request(
    State(state): State<CoreApiState>,
    headers: HeaderMap,
    Query(params): Query<RequestParams>,
) -> Result<impl IntoResponse, StatusCode> {
    check_auth(&headers, &state.password)?;

    let start = std::time::Instant::now();
    let outbound = get_outbound_by_tag(&params.tag);

    let response = request_via_outbound(
        outbound.clone(),
        Method::GET,
        &params.url,
        outbound.connect_timeout(),
        params.max_redirects,
        None,
    )
    .await
    .map_err(|error| {
        if error
            .downcast_ref::<tokio::time::error::Elapsed>()
            .is_some()
        {
            StatusCode::GATEWAY_TIMEOUT
        } else {
            StatusCode::BAD_GATEWAY
        }
    })?;
    let duration_ms = start.elapsed().as_millis() as u64;

    let mut resp_headers = HashMap::new();
    for (key, value) in response.headers.iter() {
        if let Ok(val_str) = value.to_str() {
            resp_headers.insert(key.as_str().to_string(), val_str.to_string());
        }
    }

    let body = String::from_utf8_lossy(&response.body).to_string();

    Ok(Json(RequestResponse {
        status: response.status.as_u16(),
        headers: resp_headers,
        body,
        duration_ms,
    }))
}

// ─── Handler: Traffic ───

async fn get_traffic(
    State(state): State<CoreApiState>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, StatusCode> {
    check_auth(&headers, &state.password)?;

    Ok(Json(state.observer.drain_dst_traffic()))
}

// ─── Shared types ───

#[derive(Serialize)]
struct StatsData {
    protocol: String,
    tcp_conns: u64,
    udp_sessions: u64,
    upload: u64,
    download: u64,
    latency: u64,
    ip: String,
    loc: String,
    outbounds: Option<Vec<String>>,
    selected_node: Option<String>,
}

#[derive(Serialize)]
struct ConnectionData {
    id: String,
    inbound_tag: String,
    outbound_tag: String,
    matched_rule_index: Option<usize>,
    dst: String,
    ip: String,
    is_fakeip: bool,
    is_udp: bool,
    upload: u64,
    download: u64,
    start_time: u64,
}

#[derive(Serialize)]
struct ObserveResponse {
    inbounds: HashMap<String, StatsData>,
    outbounds: HashMap<String, StatsData>,
    dns_avg_time_us: u64,
    route_avg_time_us: u64,
    memory_usage: u64,
}

#[derive(Serialize)]
struct OutboundInfo {
    tag: String,
    protocol: String,
    latency: u64,
    ip: String,
    loc: String,
    outbounds: Option<Vec<String>>,
    selected_node: Option<String>,
    uplink_path_stats: Option<crate::proxy::outbound::PathState>,
    downlink_path_stats: Option<crate::proxy::outbound::PathState>,
}
