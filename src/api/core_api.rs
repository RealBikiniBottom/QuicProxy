//! Core API — 实时监控代理状态、切换节点/模式
//!
//! 仅在 quicproxy 核心进程运行时可用。

use crate::proxy::outbound::{AnyOutbound, OUTBOUNDS_MAP};
use crate::proxy::{
    observe::{NodeStats, Observer, get_observer},
    router::get_router,
};
use crate::utils::http_outbound::request_via_outbound_with_dns;
use crate::{config::RouterMode, proxy::inbound::create_tcp_listener};
use axum::{
    Router,
    extract::{Query, State},
    http::StatusCode,
    response::{IntoResponse, Json},
    routing::{get, put},
};
use hashbrown::HashMap;
use hyper::http::Method;
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex, OnceLock};
use sysinfo::System;
use tokio::sync::mpsc::Sender;
use tracing::{debug, error, info};

use super::common::{auth_middleware, cors_middleware};

// ─── State ───

#[derive(Clone)]
pub struct CoreApiState {
    pub observer: Arc<Observer>,
    pub router: Arc<crate::proxy::router::Router>,
    pub shutdown_tx: Sender<()>,
}

// ─── Router 构建 ───

use crate::utils::shutdown;
use anyhow::{Result, bail};

pub async fn init_core_api(
    cfg: &crate::config::Config,
) -> Result<Option<tokio::sync::mpsc::Receiver<()>>> {
    let api = match &cfg.api {
        Some(r) => r.clone(),
        None => {
            debug!("init_core_api");
            return Ok(None);
        }
    };

    let ip = api.address.parse::<IpAddr>().map_err(|e| {
        std::io::Error::other(format!("Invalid API address '{}': {}", api.address, e))
    })?;
    let addr = SocketAddr::new(ip, api.port);

    let (shutdown_tx, shutdown_rx) = tokio::sync::mpsc::channel(1);
    let password: Arc<str> = Arc::from(api.password);

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
        .route("/version", get(get_runtime_core_version))
        .route_layer(axum::middleware::from_fn_with_state(
            password,
            auth_middleware,
        ))
        .layer(axum::middleware::from_fn(cors_middleware))
        .with_state(CoreApiState {
            shutdown_tx,
            router: get_router()?,
            observer: match get_observer() {
                Some(o) => o,
                None => {
                    bail!("require observer.");
                }
            },
        });

    let listener = create_tcp_listener(addr)?;

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
    Query(params): Query<DeleteConnectionParams>,
) -> Result<impl IntoResponse, StatusCode> {
    if params.all {
        state.observer.kill_all_connections();
    } else if let Some(id) = &params.id {
        if uuid::Uuid::parse_str(id).is_err() {
            return Err(StatusCode::BAD_REQUEST);
        }
        if !state.observer.kill_connection(id) {
            return Err(StatusCode::NOT_FOUND);
        }
    } else if let Some(outbound) = &params.outbound {
        state.observer.kill_connections_by_outbound(outbound);
    } else {
        return Err(StatusCode::BAD_REQUEST);
    }

    Ok(StatusCode::NO_CONTENT)
}

async fn get_connections(
    State(state): State<CoreApiState>,
) -> Result<impl IntoResponse, StatusCode> {
    let connections = state.observer.get_all_connections();
    let data: Vec<ConnectionData> = connections
        .iter()
        .map(|c| ConnectionData {
            id: c.id.to_string(),
            inbound_tag: c.inbound_tag.to_string(),
            outbound_tag: c.outbound_tag.to_string(),
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

async fn get_observe(State(state): State<CoreApiState>) -> Result<impl IntoResponse, StatusCode> {
    let inbounds = state.observer.get_all_inbounds().into_iter().collect();
    let outbounds = state.observer.get_all_outbounds().into_iter().collect();

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

async fn get_mode(State(state): State<CoreApiState>) -> Result<impl IntoResponse, StatusCode> {
    let mode = state.router.get_mode().await;
    Ok(Json(serde_json::json!({ "mode": mode })))
}

#[derive(Deserialize)]
struct ModeUpdate {
    mode: RouterMode,
}

async fn put_mode(
    State(state): State<CoreApiState>,
    Json(payload): Json<ModeUpdate>,
) -> Result<impl IntoResponse, StatusCode> {
    state.router.set_mode(payload.mode).await;
    Ok(StatusCode::OK)
}

// ─── Handler: Outbounds ───

async fn get_outbounds(State(state): State<CoreApiState>) -> Result<impl IntoResponse, StatusCode> {
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
        let latency = state
            .observer
            .get_outbound_stats(&tag)
            .map(|n| n.stats.get_latency_ms() as i64)
            .unwrap_or(0);

        let trace = state.observer.get_outbound_trace(&tag);
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
    Json(payload): Json<SelectorUpdate>,
) -> Result<impl IntoResponse, StatusCode> {
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

async fn get_quit(State(state): State<CoreApiState>) -> Result<impl IntoResponse, StatusCode> {
    let _ = state.shutdown_tx.send(()).await;
    Ok(StatusCode::OK)
}

// ─── Handler: Trace ───

#[derive(Deserialize)]
struct TraceParams {
    tag: String,
    dns: Option<String>,
}

#[derive(Serialize)]
pub struct TraceResponse {
    pub ip: String,
    pub loc: String,
    pub duration_ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub selected_node: Option<String>,
    pub uplink_path_stats: Option<crate::proxy::outbound::PathState>,
    pub downlink_path_stats: Option<crate::proxy::outbound::PathState>,
}

async fn get_trace(
    State(state): State<CoreApiState>,
    Query(params): Query<TraceParams>,
) -> Result<impl IntoResponse, StatusCode> {
    let outbound = OUTBOUNDS_MAP
        .get(&params.tag)
        .map(|entry| entry.value().clone())
        .ok_or(StatusCode::NOT_FOUND)?;

    if let Some(selector) = outbound.as_selector() {
        selector.check_all().await;

        let selected_node = selector.get_selected_tag().map(str::to_owned);
        let selected_tag = selector.get_effective_tag();
        let node_state = state
            .observer
            .get_outbound_stats(&selected_tag)
            .ok_or(StatusCode::BAD_GATEWAY)?;
        let latency = node_state.stats.get_latency_ms() as i64;
        if latency <= 0 {
            return Err(StatusCode::BAD_GATEWAY);
        }
        let trace = state
            .observer
            .get_outbound_trace(&selected_tag)
            .ok_or(StatusCode::BAD_GATEWAY)?;
        state.observer.update_outbound_trace(
            outbound,
            latency,
            trace.ip.clone(),
            trace.loc.clone(),
            trace.uplink_path_stats.clone(),
            trace.downlink_path_stats.clone(),
        );

        return Ok(Json(TraceResponse {
            ip: trace.ip.clone(),
            loc: trace.loc.clone(),
            duration_ms: latency.max(0) as u64,
            selected_node,
            uplink_path_stats: trace.uplink_path_stats.clone(),
            downlink_path_stats: trace.downlink_path_stats.clone(),
        }));
    }

    let dns = params.dns.as_deref().or_else(|| outbound.dns_server_name());
    match get_outbound_info(&params.tag, state.observer.clone(), dns).await {
        Ok(r) => Ok(Json(r)),
        Err(_) => Err(StatusCode::BAD_GATEWAY),
    }
}

struct TraceTestGuard {
    observer: Arc<Observer>,
    outbound: Arc<dyn AnyOutbound>,
    tag: String,
    succeeded: bool,
}

impl TraceTestGuard {
    fn mark_succeeded(&mut self) {
        self.succeeded = true;
    }
}

impl Drop for TraceTestGuard {
    fn drop(&mut self) {
        self.observer.set_outbound_trace_testing(&self.tag, false);
        // Drop also runs when a selector test is aborted by the round timeout.
        if !self.succeeded {
            self.observer
                .update_outbound_trace(self.outbound.clone(), -1, "", "", None, None);
        }
    }
}

pub async fn get_outbound_info(
    outbound_tag: &str,
    observer: Arc<Observer>,
    dns: Option<&str>,
) -> Result<TraceResponse> {
    let start = std::time::Instant::now();
    let outbound = OUTBOUNDS_MAP
        .get(outbound_tag)
        .map(|entry| entry.value().clone())
        .ok_or_else(|| anyhow::anyhow!("outbound not found: {outbound_tag}"))?;

    observer.set_outbound_trace_testing(outbound_tag, true);
    let mut guard = TraceTestGuard {
        observer: observer.clone(),
        outbound: outbound.clone(),
        tag: outbound_tag.to_string(),
        succeeded: false,
    };

    let response = request_via_outbound_with_dns(
        outbound.clone(),
        dns,
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
        outbound,
        (duration_ms) as i64,
        ip.clone(),
        loc.clone(),
        uplink_path_stats.clone(),
        downlink_path_stats.clone(),
    );
    guard.mark_succeeded();

    Ok(TraceResponse {
        ip,
        loc,
        duration_ms,
        selected_node: None,
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

const MAX_RESPONSE_BODY_BYTES: usize = 10 * 1024 * 1024;

async fn get_request(Query(params): Query<RequestParams>) -> Result<impl IntoResponse, StatusCode> {
    let start = std::time::Instant::now();
    let outbound = OUTBOUNDS_MAP
        .get(&params.tag)
        .map(|entry| entry.value().clone())
        .ok_or(StatusCode::NOT_FOUND)?;

    let response = request_via_outbound_with_dns(
        outbound.clone(),
        outbound.dns_server_name(),
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

    if response.body.len() > MAX_RESPONSE_BODY_BYTES {
        return Err(StatusCode::PAYLOAD_TOO_LARGE);
    }

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

async fn get_traffic(State(state): State<CoreApiState>) -> Result<impl IntoResponse, StatusCode> {
    Ok(Json(state.observer.drain_dst_traffic()))
}

// ─── Handler: Version & System Info ───

fn system_instance() -> &'static Mutex<System> {
    static SYSTEM: OnceLock<Mutex<System>> = OnceLock::new();
    SYSTEM.get_or_init(|| Mutex::new(System::new_all()))
}

async fn get_runtime_core_version() -> Result<impl IntoResponse, StatusCode> {
    let mut system = system_instance().lock().unwrap_or_else(|e| e.into_inner());
    system.refresh_memory();

    Ok(Json(build_core_version_response(&system)))
}

fn build_core_version_info() -> CoreVersionInfo {
    CoreVersionInfo {
        version: env!("CARGO_PKG_VERSION"),
        build_date: option_env!("QUICPROXY_BUILD_DATE").unwrap_or("unknown"),
    }
}

fn build_core_version_response(system: &System) -> CoreVersionResponse {
    CoreVersionResponse {
        core: build_core_version_info(),
        system: build_system_info(system),
        memory: build_memory_info(system),
    }
}

fn build_system_info(system: &System) -> SystemInfoResponse {
    SystemInfoResponse {
        os_name: System::name(),
        os_version: System::os_version(),
        kernel_version: System::kernel_version(),
        host_name: System::host_name(),
        arch: std::env::consts::ARCH.to_string(),
        cpu_count: system.cpus().len(),
        uptime_secs: System::uptime(),
    }
}

fn build_memory_info(system: &System) -> MemoryResponse {
    MemoryResponse {
        total: system.total_memory(),
        used: system.used_memory(),
        available: system.available_memory(),
        free: system.free_memory(),
        swap_total: system.total_swap(),
        swap_used: system.used_swap(),
        swap_free: system.free_swap(),
    }
}

// ─── Shared types ───

#[derive(Serialize)]
struct CoreVersionResponse {
    core: CoreVersionInfo,
    system: SystemInfoResponse,
    memory: MemoryResponse,
}

#[derive(Debug, PartialEq, Eq, Serialize)]
struct CoreVersionInfo {
    version: &'static str,
    build_date: &'static str,
}

#[derive(Serialize)]
struct SystemInfoResponse {
    os_name: Option<String>,
    os_version: Option<String>,
    kernel_version: Option<String>,
    host_name: Option<String>,
    arch: String,
    cpu_count: usize,
    uptime_secs: u64,
}

#[derive(Serialize)]
struct MemoryResponse {
    total: u64,
    used: u64,
    available: u64,
    free: u64,
    swap_total: u64,
    swap_used: u64,
    swap_free: u64,
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
    inbounds: HashMap<String, Arc<NodeStats>>,
    outbounds: HashMap<String, Arc<NodeStats>>,
    dns_avg_time_us: u64,
    route_avg_time_us: u64,
    memory_usage: u64,
}

#[derive(Serialize)]
struct OutboundInfo {
    tag: String,
    protocol: String,
    latency: i64,
    ip: String,
    loc: String,
    outbounds: Option<Vec<String>>,
    selected_node: Option<String>,
    uplink_path_stats: Option<crate::proxy::outbound::PathState>,
    downlink_path_stats: Option<crate::proxy::outbound::PathState>,
}

#[cfg(test)]
mod tests {
    use super::build_core_version_info;

    #[test]
    fn core_version_metadata_is_available() {
        let info = build_core_version_info();

        assert_eq!(info.version, env!("CARGO_PKG_VERSION"));
        assert!(!info.build_date.is_empty());
    }
}
