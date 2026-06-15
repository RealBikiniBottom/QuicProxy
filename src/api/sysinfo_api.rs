//! 系统信息 API
//!
//! 获取 CPU、内存、磁盘、网络等系统信息。

use std::sync::{Arc, Mutex};

use axum::{
    Router,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Json},
    routing::get,
};
use serde::Serialize;
use sysinfo::{Disks, System};

use super::common::check_auth;

// ─── State ───

#[derive(Clone)]
pub struct SysInfoState {
    pub password: String,
    pub system: Arc<Mutex<System>>,
    pub disks: Arc<Mutex<Disks>>,
}

// ─── Router 构建 ───

pub fn router() -> Router<SysInfoState> {
    Router::new()
        .route("/api/system/info", get(handle_system_info))
        .route("/api/system/cpu", get(handle_cpu))
        .route("/api/system/memory", get(handle_memory))
        .route("/api/system/disks", get(handle_disks))
}

// ─── Response types ───

#[derive(Serialize)]
struct SystemInfoResponse {
    os_name: Option<String>,
    os_version: Option<String>,
    kernel_version: Option<String>,
    host_name: Option<String>,
    cpu_count: usize,
    uptime_secs: u64,
}

#[derive(Serialize)]
struct CpuInfo {
    name: String,
    usage: f32,
    frequency: u64,
}

#[derive(Serialize)]
struct CpuResponse {
    cpus: Vec<CpuInfo>,
    overall_usage: f32,
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
struct DiskInfo {
    name: String,
    mount_point: String,
    total: u64,
    available: u64,
    used: u64,
    kind: String,
    file_system: String,
}

#[derive(Serialize)]
struct DisksResponse {
    disks: Vec<DiskInfo>,
}

// ─── Handlers ───

async fn handle_system_info(
    State(state): State<SysInfoState>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, StatusCode> {
    check_auth(&headers, &state.password)?;

    let mut sys = state.system.lock().unwrap();
    sys.refresh_memory();

    let info = SystemInfoResponse {
        os_name: System::name(),
        os_version: System::os_version(),
        kernel_version: System::kernel_version(),
        host_name: System::host_name(),
        cpu_count: sys.cpus().len(),
        uptime_secs: System::uptime(),
    };

    Ok(Json(info))
}

async fn handle_cpu(
    State(state): State<SysInfoState>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, StatusCode> {
    check_auth(&headers, &state.password)?;

    let mut sys = state.system.lock().unwrap();
    sys.refresh_cpu_usage();

    let cpus: Vec<CpuInfo> = sys
        .cpus()
        .iter()
        .map(|cpu| CpuInfo {
            name: cpu.name().to_string(),
            usage: cpu.cpu_usage(),
            frequency: cpu.frequency(),
        })
        .collect();

    let overall_usage = if cpus.is_empty() {
        0.0
    } else {
        cpus.iter().map(|c| c.usage).sum::<f32>() / cpus.len() as f32
    };

    Ok(Json(CpuResponse { cpus, overall_usage }))
}

async fn handle_memory(
    State(state): State<SysInfoState>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, StatusCode> {
    check_auth(&headers, &state.password)?;

    let mut sys = state.system.lock().unwrap();
    sys.refresh_memory();

    let memory = MemoryResponse {
        total: sys.total_memory(),
        used: sys.used_memory(),
        available: sys.available_memory(),
        free: sys.free_memory(),
        swap_total: sys.total_swap(),
        swap_used: sys.used_swap(),
        swap_free: sys.free_swap(),
    };

    Ok(Json(memory))
}

async fn handle_disks(
    State(state): State<SysInfoState>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, StatusCode> {
    check_auth(&headers, &state.password)?;

    let mut disks = state.disks.lock().unwrap();
    disks.refresh(false);

    let disk_list: Vec<DiskInfo> = disks
        .iter()
        .map(|d| DiskInfo {
            name: d.name().to_string_lossy().to_string(),
            mount_point: d.mount_point().to_string_lossy().to_string(),
            total: d.total_space(),
            available: d.available_space(),
            used: d.total_space() - d.available_space(),
            kind: format!("{:?}", d.kind()),
            file_system: d.file_system().to_string_lossy().to_string(),
        })
        .collect();

    Ok(Json(DisksResponse { disks: disk_list }))
}

