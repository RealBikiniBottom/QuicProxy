use bytesize::ByteSize;
use dashmap::DashMap;
use serde::{Serialize, Serializer};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, LazyLock, Mutex, RwLock};
use tracing::info;
use uuid::Uuid;

use crate::proxy::outbound;
use crate::utils::now_timestamp;
use crate::utils::shutdown;
use crate::utils::system::get_memory_usage;
use crate::utils::{format_ms, format_us};

fn serialize_atomic_u64<S>(val: &AtomicU64, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_u64(val.load(Ordering::Relaxed))
}

#[derive(Debug, Serialize)]
pub struct ConnectionTracker {
    pub id: String,
    pub inbound_tag: String,
    pub outbound_tag: String,
    pub matched_rule_index: Option<usize>,
    pub final_target: TargetAddr,
    pub origin_target: TargetAddr,
    pub is_fakeip: bool,
    pub is_udp: bool,
    #[serde(serialize_with = "serialize_atomic_u64")]
    pub upload: AtomicU64,
    #[serde(serialize_with = "serialize_atomic_u64")]
    pub download: AtomicU64,
    pub start_time: u64,
}

impl ConnectionTracker {
    pub fn new(
        inbound_tag: String,
        outbound_tag: String,
        matched_rule_index: Option<usize>,
        final_target: TargetAddr,
        origin_target: TargetAddr,
        is_fakeip: bool,
        is_udp: bool,
    ) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            inbound_tag,
            outbound_tag,
            matched_rule_index,
            origin_target,
            final_target,
            is_fakeip,
            is_udp,
            upload: AtomicU64::new(0),
            download: AtomicU64::new(0),
            start_time: now_timestamp(),
        }
    }
    pub fn inc_upload(&self, bytes: u64) {
        self.upload.fetch_add(bytes, Ordering::Relaxed);
    }
    pub fn inc_download(&self, bytes: u64) {
        self.download.fetch_add(bytes, Ordering::Relaxed);
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct DstTrafficEntry {
    pub domain: String,
    pub ip: String,
    pub outbound_tag: String,
    pub upload: u64,
    pub download: u64,
    pub last_active: u64,
}

#[derive(Debug)]
pub struct Stats {
    active_tcp_conns: AtomicU64,
    active_udp_conns: AtomicU64,
    total_tcp_conns: AtomicU64,
    total_udp_conns: AtomicU64,
    upload_bytes: AtomicU64,
    download_bytes: AtomicU64,
    // DNS stats (global)
    dns_total_time_us: AtomicU64,
    dns_query_count: AtomicU64,
    // Route stats (global)
    route_total_time_us: AtomicU64,
    route_match_count: AtomicU64,
    // Latency (for outbounds)
    latency_total_ms: AtomicU64,
    latency_count: AtomicU64,
}

impl Default for Stats {
    fn default() -> Self {
        Self {
            active_tcp_conns: AtomicU64::new(0),
            active_udp_conns: AtomicU64::new(0),
            total_tcp_conns: AtomicU64::new(0),
            total_udp_conns: AtomicU64::new(0),

            upload_bytes: AtomicU64::new(0),
            download_bytes: AtomicU64::new(0),

            dns_total_time_us: AtomicU64::new(0),
            dns_query_count: AtomicU64::new(0),

            route_total_time_us: AtomicU64::new(0),
            route_match_count: AtomicU64::new(0),

            latency_total_ms: AtomicU64::new(0),
            latency_count: AtomicU64::new(0),
        }
    }
}

impl Stats {
    pub fn get_latency_ms(&self) -> u64 {
        let count = self.latency_count.load(Ordering::Relaxed);
        if count == 0 {
            0
        } else {
            self.latency_total_ms.load(Ordering::Relaxed) / count
        }
    }

    pub fn record_latency_ms(&self, ms: u64) {
        self.latency_total_ms.fetch_add(ms, Ordering::Relaxed);
        self.latency_count.fetch_add(1, Ordering::Relaxed);
    }

    pub fn get_upload_bytes(&self) -> u64 {
        self.upload_bytes.load(Ordering::Relaxed)
    }
    pub fn get_download_bytes(&self) -> u64 {
        self.download_bytes.load(Ordering::Relaxed)
    }
    pub fn get_active_tcp_conns(&self) -> u64 {
        self.active_tcp_conns.load(Ordering::Relaxed)
    }
    pub fn get_active_udp_sessions(&self) -> u64 {
        self.active_udp_conns.load(Ordering::Relaxed)
    }
    pub fn get_total_tcp_conns(&self) -> u64 {
        self.total_tcp_conns.load(Ordering::Relaxed)
    }
    pub fn get_total_udp_conns(&self) -> u64 {
        self.total_udp_conns.load(Ordering::Relaxed)
    }
    pub fn get_dns_avg_time_us(&self) -> u64 {
        let count = self.dns_query_count.load(Ordering::Relaxed);
        if count == 0 {
            0
        } else {
            self.dns_total_time_us.load(Ordering::Relaxed) / count
        }
    }
    pub fn get_route_avg_time_us(&self) -> u64 {
        let count = self.route_match_count.load(Ordering::Relaxed);
        if count == 0 {
            0
        } else {
            self.route_total_time_us.load(Ordering::Relaxed) / count
        }
    }

    pub fn add_traffic(&self, upload: u64, download: u64) {
        self.upload_bytes.fetch_add(upload, Ordering::Relaxed);
        self.download_bytes.fetch_add(download, Ordering::Relaxed);
    }

    pub fn record_dns_time(&self, duration_us: u64) {
        self.dns_total_time_us
            .fetch_add(duration_us, Ordering::Relaxed);
        self.dns_query_count.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_route_time(&self, duration_us: u64) {
        self.route_total_time_us
            .fetch_add(duration_us, Ordering::Relaxed);
        self.route_match_count.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_active_tcp(&self) {
        self.active_tcp_conns.fetch_add(1, Ordering::Relaxed);
        self.total_tcp_conns.fetch_add(1, Ordering::Relaxed);
    }

    pub fn dec_active_tcp(&self) {
        self.active_tcp_conns.fetch_sub(1, Ordering::Relaxed);
    }

    pub fn inc_active_udp(&self) {
        self.active_udp_conns.fetch_add(1, Ordering::Relaxed);
        self.total_udp_conns.fetch_add(1, Ordering::Relaxed);
    }

    pub fn dec_active_udp(&self) {
        self.active_udp_conns.fetch_sub(1, Ordering::Relaxed);
    }

    pub fn inc_upload(&self, bytes: u64) {
        self.upload_bytes.fetch_add(bytes, Ordering::Relaxed);
    }

    pub fn inc_download(&self, bytes: u64) {
        self.download_bytes.fetch_add(bytes, Ordering::Relaxed);
    }
}

#[derive(Debug)]
pub struct NodeStats {
    pub tag: String,
    pub protocol: String,
    pub stats: Arc<Stats>,
}

#[derive(Debug, Clone)]
pub struct OutboundTraceInfo {
    pub ip: String,
    pub loc: String,
    pub latency_ms: i64,
    pub uplink_path_stats: Option<outbound::PathState>,
    pub downlink_path_stats: Option<outbound::PathState>,
}

use crate::proxy::SessionCloser;

use super::TargetAddr;

pub struct Observer {
    inbounds: DashMap<String, Arc<NodeStats>>,
    outbounds: DashMap<String, Arc<NodeStats>>,
    outbound_traces: DashMap<String, OutboundTraceInfo>,
    pub realip2domain: DashMap<String, String>,
    global_stats: Arc<Stats>,
    connections: DashMap<String, Arc<ConnectionTracker>>,
    closers: DashMap<String, Arc<SessionCloser>>,
    dst_traffic: DashMap<String, DstTrafficEntry>,
    mem_stats: Mutex<(u64, u64, u64)>,
}

impl Observer {
    pub fn new() -> Self {
        Self {
            inbounds: DashMap::new(),
            outbounds: DashMap::new(),
            realip2domain: DashMap::new(),
            outbound_traces: DashMap::new(),
            global_stats: Arc::new(Stats::default()),
            connections: DashMap::new(),
            closers: DashMap::new(),
            dst_traffic: DashMap::new(),
            mem_stats: Mutex::new((0, 0, 0)),
        }
    }

    pub fn add_connection(
        &self,
        conn: ConnectionTracker,
        closer: Arc<SessionCloser>,
    ) -> Arc<ConnectionTracker> {
        let tracker = Arc::new(conn);
        self.connections.insert(tracker.id.clone(), tracker.clone());
        self.closers.insert(tracker.id.clone(), closer);
        tracker
    }

    pub fn remove_connection(&self, id: &str) {
        if let Some((_, conn)) = self.connections.remove(id) {
            self.closers.remove(id);
            let upload = conn.upload.load(Ordering::Relaxed);
            let download = conn.download.load(Ordering::Relaxed);
            if upload > 0 || download > 0 {
                let now = now_timestamp();

                let mut ip = "".to_string();
                let domain = match &conn.final_target {
                    TargetAddr::Ip(addr) => {
                        let ip_str = addr.ip().to_string();
                        ip = addr.to_string();
                        self.realip2domain
                            .get(&ip_str)
                            .map(|r| format!("{}:{}", r.value().clone(), addr.port()))
                            .unwrap_or_else(|| "".to_string())
                    }
                    TargetAddr::Domain(..) => conn.final_target.to_string(),
                };

                self.dst_traffic
                    .entry(domain.to_string())
                    .and_modify(|e| {
                        e.upload = e.upload.wrapping_add(upload);
                        e.download = e.download.wrapping_add(download);
                        e.last_active = now;
                        if !conn.outbound_tag.is_empty() {
                            e.outbound_tag = conn.outbound_tag.clone();
                        }
                    })
                    .or_insert(DstTrafficEntry {
                        domain: domain,
                        ip: ip,
                        outbound_tag: conn.outbound_tag.clone(),
                        upload,
                        download,
                        last_active: now,
                    });
            }
        }
    }

    pub fn kill_connection(&self, id: &str) {
        if let Some(closer) = self.closers.get(id) {
            closer.close();
        }
    }

    pub fn kill_all_connections(&self) {
        for closer in self.closers.iter() {
            closer.close();
        }
    }

    pub fn kill_connections_by_outbound(&self, tag: &str) {
        let to_close: Vec<String> = self
            .connections
            .iter()
            .filter(|entry| entry.value().outbound_tag == tag)
            .map(|entry| entry.key().clone())
            .collect();

        info!("{} connection to delete", to_close.len());
        for id in to_close {
            if let Some((_, closer)) = self.closers.remove(&id) {
                closer.close();
                info!("Closed connection: {}", id);
            }
        }
    }

    pub fn get_all_connections(&self) -> Vec<Arc<ConnectionTracker>> {
        self.connections.iter().map(|r| r.value().clone()).collect()
    }

    pub fn drain_dst_traffic(&self) -> Vec<DstTrafficEntry> {
        let entries = self.dst_traffic.iter().map(|r| r.value().clone()).collect();
        self.dst_traffic.clear();
        entries
    }

    pub fn get_global_stats(&self) -> Arc<Stats> {
        self.global_stats.clone()
    }

    pub fn record_dns_time(&self, duration_us: u64) {
        self.global_stats.record_dns_time(duration_us);
    }

    pub fn record_route_time(&self, duration_us: u64) {
        self.global_stats.record_route_time(duration_us);
    }

    pub fn on_inbound_open_tcp(&self, tag: &str) {
        if let Some(node) = self.inbounds.get(tag) {
            node.stats.active_tcp_conns.fetch_add(1, Ordering::Relaxed);
            node.stats.total_tcp_conns.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub fn on_inbound_close_tcp(&self, tag: &str) {
        if let Some(node) = self.inbounds.get(tag) {
            node.stats.active_tcp_conns.fetch_sub(1, Ordering::Relaxed);
        }
    }

    pub fn on_inbound_open_udp(&self, tag: &str) {
        if let Some(node) = self.inbounds.get(tag) {
            node.stats.active_udp_conns.fetch_add(1, Ordering::Relaxed);
            node.stats.total_udp_conns.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub fn on_inbound_close_udp(&self, tag: &str) {
        if let Some(node) = self.inbounds.get(tag) {
            node.stats.active_udp_conns.fetch_sub(1, Ordering::Relaxed);
        }
    }

    pub fn on_outbound_open_tcp(&self, tag: &str) {
        if let Some(node) = self.outbounds.get(tag) {
            node.stats.active_tcp_conns.fetch_add(1, Ordering::Relaxed);
            node.stats.total_tcp_conns.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub fn on_outbound_close_tcp(&self, tag: &str) {
        if let Some(node) = self.outbounds.get(tag) {
            node.stats.active_tcp_conns.fetch_sub(1, Ordering::Relaxed);
        }
    }

    pub fn on_outbound_open_udp(&self, tag: &str) {
        if let Some(node) = self.outbounds.get(tag) {
            node.stats.active_udp_conns.fetch_add(1, Ordering::Relaxed);
            node.stats.total_udp_conns.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub fn on_outbound_close_udp(&self, tag: &str) {
        if let Some(node) = self.outbounds.get(tag) {
            node.stats.active_udp_conns.fetch_sub(1, Ordering::Relaxed);
        }
    }

    pub fn update_outbound_traffic(&self, tag: &str, upload: u64, download: u64) {
        if let Some(node) = self.outbounds.get(tag) {
            node.stats.add_traffic(upload, download);
        }
        self.global_stats.add_traffic(upload, download);
    }

    pub fn update_inbound_traffic(&self, tag: &str, upload: u64, download: u64) {
        if let Some(node) = self.inbounds.get(tag) {
            node.stats.add_traffic(upload, download);
        }
    }

    pub fn register_inbound(&self, tag: &str, protocol: &str) {
        if !self.inbounds.contains_key(tag) {
            self.inbounds.insert(
                tag.to_string(),
                Arc::new(NodeStats {
                    tag: tag.to_string(),
                    protocol: protocol.to_string(),
                    stats: Arc::new(Stats::default()),
                }),
            );
        }
    }

    pub fn register_outbound(&self, tag: &str, protocol: &str) {
        if !self.outbounds.contains_key(tag) {
            self.outbounds.insert(
                tag.to_string(),
                Arc::new(NodeStats {
                    tag: tag.to_string(),
                    protocol: protocol.to_string(),
                    stats: Arc::new(Stats::default()),
                }),
            );
        }
    }

    pub fn update_outbound_latency(&self, tag: &str, latency_ms: i64) {
        if let Some(node) = self.outbounds.get(tag) {
            if latency_ms > 0 {
                node.stats.record_latency_ms(latency_ms as u64);
            }
        }
    }

    pub fn update_outbound_trace(
        &self,
        tag: &str,
        latency_ms: i64,
        ip: impl Into<String>,
        loc: impl Into<String>,
        uplink_path_stats: Option<outbound::PathState>,
        downlink_path_stats: Option<outbound::PathState>,
    ) {
        if let Some(node) = self.outbounds.get(tag) {
            if latency_ms > 0 {
                node.stats.record_latency_ms(latency_ms as u64);
            }
        }
        self.outbound_traces.insert(
            tag.to_string(),
            OutboundTraceInfo {
                ip: ip.into(),
                loc: loc.into(),
                latency_ms,
                uplink_path_stats,
                downlink_path_stats,
            },
        );
    }

    pub fn get_outbound_trace(&self, tag: &str) -> Option<OutboundTraceInfo> {
        self.outbound_traces.get(tag).map(|v| v.value().clone())
    }

    pub fn get_inbound_stats(&self, tag: &str) -> Option<Arc<NodeStats>> {
        self.inbounds.get(tag).map(|v| v.clone())
    }

    pub fn get_outbound_stats(&self, tag: &str) -> Option<Arc<NodeStats>> {
        self.outbounds.get(tag).map(|v| v.clone())
    }

    pub fn get_all_inbounds(&self) -> Vec<(String, Arc<NodeStats>)> {
        self.inbounds
            .iter()
            .map(|r| (r.key().clone(), r.value().clone()))
            .collect()
    }

    pub fn get_all_outbounds(&self) -> Vec<(String, Arc<NodeStats>)> {
        self.outbounds
            .iter()
            .map(|r| (r.key().clone(), r.value().clone()))
            .collect()
    }

    pub fn log_statistics(&self) {
        info!("--- Statistics ---");

        let log_nodes = |label: &str, nodes: Vec<(String, Arc<NodeStats>)>| {
            if !nodes.is_empty() {
                info!("{}:", label);
                for (tag, node) in nodes {
                    info!(
                        "  [{}({})]: TCP: {}, UDP: {}, Up: {}, Down: {}, Latency: {}",
                        tag,
                        node.protocol,
                        node.stats.get_active_tcp_conns(),
                        node.stats.get_active_udp_sessions(),
                        ByteSize(node.stats.get_upload_bytes()),
                        ByteSize(node.stats.get_download_bytes()),
                        format_ms(node.stats.get_latency_ms())
                    );
                }
            }
        };

        log_nodes("Inbounds", self.get_all_inbounds());
        log_nodes("Outbounds", self.get_all_outbounds());

        let gs = self.get_global_stats();
        info!("Others:");
        info!(
            "  [DNS]: {}, [Router]: {}",
            format_us(gs.get_dns_avg_time_us()),
            format_us(gs.get_route_avg_time_us())
        );

        if let Some(current_mem) = get_memory_usage() {
            if current_mem > 0 {
                let mut mem_stats = self.mem_stats.lock().unwrap_or_else(|e| e.into_inner());
                mem_stats.1 += 1;
                mem_stats.0 += current_mem;
                mem_stats.2 = mem_stats.2.max(current_mem);
                info!(
                    "  [Memory]: Cur: {}, Avg: {}, Peak: {}",
                    ByteSize(current_mem),
                    ByteSize(mem_stats.0 / mem_stats.1),
                    ByteSize(mem_stats.2)
                );
            }
        }
        info!("--------------------------");
    }

    pub fn spawn_periodic_log(self: &Arc<Self>, interval_secs: u64) {
        let observer = self.clone();
        shutdown::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(interval_secs));
            loop {
                interval.tick().await;
                observer.log_statistics();
            }
        });
    }
}

static GLOBAL_OBSERVER: LazyLock<RwLock<Option<Arc<Observer>>>> =
    LazyLock::new(|| RwLock::new(None));

pub fn init_observer(cfg: &crate::config::Config) -> anyhow::Result<()> {
    if let Some(obs_cfg) = cfg.observe.as_ref() {
        if obs_cfg.enabled {
            let observer = Arc::new(Observer::new());
            observer.spawn_periodic_log(obs_cfg.log_interval);
            *GLOBAL_OBSERVER
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(observer);
        }
    }
    Ok(())
}

pub fn get_observer() -> Option<Arc<Observer>> {
    GLOBAL_OBSERVER
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone()
}

pub fn shutdown_observer() {
    GLOBAL_OBSERVER
        .write()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .take();
}
