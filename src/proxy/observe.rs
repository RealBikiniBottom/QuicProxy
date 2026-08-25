use arc_swap::ArcSwapOption;
use bytesize::ByteSize;
use dashmap::DashMap;
use serde::{Serialize, Serializer};
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use tracing::info;
use uuid::Uuid;

use super::TargetAddr;
use crate::cache::Cache;
use crate::proxy::outbound::{self, AnyOutbound, get_outbound_by_tag};
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

fn serialize_atomic_i64<S>(val: &AtomicI64, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_i64(val.load(Ordering::Relaxed))
}

#[derive(Debug, Serialize)]
pub struct ConnectionTracker {
    #[serde(serialize_with = "serialize_uuid")]
    pub id: Uuid,
    #[serde(serialize_with = "serialize_shared_str")]
    pub inbound_tag: Arc<str>,
    pub outbound_tag: Vec<String>,
    pub matched_rule_index: Option<usize>,
    pub final_target: TargetAddr,
    pub origin_target: TargetAddr,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
    pub is_fakeip: bool,
    pub is_udp: bool,
    #[serde(serialize_with = "serialize_atomic_u64")]
    pub upload: AtomicU64,
    #[serde(serialize_with = "serialize_atomic_u64")]
    pub download: AtomicU64,
    pub start_time: u64,
}

fn serialize_uuid<S>(value: &Uuid, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.collect_str(value.as_hyphenated())
}

fn serialize_shared_str<S>(value: &Arc<str>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(value)
}

impl ConnectionTracker {
    pub fn new(
        inbound_tag: Arc<str>,
        outbound_tag: Vec<String>,
        matched_rule_index: Option<usize>,
        final_target: TargetAddr,
        origin_target: TargetAddr,
        is_fakeip: bool,
        is_udp: bool,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            inbound_tag,
            outbound_tag,
            matched_rule_index,
            origin_target,
            final_target,
            domain: None,
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

    fn uses_outbound(&self, tag: &str) -> bool {
        self.outbound_tag.iter().any(|outbound| outbound == tag)
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
pub struct NodeStats {
    pub tag: String,
    pub protocol: String,
    pub stats: Arc<Stats>,
    pub is_testing_trace: AtomicBool,
    pub trace: Arc<RwLock<OutboundTraceInfo>>,
}

impl Serialize for NodeStats {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        use serde::ser::SerializeStruct;
        let trace = self.trace.read().unwrap_or_else(|e| e.into_inner());
        let mut state = serializer.serialize_struct("NodeStats", 4)?;
        state.serialize_field("tag", &self.tag)?;
        state.serialize_field("protocol", &self.protocol)?;
        state.serialize_field("is_testing_trace", &self.is_testing_trace)?;
        state.serialize_field("stats", &self.stats)?;
        state.serialize_field("trace", &*trace)?;
        if self.protocol == "selector" || self.protocol == "urltest" {
            let outbound = get_outbound_by_tag(&self.tag);
            if let Some(selector) = outbound.as_selector() {
                if let Some(selected_tag) = selector.get_selected_tag() {
                    state.serialize_field("selector_tag", selected_tag)?;
                }
            }
        }
        state.end()
    }
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct OutboundTraceInfo {
    pub ip: String,
    pub loc: String,
    pub uplink_path_stats: Option<outbound::PathState>,
    pub downlink_path_stats: Option<outbound::PathState>,
}

#[derive(Debug, Serialize)]
pub struct Stats {
    #[serde(serialize_with = "serialize_atomic_u64")]
    active_tcp_conns: AtomicU64,
    #[serde(serialize_with = "serialize_atomic_u64")]
    active_udp_conns: AtomicU64,
    #[serde(serialize_with = "serialize_atomic_u64")]
    total_tcp_conns: AtomicU64,
    #[serde(serialize_with = "serialize_atomic_u64")]
    total_udp_conns: AtomicU64,
    #[serde(serialize_with = "serialize_atomic_u64")]
    upload_bytes: AtomicU64,
    #[serde(serialize_with = "serialize_atomic_u64")]
    download_bytes: AtomicU64,
    // DNS stats (global)
    #[serde(serialize_with = "serialize_atomic_u64")]
    dns_total_time_us: AtomicU64,
    #[serde(serialize_with = "serialize_atomic_u64")]
    dns_query_count: AtomicU64,
    // Route stats (global)
    #[serde(serialize_with = "serialize_atomic_u64")]
    route_total_time_us: AtomicU64,
    #[serde(serialize_with = "serialize_atomic_u64")]
    route_match_count: AtomicU64,
    // Latency (for outbounds)
    #[serde(serialize_with = "serialize_atomic_i64")]
    latency_ms: AtomicI64,
}

impl NodeStats {
    pub fn new(tag: &str, protocol: &str) -> Arc<Self> {
        Arc::new(NodeStats {
            tag: tag.to_string(),
            protocol: protocol.to_string(),
            stats: Arc::new(Stats::default()),
            is_testing_trace: AtomicBool::new(false),
            trace: Arc::new(RwLock::new(OutboundTraceInfo::default())),
        })
    }
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

            latency_ms: AtomicI64::new(0),
        }
    }
}

impl Stats {
    pub fn get_latency_ms(&self) -> i64 {
        self.latency_ms.load(Ordering::Relaxed)
    }

    pub fn record_latency_ms(&self, ms: i64) {
        self.latency_ms.store(ms, Ordering::Relaxed);
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
        self.active_tcp_conns
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
                Some(v.saturating_sub(1))
            })
            .ok();
    }

    pub fn inc_active_udp(&self) {
        self.active_udp_conns.fetch_add(1, Ordering::Relaxed);
        self.total_udp_conns.fetch_add(1, Ordering::Relaxed);
    }

    pub fn dec_active_udp(&self) {
        self.active_udp_conns
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
                Some(v.saturating_sub(1))
            })
            .ok();
    }

    pub fn inc_upload(&self, bytes: u64) {
        self.upload_bytes.fetch_add(bytes, Ordering::Relaxed);
    }

    pub fn inc_download(&self, bytes: u64) {
        self.download_bytes.fetch_add(bytes, Ordering::Relaxed);
    }
}

use crate::proxy::SessionCloser;

pub struct Observer {
    inbounds: DashMap<String, Arc<NodeStats>>,
    outbounds: DashMap<String, Arc<NodeStats>>,
    pub realip2domain: Cache<String>,
    global_stats: Arc<Stats>,
    connections: DashMap<Uuid, ConnectionRecord>,
    dst_traffic: DashMap<String, DstTrafficEntry>,
    mem_stats: Mutex<(u64, u64, u64)>,
}

struct ConnectionRecord {
    tracker: Arc<ConnectionTracker>,
    closer: Option<Arc<SessionCloser>>,
}

impl Observer {
    pub fn new(cache_name: &str) -> anyhow::Result<Self> {
        let realip2domain = Cache::new_with_tag(cache_name, "observe:realip2domain".to_string())?;

        Ok(Self {
            inbounds: DashMap::new(),
            outbounds: DashMap::new(),
            realip2domain,
            global_stats: Arc::new(Stats::default()),
            connections: DashMap::new(),
            dst_traffic: DashMap::new(),
            mem_stats: Mutex::new((0, 0, 0)),
        })
    }

    pub fn add_connection(
        &self,
        mut conn: ConnectionTracker,
        closer: Option<Arc<SessionCloser>>,
    ) -> Arc<ConnectionTracker> {
        conn.domain = self.resolve_domain_for_target(&conn.final_target);
        let tracker = Arc::new(conn);
        self.connections.insert(
            tracker.id,
            ConnectionRecord {
                tracker: tracker.clone(),
                closer,
            },
        );
        tracker
    }

    fn resolve_domain_for_target(&self, target: &TargetAddr) -> Option<String> {
        let TargetAddr::Ip(addr) = target else {
            return None;
        };

        self.realip2domain
            .get(&addr.ip().to_string())
            .ok()
            .flatten()
            .and_then(|(domain, _)| {
                let domain = domain.trim();
                (!domain.is_empty()).then(|| format!("{}:{}", domain, addr.port()))
            })
    }

    pub fn remove_connection(&self, id: &Uuid) {
        let Some((_, record)) = self.connections.remove(id) else {
            return;
        };
        let conn = record.tracker;
        let upload = conn.upload.load(Ordering::Relaxed);
        let download = conn.download.load(Ordering::Relaxed);
        if upload == 0 && download == 0 {
            return;
        }

        let now = now_timestamp();
        let outbound_tag = conn.outbound_tag.first().cloned().unwrap_or_default();

        let domain = conn
            .domain
            .clone()
            .or_else(|| self.resolve_domain_for_target(&conn.final_target))
            .unwrap_or_else(|| conn.final_target.to_string());

        if let Some(mut entry) = self.dst_traffic.get_mut(domain.as_str()) {
            entry.upload = entry.upload.wrapping_add(upload);
            entry.download = entry.download.wrapping_add(download);
            entry.last_active = now;
            if !outbound_tag.is_empty() {
                entry.outbound_tag = outbound_tag;
            }
        } else {
            let ip = match &conn.final_target {
                TargetAddr::Ip(addr) => addr.to_string(),
                TargetAddr::Domain(..) => String::new(),
            };
            self.dst_traffic.insert(
                domain.clone(),
                DstTrafficEntry {
                    domain,
                    ip,
                    outbound_tag,
                    upload,
                    download,
                    last_active: now,
                },
            );
        }
    }

    pub fn kill_connection(&self, id: &str) -> bool {
        let Ok(id) = Uuid::parse_str(id) else {
            return false;
        };
        if let Some(record) = self.connections.get(&id)
            && let Some(closer) = &record.closer
        {
            closer.close();
            true
        } else {
            false
        }
    }

    pub fn kill_all_connections(&self) {
        for record in self.connections.iter() {
            if let Some(closer) = &record.closer {
                closer.close();
            }
        }
    }

    pub fn kill_connections_by_outbound(&self, tag: &str) {
        let to_close: Vec<Uuid> = self
            .connections
            .iter()
            .filter(|entry| entry.value().tracker.uses_outbound(tag))
            .map(|entry| *entry.key())
            .collect();

        info!("{} connection to delete", to_close.len());
        for id in to_close {
            if let Some(record) = self.connections.get(&id)
                && let Some(closer) = &record.closer
            {
                closer.close();
                info!("Closed connection: {}", id);
            }
        }
    }

    pub fn get_all_connections(&self) -> Vec<Arc<ConnectionTracker>> {
        self.connections
            .iter()
            .map(|r| r.value().tracker.clone())
            .collect()
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
            node.stats.dec_active_tcp();
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
            node.stats.dec_active_udp();
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
            node.stats.dec_active_tcp();
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
            node.stats.dec_active_udp();
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
            self.inbounds
                .insert(tag.to_string(), NodeStats::new(tag, protocol));
        }
    }

    pub fn register_outbound(&self, tag: &str, protocol: &str) {
        if !self.outbounds.contains_key(tag) {
            self.outbounds
                .insert(tag.to_string(), NodeStats::new(tag, protocol));
        }
    }

    pub fn update_outbound_trace(
        &self,
        outbound: Arc<dyn AnyOutbound>,
        latency_ms: i64,
        ip: impl Into<String>,
        loc: impl Into<String>,
        uplink_path_stats: Option<outbound::PathState>,
        downlink_path_stats: Option<outbound::PathState>,
    ) {
        if let Some(node) = self.outbounds.get(outbound.tag()) {
            node.stats.record_latency_ms(latency_ms);
            if let Ok(mut trace) = node.trace.write() {
                trace.ip = ip.into();
                trace.loc = loc.into();
                trace.uplink_path_stats = uplink_path_stats;
                trace.downlink_path_stats = downlink_path_stats;
            }
        }
    }

    pub fn set_outbound_trace_testing(&self, tag: &str, testing: bool) {
        if let Some(node) = self.outbounds.get(tag) {
            node.is_testing_trace.store(testing, Ordering::Relaxed);
        }
    }

    pub fn get_outbound_trace(&self, tag: &str) -> Option<OutboundTraceInfo> {
        let node = self.outbounds.get(tag)?;
        let trace = node.trace.clone();
        let guard = trace.read().ok()?;
        Some(guard.clone())
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
                    let latency_ms = node.stats.get_latency_ms();
                    let latency = if latency_ms < 0 {
                        format!("{latency_ms} ms")
                    } else {
                        format_ms(latency_ms as u64)
                    };
                    info!(
                        "  [{}({})]: TCP: {}, UDP: {}, Up: {}, Down: {}, Latency: {}",
                        tag,
                        node.protocol,
                        node.stats.get_active_tcp_conns(),
                        node.stats.get_active_udp_sessions(),
                        ByteSize(node.stats.get_upload_bytes()),
                        ByteSize(node.stats.get_download_bytes()),
                        latency
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

static GLOBAL_OBSERVER: ArcSwapOption<Observer> = ArcSwapOption::const_empty();

pub fn init_observer(cfg: &crate::config::Config) -> anyhow::Result<()> {
    if let Some(obs_cfg) = cfg.observe.as_ref() {
        if obs_cfg.enabled {
            let cache_name = obs_cfg
                .cache
                .as_deref()
                .ok_or_else(|| anyhow::anyhow!("observe requires cache"))?;
            let observer = Arc::new(Observer::new(cache_name)?);
            observer.spawn_periodic_log(obs_cfg.log_interval);
            GLOBAL_OBSERVER.store(Some(observer));
        }
    }
    Ok(())
}

pub fn get_observer() -> Option<Arc<Observer>> {
    GLOBAL_OBSERVER.load_full()
}

pub fn shutdown_observer() {
    GLOBAL_OBSERVER.store(None);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connection_tracker_serializes_core_api_shape() {
        let mut tracker = ConnectionTracker::new(
            Arc::from("mixed"),
            vec![
                "proxy".to_string(),
                "urltest".to_string(),
                "node-a".to_string(),
            ],
            Some(3),
            TargetAddr::Ip("203.0.113.9:443".parse().unwrap()),
            TargetAddr::Ip("198.51.100.7:54321".parse().unwrap()),
            true,
            false,
        );
        tracker.domain = Some("resolved.example:443".to_string());
        tracker.inc_upload(128);
        tracker.inc_download(256);

        let value = serde_json::to_value(tracker).unwrap();

        assert_eq!(
            value["final_target"],
            serde_json::json!({"Ip": "203.0.113.9:443"})
        );
        assert_eq!(
            value["origin_target"],
            serde_json::json!({"Ip": "198.51.100.7:54321"})
        );
        assert_eq!(value["upload"], 128);
        assert_eq!(value["download"], 256);
        assert_eq!(
            value["outbound_tag"],
            serde_json::json!(["proxy", "urltest", "node-a"])
        );
        assert_eq!(value["domain"], "resolved.example:443");
        assert!(value.get("effective_outbound_tag").is_none());
        assert!(value.get("dst").is_none());
        assert!(value.get("ip").is_none());

        let direct_tracker = ConnectionTracker::new(
            Arc::from("mixed"),
            vec!["direct".to_string()],
            None,
            TargetAddr::Domain("example.org".to_string(), 80),
            TargetAddr::Domain("example.org".to_string(), 80),
            false,
            false,
        );
        let direct_value = serde_json::to_value(direct_tracker).unwrap();
        assert_eq!(direct_value["outbound_tag"], serde_json::json!(["direct"]));
        assert!(direct_value.get("domain").is_none());
    }

    #[test]
    fn connection_tracker_matches_nested_selector() {
        let tracker = ConnectionTracker::new(
            Arc::from("mixed"),
            vec![
                "proxy".to_string(),
                "urltest".to_string(),
                "node-a".to_string(),
            ],
            None,
            TargetAddr::Domain("example.org".to_string(), 443),
            TargetAddr::Domain("example.org".to_string(), 443),
            false,
            false,
        );

        assert!(tracker.uses_outbound("proxy"));
        assert!(tracker.uses_outbound("urltest"));
        assert!(tracker.uses_outbound("node-a"));
        assert!(!tracker.uses_outbound("other-urltest"));
    }
}
