use arc_swap::ArcSwapOption;
use bytesize::ByteSize;
use dashmap::DashMap;
use serde::{Deserialize, Serialize, Serializer};
use sha2::{Digest, Sha224, Sha256};
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use tracing::info;
use uuid::Uuid;

use super::TargetAddr;
use crate::cache::Cache;
use crate::config::AuthUser;
use crate::proxy::inbound::apply_user_change;
use crate::proxy::outbound::{self, AnyOutbound, OUTBOUNDS_MAP};
use crate::proxy::shadowquic_udp::gen_sunny_auth_hash;
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user: Option<Arc<str>>,
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
            user: None,
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

    pub fn with_user(mut self, user: Option<Arc<str>>) -> Self {
        self.user = user;
        self
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
        let selector_tag = if self.protocol == "selector" || self.protocol == "urltest" {
            OUTBOUNDS_MAP
                .get(&self.tag)
                .map(|entry| entry.clone())
                .and_then(|outbound| {
                    outbound
                        .as_selector()
                        .and_then(|selector| selector.get_selected_tag().map(str::to_owned))
                })
        } else {
            None
        };
        let trace = self.trace.read().unwrap_or_else(|e| e.into_inner());
        let field_count = 5 + usize::from(selector_tag.is_some());
        let mut state = serializer.serialize_struct("NodeStats", field_count)?;
        state.serialize_field("tag", &self.tag)?;
        state.serialize_field("protocol", &self.protocol)?;
        state.serialize_field("is_testing_trace", &self.is_testing_trace)?;
        state.serialize_field("stats", &self.stats)?;
        state.serialize_field("trace", &*trace)?;
        if let Some(selector_tag) = selector_tag {
            state.serialize_field("selector_tag", &selector_tag)?;
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
        self.dns_total_time_us
            .load(Ordering::Relaxed)
            .checked_div(count)
            .unwrap_or(0)
    }
    pub fn get_route_avg_time_us(&self) -> u64 {
        let count = self.route_match_count.load(Ordering::Relaxed);
        self.route_total_time_us
            .load(Ordering::Relaxed)
            .checked_div(count)
            .unwrap_or(0)
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

    /// Atomically read and zero the cumulative counters. Each counter is swapped
    /// individually, so concurrent traffic is never lost: bytes counted before
    /// the swap are returned, bytes after it land in the fresh counter.
    pub fn take_traffic(&self) -> TrafficSnapshot {
        TrafficSnapshot {
            upload: self.upload_bytes.swap(0, Ordering::Relaxed),
            download: self.download_bytes.swap(0, Ordering::Relaxed),
            total_tcp: self.total_tcp_conns.swap(0, Ordering::Relaxed),
            total_udp: self.total_udp_conns.swap(0, Ordering::Relaxed),
        }
    }

    /// Overwrite the cumulative counters (used when restoring persisted stats).
    pub fn restore(&self, snapshot: TrafficSnapshot) {
        self.upload_bytes.store(snapshot.upload, Ordering::Relaxed);
        self.download_bytes
            .store(snapshot.download, Ordering::Relaxed);
        self.total_tcp_conns
            .store(snapshot.total_tcp, Ordering::Relaxed);
        self.total_udp_conns
            .store(snapshot.total_udp, Ordering::Relaxed);
    }
}

#[derive(Debug, Clone, Copy, Default, Serialize)]
pub struct TrafficSnapshot {
    pub upload: u64,
    pub download: u64,
    pub total_tcp: u64,
    pub total_udp: u64,
}

/// Compute the credential bytes as they appear on the wire for a protocol.
///
/// trojan: lowercase hex of SHA224(password) (56 ASCII bytes)
/// anytls: SHA256(password) (32 bytes)
/// shadowquic: SHA256("username:password") (64 bytes)
/// vmess: the uuid's 16-byte cmd_key (the username is the uuid)
pub fn credential_hash(protocol: &str, username: &str, password: &str) -> anyhow::Result<Vec<u8>> {
    match protocol {
        "trojan" => {
            let mut hasher = Sha224::new();
            hasher.update(password.as_bytes());
            Ok(hex::encode(hasher.finalize()).into_bytes())
        }
        "anytls" => {
            let mut hasher = Sha256::new();
            hasher.update(password.as_bytes());
            Ok(hasher.finalize().to_vec())
        }
        "shadowquic" => Ok(gen_sunny_auth_hash(username, password).to_vec()),
        "vmess" => {
            let uuid = uuid::Uuid::parse_str(username)
                .map_err(|e| anyhow::anyhow!("invalid vmess uuid '{username}': {e}"))?;
            Ok(crate::proxy::outbound::vmess::vmess_impl::new_id(&uuid)
                .cmd_key
                .to_vec())
        }
        other => anyhow::bail!("protocol '{other}' does not support user management"),
    }
}

/// An authenticated identity: the username plus its shared traffic counters.
/// The inbound owns the credential; the Observer only tracks stats keyed by
/// username, so the same user on different inbounds shares one counter.
#[derive(Clone)]
pub struct UserAccount {
    pub username: Arc<str>,
    pub stats: Arc<Stats>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistedUser {
    pub username: String,
    /// Empty for records written before credential persistence, or for
    /// config-seeded users whose password is re-read from the config on start.
    #[serde(default)]
    pub password: String,
    pub upload: u64,
    pub download: u64,
    pub total_tcp: u64,
    pub total_udp: u64,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct UserStats {
    pub username: String,
    pub upload: u64,
    pub download: u64,
    pub tcp_conns: u64,
    pub udp_conns: u64,
    pub total_tcp: u64,
    pub total_udp: u64,
}

use crate::proxy::SessionCloser;

pub struct Observer {
    inbounds: DashMap<String, Arc<NodeStats>>,
    outbounds: DashMap<String, Arc<NodeStats>>,
    pub realip2domain: Cache<String>,
    user_stats: DashMap<Arc<str>, Arc<Stats>>,
    user_creds: DashMap<(Arc<str>, Arc<str>), Vec<u8>>,
    user_passwords: DashMap<Arc<str>, String>,
    user_cache: Option<Cache<PersistedUser>>,
    global_stats: Arc<Stats>,
    connections: DashMap<Uuid, ConnectionRecord>,
    dst_traffic: DashMap<String, DstTrafficEntry>,
    mem_stats: Mutex<(u64, u64, u64)>,
}

struct ConnectionRecord {
    tracker: Arc<ConnectionTracker>,
    closer: Option<Arc<SessionCloser>>,
}

#[derive(Clone)]
pub struct ConnectionHandle {
    tracker: Arc<ConnectionTracker>,
    _lifecycle: Arc<ConnectionLifecycle>,
}

struct ConnectionLifecycle {
    observer: Arc<Observer>,
    id: Uuid,
}

impl std::ops::Deref for ConnectionHandle {
    type Target = ConnectionTracker;

    fn deref(&self) -> &Self::Target {
        &self.tracker
    }
}

impl Drop for ConnectionLifecycle {
    fn drop(&mut self) {
        self.observer.remove_connection(&self.id);
    }
}

impl Observer {
    pub fn new(cache_name: &str) -> anyhow::Result<Self> {
        let realip2domain = Cache::new_with_tag(cache_name, "observe:realip2domain".to_string())?;
        let user_cache = Cache::new_with_tag(cache_name, "observe:users".to_string()).ok();

        let observer = Self {
            inbounds: DashMap::new(),
            outbounds: DashMap::new(),
            realip2domain,
            user_stats: DashMap::new(),
            user_creds: DashMap::new(),
            user_passwords: DashMap::new(),
            user_cache,
            global_stats: Arc::new(Stats::default()),
            connections: DashMap::new(),
            dst_traffic: DashMap::new(),
            mem_stats: Mutex::new((0, 0, 0)),
        };
        observer.load_persisted_users();
        Ok(observer)
    }

    #[cfg(test)]
    fn test_cache_db_path() -> String {
        use std::sync::atomic::AtomicUsize;
        static SEQ: AtomicUsize = AtomicUsize::new(0);
        std::env::temp_dir()
            .join(format!(
                "quicproxy-observe-test-{}-{}.db",
                std::process::id(),
                SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            ))
            .to_string_lossy()
            .into_owned()
    }

    #[cfg(test)]
    pub(crate) fn new_for_test() -> Arc<Self> {
        Arc::new(Self {
            inbounds: DashMap::new(),
            outbounds: DashMap::new(),
            realip2domain: Cache::new(
                Self::test_cache_db_path(),
                "observe:test:realip2domain".to_string(),
                1,
            )
            .expect("create observer test cache"),
            user_stats: DashMap::new(),
            user_creds: DashMap::new(),
            user_passwords: DashMap::new(),
            user_cache: None,
            global_stats: Arc::new(Stats::default()),
            connections: DashMap::new(),
            dst_traffic: DashMap::new(),
            mem_stats: Mutex::new((0, 0, 0)),
        })
    }

    pub fn add_connection(
        self: &Arc<Self>,
        mut conn: ConnectionTracker,
        closer: Option<Arc<SessionCloser>>,
    ) -> ConnectionHandle {
        conn.domain = self.resolve_domain_for_target(&conn.final_target);
        let tracker = Arc::new(conn);
        self.connections.insert(
            tracker.id,
            ConnectionRecord {
                tracker: tracker.clone(),
                closer,
            },
        );
        ConnectionHandle {
            _lifecycle: Arc::new(ConnectionLifecycle {
                observer: self.clone(),
                id: tracker.id,
            }),
            tracker,
        }
    }

    fn resolve_domain_for_target(&self, target: &TargetAddr) -> Option<String> {
        let TargetAddr::Ip(addr) = target else {
            return None;
        };

        self.realip2domain
            .get(&addr.ip().to_string())
            .ok()
            .flatten()
            .and_then(|domain| {
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

        let ip = match &conn.final_target {
            TargetAddr::Ip(addr) => addr.to_string(),
            TargetAddr::Domain(..) => String::new(),
        };
        match self.dst_traffic.entry(domain.clone()) {
            dashmap::mapref::entry::Entry::Occupied(mut occupied) => {
                let entry = occupied.get_mut();
                entry.upload = entry.upload.saturating_add(upload);
                entry.download = entry.download.saturating_add(download);
                entry.last_active = now;
                if !ip.is_empty() {
                    entry.ip = ip;
                }
                if !outbound_tag.is_empty() {
                    entry.outbound_tag = outbound_tag;
                }
            }
            dashmap::mapref::entry::Entry::Vacant(vacant) => {
                vacant.insert(DstTrafficEntry {
                    domain,
                    ip,
                    outbound_tag,
                    upload,
                    download,
                    last_active: now,
                });
            }
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
        // Remove the keys seen by this snapshot one by one. Updates that win the
        // race are included in this batch; entries inserted afterwards remain for
        // the next drain instead of being erased by a map-wide clear().
        let keys: Vec<String> = self
            .dst_traffic
            .iter()
            .map(|entry| entry.key().clone())
            .collect();
        let mut entries: Vec<DstTrafficEntry> = keys
            .into_iter()
            .filter_map(|key| self.dst_traffic.remove(&key).map(|(_, entry)| entry))
            .collect();
        entries.sort_unstable_by(|a, b| a.domain.cmp(&b.domain));
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
        self.update_outbound_node_traffic(tag, upload, download);
        self.update_global_traffic(upload, download);
    }

    pub(crate) fn update_outbound_node_traffic(&self, tag: &str, upload: u64, download: u64) {
        if let Some(node) = self.outbounds.get(tag) {
            node.stats.add_traffic(upload, download);
        }
    }

    pub(crate) fn global_stats_arc(&self) -> Arc<Stats> {
        self.global_stats.clone()
    }

    pub fn update_global_traffic(&self, upload: u64, download: u64) {
        self.global_stats.add_traffic(upload, download);
    }

    pub fn update_inbound_traffic(&self, tag: &str, upload: u64, download: u64) {
        if let Some(node) = self.inbounds.get(tag) {
            node.stats.add_traffic(upload, download);
        }
    }

    pub fn register_inbound(&self, tag: &str, protocol: &str) {
        self.inbounds
            .entry(tag.to_string())
            .or_insert_with(|| NodeStats::new(tag, protocol));
    }

    pub fn register_outbound(&self, tag: &str, protocol: &str) {
        self.outbounds
            .entry(tag.to_string())
            .or_insert_with(|| NodeStats::new(tag, protocol));
    }

    pub fn upsert_user(&self, username: &str) -> Arc<Stats> {
        self.user_stats
            .entry(Arc::from(username))
            .or_insert_with(|| Arc::new(Stats::default()))
            .clone()
    }

    pub fn set_user_credential(&self, tag: &str, username: &str, credential: Vec<u8>) {
        self.user_creds
            .insert((Arc::from(tag), Arc::from(username)), credential);
    }

    /// Remember a user's plaintext password so it can be re-applied to inbounds
    /// on the next start and re-written when persisting stats.
    pub fn set_user_password(&self, username: &str, password: &str) {
        self.user_passwords
            .insert(Arc::from(username), password.to_string());
    }

    /// Users recovered from the observe cache, ready to be re-registered on the
    /// inbounds that support user management.
    pub fn persisted_users(&self) -> Vec<AuthUser> {
        self.user_passwords
            .iter()
            .map(|entry| AuthUser {
                username: entry.key().to_string(),
                password: entry.value().clone(),
            })
            .collect()
    }

    pub fn user_account(&self, username: &str) -> Option<UserAccount> {
        self.user_stats.get(username).map(|stats| UserAccount {
            username: Arc::from(username),
            stats: stats.value().clone(),
        })
    }

    pub fn authenticate(&self, tag: &str, credential: &[u8]) -> Option<(String, Arc<Stats>)> {
        self.user_creds
            .iter()
            .find(|e| e.key().0.as_ref() == tag && e.value() == credential)
            .map(|e| (e.key().1.to_string(), e.value().clone()))
            .and_then(|(username, _)| {
                let stats = self.user_stats.get(username.as_str())?;
                Some((username, stats.value().clone()))
            })
    }

    pub fn user_stats(&self, username: &str) -> Option<Arc<Stats>> {
        self.user_stats.get(username).map(|e| e.value().clone())
    }

    pub fn all_user_stats(&self) -> Vec<(String, Arc<Stats>)> {
        self.user_stats
            .iter()
            .map(|e| (e.key().to_string(), e.value().clone()))
            .collect()
    }

    pub async fn add_user(&self, username: &str, password: &str) -> anyhow::Result<()> {
        let user = AuthUser {
            username: username.to_string(),
            password: password.to_string(),
        };
        apply_user_change(&user, false).await?;
        for entry in self.inbounds.iter() {
            let protocol = &entry.value().protocol;
            if let Ok(credential) = credential_hash(protocol, username, password) {
                self.set_user_credential(entry.key(), username, credential);
            }
        }
        self.upsert_user(username);
        self.user_passwords
            .insert(Arc::from(username), password.to_string());
        self.save_persisted(username);
        Ok(())
    }

    pub async fn remove_user(&self, username: &str) -> anyhow::Result<bool> {
        if !self.user_stats.contains_key(username) {
            return Ok(false);
        }
        apply_user_change(
            &AuthUser {
                username: username.to_string(),
                password: String::new(),
            },
            true,
        )
        .await?;
        self.user_stats.remove(username);
        self.user_passwords.remove(username);
        let tags: Vec<Arc<str>> = self
            .user_creds
            .iter()
            .filter(|e| e.key().1.as_ref() == username)
            .map(|e| e.key().0.clone())
            .collect();
        for tag in tags {
            self.user_creds.remove(&(tag, Arc::from(username)));
        }
        if let Some(cache) = &self.user_cache {
            let _ = cache.delete(username);
        }
        self.kill_connections_by_user(username);
        Ok(true)
    }

    pub fn kill_connections_by_user(&self, username: &str) {
        let to_close: Vec<Uuid> = self
            .connections
            .iter()
            .filter(|e| e.value().tracker.user.as_deref() == Some(username))
            .map(|e| *e.key())
            .collect();
        for id in to_close {
            if let Some(record) = self.connections.get(&id)
                && let Some(closer) = &record.closer
            {
                closer.close();
            }
        }
    }

    pub fn collect_user_stats(&self, username: Option<&str>, clear: bool) -> Vec<UserStats> {
        let mut result: Vec<UserStats> = Vec::new();
        for entry in self.user_stats.iter() {
            let name = entry.key();
            let stats = entry.value();
            if let Some(filter) = username
                && name.as_ref() != filter
            {
                continue;
            }
            let snapshot = if clear {
                stats.take_traffic()
            } else {
                TrafficSnapshot {
                    upload: stats.get_upload_bytes(),
                    download: stats.get_download_bytes(),
                    total_tcp: stats.get_total_tcp_conns(),
                    total_udp: stats.get_total_udp_conns(),
                }
            };
            result.push(UserStats {
                username: name.to_string(),
                upload: snapshot.upload,
                download: snapshot.download,
                total_tcp: snapshot.total_tcp,
                total_udp: snapshot.total_udp,
                tcp_conns: stats.get_active_tcp_conns(),
                udp_conns: stats.get_active_udp_sessions(),
            });
        }
        result
    }

    fn save_persisted(&self, username: &str) {
        let Some(cache) = &self.user_cache else {
            return;
        };
        let Some(stats) = self.user_stats.get(username) else {
            return;
        };
        let password = self
            .user_passwords
            .get(username)
            .map(|entry| entry.value().clone())
            .unwrap_or_default();
        let persisted = PersistedUser {
            username: username.to_string(),
            password,
            upload: stats.get_upload_bytes(),
            download: stats.get_download_bytes(),
            total_tcp: stats.get_total_tcp_conns(),
            total_udp: stats.get_total_udp_conns(),
        };
        if let Err(e) = cache.set(username, &persisted) {
            tracing::error!("persist user '{}' failed: {}", username, e);
        }
    }

    fn load_persisted_users(&self) {
        let Some(cache) = &self.user_cache else {
            return;
        };
        let entries = match cache.list() {
            Ok(entries) => entries,
            Err(e) => {
                tracing::error!("load persisted users failed: {}", e);
                return;
            }
        };
        for (_key, p) in entries {
            let stats = self
                .user_stats
                .entry(Arc::from(p.username.as_str()))
                .or_insert_with(|| Arc::new(Stats::default()))
                .clone();
            stats.restore(TrafficSnapshot {
                upload: p.upload,
                download: p.download,
                total_tcp: p.total_tcp,
                total_udp: p.total_udp,
            });
            if !p.password.is_empty() {
                self.user_passwords
                    .insert(Arc::from(p.username.as_str()), p.password);
            }
        }
    }

    fn persist_users(&self) {
        for (username, _) in self.all_user_stats() {
            self.save_persisted(&username);
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
            let mut trace = node.trace.write().unwrap_or_else(|e| e.into_inner());
            trace.ip = ip.into();
            trace.loc = loc.into();
            trace.uplink_path_stats = uplink_path_stats;
            trace.downlink_path_stats = downlink_path_stats;
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
        let guard = trace.read().unwrap_or_else(|e| e.into_inner());
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

        if let Some(current_mem) = get_memory_usage()
            && current_mem > 0
        {
            let mut mem_stats = self.mem_stats.lock().unwrap_or_else(|e| e.into_inner());
            mem_stats.1 = mem_stats.1.saturating_add(1);
            mem_stats.0 = mem_stats.0.saturating_add(current_mem);
            mem_stats.2 = mem_stats.2.max(current_mem);
            info!(
                "  [Memory]: Cur: {}, Avg: {}, Peak: {}",
                ByteSize(current_mem),
                ByteSize(mem_stats.0 / mem_stats.1),
                ByteSize(mem_stats.2)
            );
        }
        info!("--------------------------");
        self.persist_users();
    }

    pub fn spawn_periodic_log(self: &Arc<Self>, interval_secs: u64) -> anyhow::Result<()> {
        if interval_secs == 0 {
            anyhow::bail!("observe log_interval must be greater than zero");
        }

        let observer = self.clone();
        shutdown::spawn(async move {
            let period = std::time::Duration::from_secs(interval_secs);
            let start = tokio::time::Instant::now() + period;
            let mut interval = tokio::time::interval_at(start, period);
            loop {
                interval.tick().await;
                observer.log_statistics();
            }
        });
        Ok(())
    }
}

static GLOBAL_OBSERVER: ArcSwapOption<Observer> = ArcSwapOption::const_empty();

pub fn init_observer(cfg: &crate::config::Config) -> anyhow::Result<()> {
    if let Some(obs_cfg) = cfg.observe.as_ref()
        && obs_cfg.enabled
    {
        let cache_name = obs_cfg
            .cache
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("observe requires cache"))?;
        let observer = Arc::new(Observer::new(cache_name)?);
        observer.spawn_periodic_log(obs_cfg.log_interval)?;
        GLOBAL_OBSERVER.store(Some(observer));
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
    use std::sync::Barrier;
    use std::thread;

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

    #[test]
    fn node_stats_serialization_tolerates_missing_selector() {
        let stats = NodeStats::new("missing-selector", "selector");
        let value = serde_json::to_value(stats).unwrap();

        assert_eq!(value["tag"], "missing-selector");
        assert!(value.get("selector_tag").is_none());
    }

    #[test]
    fn public_outbound_traffic_update_includes_global_totals_once() {
        let observer = Observer::new_for_test();
        observer.register_outbound("direct", "direct");

        observer.update_outbound_traffic("direct", 10, 20);

        let outbound = observer.get_outbound_stats("direct").unwrap();
        assert_eq!(outbound.stats.get_upload_bytes(), 10);
        assert_eq!(outbound.stats.get_download_bytes(), 20);
        assert_eq!(observer.global_stats.get_upload_bytes(), 10);
        assert_eq!(observer.global_stats.get_download_bytes(), 20);
    }

    #[test]
    fn destination_traffic_aggregation_is_concurrent_and_lossless() {
        const CONNECTIONS: usize = 16;

        let observer = Observer::new_for_test();
        let barrier = Arc::new(Barrier::new(CONNECTIONS));
        let mut workers = Vec::with_capacity(CONNECTIONS);

        for _ in 0..CONNECTIONS {
            let observer = observer.clone();
            let barrier = barrier.clone();
            workers.push(thread::spawn(move || {
                let tracker = ConnectionTracker::new(
                    Arc::from("mixed"),
                    vec!["direct".to_string()],
                    None,
                    TargetAddr::Domain("example.org".to_string(), 443),
                    TargetAddr::Domain("example.org".to_string(), 443),
                    false,
                    false,
                );
                let tracker = observer.add_connection(tracker, None);
                tracker.inc_upload(10);
                tracker.inc_download(20);

                barrier.wait();
                observer.remove_connection(&tracker.id);
            }));
        }

        for worker in workers {
            worker.join().unwrap();
        }

        let entries = observer.drain_dst_traffic();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].upload, CONNECTIONS as u64 * 10);
        assert_eq!(entries[0].download, CONNECTIONS as u64 * 20);
        assert!(observer.drain_dst_traffic().is_empty());
    }

    #[test]
    fn periodic_log_rejects_zero_interval() {
        let observer = Observer::new_for_test();
        let error = observer.spawn_periodic_log(0).unwrap_err();

        assert!(error.to_string().contains("greater than zero"));
    }

    #[test]
    fn credential_hash_matches_protocol_wire_format() {
        assert_eq!(
            credential_hash("trojan", "default", "secret")
                .unwrap()
                .len(),
            56
        );
        assert_eq!(
            credential_hash("anytls", "default", "secret")
                .unwrap()
                .len(),
            32
        );
        assert_eq!(
            credential_hash("shadowquic", "alice", "secret")
                .unwrap()
                .len(),
            64
        );
        assert!(credential_hash("socks5", "a", "b").is_err());
    }

    #[test]
    fn take_traffic_swaps_cumulative_counters_only() {
        let stats = Stats::default();
        stats.add_traffic(10, 20);
        stats.inc_active_tcp();

        let snapshot = stats.take_traffic();

        assert_eq!(snapshot.upload, 10);
        assert_eq!(snapshot.download, 20);
        assert_eq!(snapshot.total_tcp, 1);
        assert_eq!(stats.get_upload_bytes(), 0);
        assert_eq!(stats.get_download_bytes(), 0);
        assert_eq!(stats.get_total_tcp_conns(), 0);
        // Active connections are live state and must survive a reset.
        assert_eq!(stats.get_active_tcp_conns(), 1);
    }

    #[tokio::test]
    async fn add_remove_and_authenticate_users() {
        let observer = Observer::new_for_test();

        // The Observer only tracks stats; the inbound computes and registers
        // credentials. Mirror that here.
        let stats = observer.upsert_user("alice");
        let trojan_credential = credential_hash("trojan", "alice", "pw").unwrap();
        let shadow_credential = credential_hash("shadowquic", "alice", "pw").unwrap();
        observer.set_user_credential("trojan-a", "alice", trojan_credential.clone());
        observer.set_user_credential("shadow-a", "alice", shadow_credential.clone());

        let (username, _) = observer
            .authenticate("trojan-a", &trojan_credential)
            .expect("trojan user should authenticate");
        assert_eq!(username, "alice");

        assert!(
            observer
                .authenticate("shadow-a", &shadow_credential)
                .is_some()
        );
        assert!(
            observer
                .authenticate("trojan-a", &shadow_credential)
                .is_none()
        );

        stats.add_traffic(5, 7);
        let collected = observer.collect_user_stats(Some("alice"), false);
        assert_eq!(collected.len(), 1);
        assert_eq!(collected[0].upload, 5);
        assert_eq!(collected[0].download, 7);

        let collected = observer.collect_user_stats(Some("alice"), true);
        assert_eq!(collected[0].upload, 5);
        // clear=true zeroes the counters.
        let collected = observer.collect_user_stats(Some("alice"), false);
        assert_eq!(collected[0].upload, 0);

        // remove_user drives inbound registration; here only the stat/cred maps
        // exist, so call apply path via inbounds is skipped, but removal still
        // drops the tracked state.
        assert!(observer.remove_user("alice").await.unwrap());
        assert!(observer.user_stats("alice").is_none());
        assert!(
            observer
                .authenticate("trojan-a", &trojan_credential)
                .is_none()
        );
        assert!(!observer.remove_user("alice").await.unwrap());
    }
}
