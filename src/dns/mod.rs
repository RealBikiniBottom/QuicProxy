use crate::cache::{Cache, CacheWithExpire};
use crate::config::{Config, DnsServerConfig};
use crate::proxy::observe::get_observer;
use crate::proxy::outbound::{AnyOutbound, get_outbound_by_tag};
use crate::proxy::{SourceAddr, TargetAddr};
use crate::utils::{format_duration, now_timestamp};
use anyhow::{Context, Result, anyhow, bail, ensure};
use bytes::Bytes;
use dashmap::DashMap;
use hyper::header::HeaderMap;
use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use simple_dns::rdata::RData;
use simple_dns::{
    CLASS, Name, Packet, PacketFlag, QCLASS, QTYPE, Question, RCODE, ResourceRecord, TYPE,
};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::str::FromStr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, LazyLock};
use std::time::{Duration, Instant};
use tracing::{debug, error, info, warn};

use crate::utils::http_outbound;

static DNS_MAP: LazyLock<DashMap<String, Arc<dyn AnyDNS>>> = LazyLock::new(DashMap::new);
pub type DnsCache = Option<CacheWithExpire<Vec<IpAddr>>>;

pub fn init_dns(cfg: &Config) -> Result<()> {
    ensure!(!cfg.dns.servers.is_empty(), "dns servers can not be empty");

    for (name, item) in cfg.dns.servers.iter() {
        let protocol = item.protocol_type.clone().to_lowercase();
        let name_str = name.clone();

        let out: Arc<dyn AnyDNS> = match protocol.as_str() {
            "fakeip" => FakeIPDNS::new(name_str, item)?,
            "udp" => UdpDns::new(name_str, item)?,
            "https" => HttpsDns::new(name_str, item)?,
            _ => {
                bail!("Unknown dns type: {}", protocol)
            }
        };

        DNS_MAP.insert(name.clone(), out);
    }

    let final_tag: String = match &cfg.dns.default_server {
        Some(tag) => tag.clone(),
        None => DNS_MAP
            .iter()
            .next()
            .map(|entry| entry.key().clone())
            .with_context(
                || "at least one dns server must be registered before setting default_server",
            )?,
    };

    // 先 clone 再 drop Ref（释放 DashMap 读锁），避免 insert 时获取写锁死锁
    let default_dns = match DNS_MAP.get(&final_tag) {
        Some(o) => o.clone(),
        None => {
            bail!("Final dns tag '{}' not found in servers config", final_tag);
        }
    };
    DNS_MAP.insert("default_server".to_string(), default_dns);
    Ok(())
}

/// 关闭所有 DNS 服务器并清空 DNS 缓存，释放底层的 redb 数据库引用。
/// 应在进程退出前调用，确保 redb 文件锁能被正常释放。
pub fn shutdown_dns() {
    DNS_MAP.clear();
}

pub fn get_dns_by_tag(tag: &str) -> Result<Arc<dyn AnyDNS>> {
    match DNS_MAP.get(tag) {
        Some(r) => Ok(r.clone()),
        None => bail!("can not find dns: {}", tag),
    }
}

pub fn get_default_dns() -> Result<Arc<dyn AnyDNS>> {
    get_dns_by_tag("default_server".as_ref())
}

pub async fn resolve_domain(domain: &str, dns_server: Arc<dyn AnyDNS>) -> Result<IpAddr> {
    let now = Instant::now();
    let outbound = dns_server.default_outbound();
    let res = dns_server.lookup(domain, false, &outbound).await?;

    let ip = res
        .first()
        .copied()
        .with_context(|| format!("DNS lookup failed for: {domain}"))?;

    if let Some(observer) = get_observer() {
        observer.record_dns_time(now.elapsed().as_micros() as u64);
        observer
            .realip2domain
            .insert(domain.to_string(), ip.to_string());
    }
    info!(
        "resolved ip: {}, cost: {}",
        ip,
        format_duration(now.elapsed())
    );

    Ok(ip)
}

pub async fn resolve_target_base(
    address: &TargetAddr,
    dns_server: Arc<dyn AnyDNS>,
) -> Result<SocketAddr> {
    match address {
        TargetAddr::Ip(socket_addr) => Ok(*socket_addr),
        TargetAddr::Domain(domain, port) => {
            let ip = resolve_domain(domain, dns_server).await?;
            Ok(SocketAddr::new(ip, *port))
        }
    }
}

pub async fn resolve_target_base2(
    address: &TargetAddr,
    dns_server: Arc<dyn AnyDNS>,
) -> Result<IpAddr> {
    match address {
        TargetAddr::Ip(socket_addr) => Ok(socket_addr.ip()),
        TargetAddr::Domain(domain, _port) => resolve_domain(domain, dns_server).await,
    }
}

pub async fn resolve_target(
    address: &TargetAddr,
    dns_server_tag: Option<&str>,
) -> Result<SocketAddr> {
    if let TargetAddr::Ip(socket_addr) = address {
        return Ok(*socket_addr);
    }

    let dns_server = match dns_server_tag {
        Some(tag) => get_dns_by_tag(tag)?,
        None => get_default_dns()?,
    };

    resolve_target_base(address, dns_server).await
}

pub async fn resolve_str(
    address: &str,
    port: u16,
    dns_server_tag: Option<&str>,
) -> Result<SocketAddr> {
    // 优先尝试直接解析成 IP
    if let Ok(ip) = address.parse::<IpAddr>() {
        return Ok(SocketAddr::new(ip, port));
    }

    // 否则视为域名处理
    let dns_server = match dns_server_tag {
        Some(tag) => get_dns_by_tag(tag)?,
        None => get_default_dns()?,
    };

    let ip = resolve_domain(address, dns_server).await?;
    Ok(SocketAddr::new(ip, port))
}

pub fn build_dns_query_packet(domain: &str, qtype: QTYPE) -> Result<Packet<'_>> {
    let mut packet = Packet::new_query(rand::random());
    packet.set_flags(PacketFlag::RECURSION_DESIRED);
    let question = Question::new(
        Name::new(domain).map_err(|e| anyhow::anyhow!("Invalid domain name: {e}"))?,
        qtype,
        QCLASS::CLASS(CLASS::IN),
        false,
    );
    packet.questions.push(question);
    Ok(packet)
}

pub fn extract_ipv4_from_response(response_bytes: &[u8]) -> Vec<Ipv4Addr> {
    let mut ips = Vec::new();
    let packet = match Packet::parse(response_bytes) {
        Ok(p) => p,
        Err(_) => return ips,
    };

    if packet.rcode() != RCODE::NoError {
        return ips;
    }

    for answer in packet.answers {
        if let RData::A(a) = answer.rdata {
            ips.push(Ipv4Addr::from(a.address));
        }
    }

    ips
}

pub fn extract_ipv6_from_response(response_bytes: &[u8]) -> Vec<Ipv6Addr> {
    let mut ips = Vec::new();
    let packet = match Packet::parse(response_bytes) {
        Ok(p) => p,
        Err(_) => return ips,
    };

    if packet.rcode() != RCODE::NoError {
        return ips;
    }

    for answer in packet.answers {
        if let RData::AAAA(aaaa) = answer.rdata {
            ips.push(Ipv6Addr::from(aaaa.address));
        }
    }

    ips
}

fn apply_ttl_to_response(
    response_bytes: &[u8],
    min_ttl: Option<Duration>,
    max_ttl: Option<Duration>,
) -> Result<Vec<u8>> {
    if min_ttl.is_none() && max_ttl.is_none() {
        return Ok(response_bytes.to_vec());
    }

    let mut packet = Packet::parse(response_bytes)
        .map_err(|e| anyhow::anyhow!("Failed to parse DNS response: {e}"))?
        .to_owned();

    let mut changed = false;
    for answer in &mut packet.answers {
        let is_target = matches!(answer.rdata, RData::A(_) | RData::AAAA(_));
        if !is_target {
            continue;
        }

        let mut effective_ttl = answer.ttl;
        if let Some(min) = min_ttl {
            let min_secs = min.as_secs() as u32;
            if effective_ttl < min_secs {
                effective_ttl = min_secs;
            }
        }
        if let Some(max) = max_ttl {
            let max_secs = max.as_secs() as u32;
            if effective_ttl > max_secs {
                effective_ttl = max_secs;
            }
        }

        if answer.ttl != effective_ttl {
            answer.ttl = effective_ttl;
            changed = true;
        }
    }

    if changed {
        packet
            .build_bytes_vec()
            .map(|b| b.to_vec())
            .map_err(|e| anyhow::anyhow!("Failed to rebuild DNS response: {e}"))
    } else {
        Ok(response_bytes.to_vec())
    }
}

#[async_trait::async_trait]
pub trait AnyDNS: Send + Sync + 'static {
    fn tag(&self) -> &str;
    fn cache(&self) -> &DnsCache;

    async fn exchange_query(
        &self,
        domain: &str,
        qtype: QTYPE,
        outbound: &Arc<dyn AnyOutbound>,
    ) -> Result<Vec<u8>> {
        let packet = build_dns_query_packet(domain, qtype)?;
        let packet_bytes = packet
            .build_bytes_vec()
            .map_err(|e| anyhow::anyhow!("Failed to build DNS query packet: {e}"))?
            .to_vec();
        self.exchange_with_outbound(&packet_bytes, outbound.clone())
            .await
    }

    async fn lookup_with_type(
        &self,
        domain: &str,
        qtype: QTYPE,
        outbound: &Arc<dyn AnyOutbound>,
    ) -> Result<Vec<IpAddr>> {
        let cache_key = match qtype {
            QTYPE::TYPE(TYPE::A) => format!("{}:A", domain),
            QTYPE::TYPE(TYPE::AAAA) => format!("{}:AAAA", domain),
            _ => return Ok(Vec::new()),
        };

        let cache_key = format!("{}:{}", outbound.tag(), cache_key);

        if let Some(cache) = self.cache() {
            if let Ok(Some((ips, remaining_ttl, source))) = cache.get(&cache_key) {
                let remaining = Duration::from_secs(remaining_ttl.saturating_sub(now_timestamp()));
                info!(
                    "hit dns cache from {:?}({}) for {}({:?}) [{}]",
                    source,
                    format_duration(remaining),
                    domain,
                    ips,
                    outbound.tag()
                );
                return Ok(ips);
            }
        }

        let response_bytes = self.exchange_query(domain, qtype, outbound).await?;
        let packet = match Packet::parse(&response_bytes) {
            Ok(p) => p,
            Err(e) => bail!(e),
        };

        let min_ttl = self.min_ttl().map(|t| t.as_secs()).unwrap_or(60);
        if packet.rcode() != RCODE::NoError {
            if let Some(cache) = self.cache() {
                let _ = cache.set(&cache_key, &Vec::new(), min_ttl);
            }
            return Ok(Vec::new());
        }

        let mut ips = Vec::new();
        let mut min_record_ttl = u32::MAX;

        for answer in packet.answers {
            match answer.rdata {
                RData::A(a) if matches!(qtype, QTYPE::TYPE(TYPE::A)) => {
                    ips.push(IpAddr::V4(a.address.into()));
                    if answer.ttl < min_record_ttl {
                        min_record_ttl = answer.ttl;
                    }
                }
                RData::AAAA(aaaa) if matches!(qtype, QTYPE::TYPE(TYPE::AAAA)) => {
                    ips.push(IpAddr::V6(aaaa.address.into()));
                    if answer.ttl < min_record_ttl {
                        min_record_ttl = answer.ttl;
                    }
                }
                _ => {}
            }
        }

        info!(
            "resolved for {}({:?}), ttl: {}s",
            domain, ips, min_record_ttl
        );
        if let Some(cache) = self.cache() {
            let final_ttl = if !ips.is_empty() {
                self.min_ttl()
                    .map(|t| t.as_secs().max(min_record_ttl as u64))
                    .unwrap_or(min_record_ttl as u64)
            } else {
                min_ttl
            };

            let _ = cache.set(&cache_key, &ips, final_ttl);
        }

        Ok(ips)
    }

    async fn lookup(
        &self,
        domain: &str,
        use_ipv6: bool,
        outbound: &Arc<dyn AnyOutbound>,
    ) -> Result<Vec<IpAddr>> {
        if let Ok(ip) = IpAddr::from_str(domain) {
            return Ok(vec![ip]);
        }
        debug!(
            "looking up domain: {} via {}, use ipv6: {}",
            domain,
            self.tag(),
            use_ipv6
        );
        if !use_ipv6 {
            return self
                .lookup_with_type(domain, QTYPE::TYPE(TYPE::A), outbound)
                .await;
        }

        let (v4_res, v6_res) = tokio::join!(
            self.lookup_with_type(domain, QTYPE::TYPE(TYPE::A), outbound),
            self.lookup_with_type(domain, QTYPE::TYPE(TYPE::AAAA), outbound)
        );

        match (v4_res, v6_res) {
            (Ok(v4_ips), Ok(v6_ips)) => {
                let mut all = v6_ips;
                all.extend(v4_ips);
                Ok(all)
            }

            (Ok(v4_ips), Err(e)) => {
                warn!("AAAA lookup failed for {}, fallback to IPv4: {}", domain, e);
                Ok(v4_ips)
            }

            (Err(e), Ok(v6_ips)) => {
                warn!("A lookup failed for {}, fallback to IPv6: {}", domain, e);
                Ok(v6_ips)
            }

            (Err(e4), Err(e6)) => {
                error!(
                    "Both A and AAAA lookups failed for {}. A error: {}, AAAA error: {}",
                    domain, e4, e6
                );
                Err(anyhow!("Dual-stack DNS lookup failed for {domain}"))
            }
        }
    }

    async fn lookup_ipv4(
        &self,
        domain: &str,
        outbound: &Arc<dyn AnyOutbound>,
    ) -> Result<Option<Ipv4Addr>> {
        Ok(self
            .lookup_with_type(domain, QTYPE::TYPE(TYPE::A), outbound)
            .await?
            .into_iter()
            .find_map(|ip| match ip {
                IpAddr::V4(v4) => Some(v4),
                _ => None,
            }))
    }

    async fn lookup_ipv6(
        &self,
        domain: &str,
        outbound: &Arc<dyn AnyOutbound>,
    ) -> Result<Option<Ipv6Addr>> {
        Ok(self
            .lookup_with_type(domain, QTYPE::TYPE(TYPE::AAAA), outbound)
            .await?
            .into_iter()
            .find_map(|ip| match ip {
                IpAddr::V6(v6) => Some(v6),
                _ => None,
            }))
    }

    async fn lookup_ipv4_response(
        &self,
        domain: &str,
        outbound: &Arc<dyn AnyOutbound>,
    ) -> Result<Vec<u8>> {
        let response_bytes = self
            .exchange_query(domain, QTYPE::TYPE(TYPE::A), outbound)
            .await?;
        apply_ttl_to_response(&response_bytes, self.min_ttl(), self.max_ttl())
    }

    async fn lookup_ipv6_response(
        &self,
        domain: &str,
        outbound: &Arc<dyn AnyOutbound>,
    ) -> Result<Vec<u8>> {
        let response_bytes = self
            .exchange_query(domain, QTYPE::TYPE(TYPE::AAAA), outbound)
            .await?;
        apply_ttl_to_response(&response_bytes, self.min_ttl(), self.max_ttl())
    }

    fn dns_server(&self) -> Option<&str> {
        None
    }

    async fn exchange(&self, packet_bytes: &[u8]) -> Result<Vec<u8>> {
        self.exchange_with_outbound(packet_bytes, self.default_outbound())
            .await
    }

    async fn exchange_with_outbound(
        &self,
        packet_bytes: &[u8],
        outbound: Arc<dyn AnyOutbound>,
    ) -> Result<Vec<u8>>;

    fn default_outbound(&self) -> Arc<dyn AnyOutbound>;

    async fn hijack_exchange(&self, packet_bytes: &[u8]) -> Result<Vec<u8>> {
        if self.reject_ipv6() {
            if let Ok(packet) = Packet::parse(packet_bytes) {
                if packet
                    .questions
                    .iter()
                    .any(|q| q.qtype == QTYPE::TYPE(TYPE::AAAA))
                {
                    let mut reply = Packet::new_reply(packet.id());
                    for question in &packet.questions {
                        reply.questions.push(question.clone());
                    }
                    debug!("rejected ipv6 with empty reply");
                    return reply
                        .build_bytes_vec()
                        .map(|b| b.to_vec())
                        .map_err(|e| anyhow!("Failed to build DNS reply: {e}"));
                }
            }
        }
        self.exchange(packet_bytes).await
    }

    fn reject_ipv6(&self) -> bool {
        false
    }

    fn min_ttl(&self) -> Option<Duration>;
    fn max_ttl(&self) -> Option<Duration>;

    async fn reverse(&self, _ip: &IpAddr) -> Option<String> {
        None
    }

    async fn is_fakeip(&self, _ip: &IpAddr) -> bool {
        false
    }
}

pub struct UdpDns {
    pub tag: String,
    pub address: TargetAddr,
    pub min_ttl: Option<Duration>,
    pub max_ttl: Option<Duration>,
    pub outbound: Arc<dyn AnyOutbound>,
    pub cache: DnsCache,
    pub reject_ipv6: bool,
}

impl UdpDns {
    pub fn new(tag: String, cfg: &DnsServerConfig) -> Result<Arc<dyn AnyDNS>> {
        let address = cfg
            .address
            .clone()
            .ok_or_else(|| anyhow!("dns '{}' requires address", tag))?;
        let port = cfg.port.unwrap_or(53);
        let address = TargetAddr::from_str2(&address, port)?;

        let min_ttl = cfg.min_ttl.map(Duration::from_secs);
        let max_ttl = cfg.max_ttl.map(Duration::from_secs);

        let cache = match cfg.cache.as_ref() {
            Some(c) => Some(
                CacheWithExpire::new_with_tag(c, tag.clone())
                    .map_err(|e| anyhow!("dns '{}' failed to init cache: {:?}", tag, e))?,
            ),
            None => None,
        };

        let outbound_tag = cfg
            .outbound
            .as_deref()
            .ok_or_else(|| anyhow!("dns '{}' requires outbound", tag))?;
        let outbound = get_outbound_by_tag(outbound_tag);

        let reject_ipv6 = cfg.reject_ipv6;

        Ok(Arc::new(Self {
            tag,
            address,
            min_ttl,
            max_ttl,
            outbound,
            cache,
            reject_ipv6,
        }))
    }
}

#[async_trait::async_trait]
impl AnyDNS for UdpDns {
    fn tag(&self) -> &str {
        &self.tag
    }

    fn cache(&self) -> &DnsCache {
        &self.cache
    }

    fn reject_ipv6(&self) -> bool {
        self.reject_ipv6
    }

    async fn exchange_with_outbound(
        &self,
        packet_bytes: &[u8],
        outbound: Arc<dyn AnyOutbound>,
    ) -> Result<Vec<u8>> {
        let target = resolve_target(&self.address, self.dns_server()).await?;
        let target = TargetAddr::Ip(target);
        let socket = outbound.connect_packet(&target).await?;

        let buf = bytes::Bytes::copy_from_slice(packet_bytes);

        socket.send_to(buf, &SourceAddr::dummy(), &target).await?;

        let (_, _, payload) = tokio::time::timeout(outbound.connect_timeout(), socket.recv_from())
            .await
            .map_err(|_| anyhow!("DNS query timed out"))??;
        socket.closer().close();

        Ok(payload.to_vec())
    }

    fn default_outbound(&self) -> Arc<dyn AnyOutbound> {
        self.outbound.clone()
    }

    fn min_ttl(&self) -> Option<Duration> {
        self.min_ttl
    }

    fn max_ttl(&self) -> Option<Duration> {
        self.max_ttl
    }
}

pub struct HttpsDns {
    pub tag: String,
    pub min_ttl: Option<Duration>,
    pub max_ttl: Option<Duration>,
    pub outbound: Arc<dyn AnyOutbound>,
    pub cache: DnsCache,
    url: String,
    dns_server_name: Option<String>,
    pub reject_ipv6: bool,
}

impl HttpsDns {
    pub fn new(tag: String, cfg: &DnsServerConfig) -> Result<Arc<dyn AnyDNS>> {
        let address = cfg
            .address
            .clone()
            .ok_or_else(|| anyhow!("dns '{}' requires address", tag))?;
        let port = cfg.port.unwrap_or(443);
        let url = format!("https://{}:{}/dns-query", address, port);

        let min_ttl = cfg.min_ttl.map(Duration::from_secs);
        let max_ttl = cfg.max_ttl.map(Duration::from_secs);

        let cache = match cfg.cache.as_ref() {
            Some(c) => Some(
                CacheWithExpire::new_with_tag(c, tag.clone())
                    .map_err(|e| anyhow!("dns '{}' failed to init cache: {:?}", tag, e))?,
            ),
            None => None,
        };

        let outbound_tag = cfg
            .outbound
            .as_deref()
            .ok_or_else(|| anyhow!("dns '{}' requires outbound", tag))?;
        let outbound = get_outbound_by_tag(outbound_tag);

        let reject_ipv6 = cfg.reject_ipv6;

        Ok(Arc::new(Self {
            tag,
            min_ttl,
            max_ttl,
            outbound,
            dns_server_name: cfg.dns.clone(),
            cache,
            url,
            reject_ipv6,
        }))
    }
}

#[async_trait::async_trait]
impl AnyDNS for HttpsDns {
    fn tag(&self) -> &str {
        &self.tag
    }

    fn cache(&self) -> &DnsCache {
        &self.cache
    }

    fn reject_ipv6(&self) -> bool {
        self.reject_ipv6
    }

    fn dns_server(&self) -> Option<&str> {
        self.dns_server_name.as_deref()
    }

    async fn exchange_with_outbound(
        &self,
        packet_bytes: &[u8],
        outbound: Arc<dyn AnyOutbound>,
    ) -> Result<Vec<u8>> {
        let mut headers = HeaderMap::new();
        headers.insert("Content-Type", "application/dns-message".parse().unwrap());

        let response = http_outbound::request_post_via_outbound(
            outbound.clone(),
            self.dns_server(),
            &self.url,
            outbound.connect_timeout(),
            Some(&headers),
            Bytes::copy_from_slice(packet_bytes),
        )
        .await?;

        if !response.status.is_success() {
            return Err(anyhow::anyhow!(
                "DoH server returned error: {}",
                response.status
            ));
        }

        Ok(response.body.to_vec())
    }

    fn default_outbound(&self) -> Arc<dyn AnyOutbound> {
        self.outbound.clone()
    }

    fn min_ttl(&self) -> Option<Duration> {
        self.min_ttl
    }

    fn max_ttl(&self) -> Option<Duration> {
        self.max_ttl
    }
}

pub type FakeIPCache = Cache<String>;

pub struct FakeIPDNS {
    pub tag: String,
    pub min_ttl: Option<Duration>,
    pub ipv4_cidr: Ipv4Net,
    pub ipv6_cidr: Ipv6Net,
    pub cache: FakeIPCache,
    pub ipv4_cursor: AtomicU64,
    pub ipv6_cursor: AtomicU64,
    pub reject_ipv6: bool,
}

impl FakeIPDNS {
    const IPV4_CURSOR_CACHE_KEY: &'static str = "fakeip_ipv4_cursor_index";
    const IPV6_CURSOR_CACHE_KEY: &'static str = "fakeip_ipv6_cursor_index";

    pub fn new(tag: String, cfg: &DnsServerConfig) -> Result<Arc<dyn AnyDNS>> {
        let min_ttl = cfg.min_ttl.map(Duration::from_secs);

        let default_v4 = Ipv4Net::from_str("198.18.0.0/16").unwrap();
        let default_v6 = Ipv6Net::from_str("fc00::/18").unwrap();

        let mut v4_found = None;
        let mut v6_found = None;

        if let Some(cidr_strings) = &cfg.range {
            for s in cidr_strings {
                if let Ok(net) = IpNet::from_str(s) {
                    match net {
                        IpNet::V4(v4) if v4_found.is_none() => v4_found = Some(v4),
                        IpNet::V6(v6) if v6_found.is_none() => v6_found = Some(v6),
                        _ => {}
                    }
                }
            }
        }

        let ipv6_cidr = v6_found.unwrap_or(default_v6);
        let ipv4_cidr = v4_found.unwrap_or(default_v4);

        let cache_name = cfg
            .cache
            .as_ref()
            .ok_or_else(|| anyhow!("dns '{}' requires cache", tag))?;

        let cache = Cache::new_with_tag(cache_name.as_str(), format!("fakeip:{}", tag))
            .map_err(|e| anyhow!("dns '{}' failed to init cache: {:?}", tag, e))?;

        let ipv4_cursor = Self::load_cursor(&cache, Self::IPV4_CURSOR_CACHE_KEY);
        let ipv6_cursor = Self::load_cursor(&cache, Self::IPV6_CURSOR_CACHE_KEY);

        let reject_ipv6 = cfg.reject_ipv6;

        Ok(Arc::new(Self {
            tag,
            min_ttl,
            ipv4_cidr,
            ipv6_cidr,
            cache,
            ipv4_cursor: AtomicU64::new(ipv4_cursor),
            ipv6_cursor: AtomicU64::new(ipv6_cursor),
            reject_ipv6,
        }))
    }

    fn load_cursor(cache: &FakeIPCache, key: &str) -> u64 {
        match cache.get(key) {
            Ok(r) => {
                if let Some(r) = r {
                    return r.0.trim().parse().unwrap_or(0);
                }
                0
            }
            Err(_) => 0,
        }
    }

    fn save_cursor(&self, key: &str, cursor: &AtomicU64) {
        let current = cursor.load(Ordering::Relaxed);
        let val = current.to_string();
        let _ = self.cache.set(key, &val);
    }

    pub fn next_ipv4_cursor(&self) -> u64 {
        let current = self.ipv4_cursor.fetch_add(1, Ordering::SeqCst);
        self.save_cursor(Self::IPV4_CURSOR_CACHE_KEY, &self.ipv4_cursor);
        current
    }

    pub fn next_ipv6_cursor(&self) -> u64 {
        let current = self.ipv6_cursor.fetch_add(1, Ordering::SeqCst);
        self.save_cursor(Self::IPV6_CURSOR_CACHE_KEY, &self.ipv6_cursor);
        current
    }

    pub fn get_fake_ipv4(&self, cursor: u64) -> Ipv4Addr {
        let prefix_len = self.ipv4_cidr.prefix_len();
        let total_hosts = 1u64 << (32 - prefix_len);

        let offset = (cursor % total_hosts) as u32;
        let base: u32 = self.ipv4_cidr.addr().into();

        Ipv4Addr::from(base + offset)
    }

    pub fn get_fake_ipv6(&self, cursor: u64) -> Ipv6Addr {
        let prefix_len = self.ipv6_cidr.prefix_len();

        if prefix_len > 64 {
            let host_bits = 128 - prefix_len;
            let total_hosts = 1u128 << host_bits;
            let offset = (cursor as u128) % total_hosts;
            let base: u128 = self.ipv6_cidr.addr().into();
            Ipv6Addr::from(base + offset)
        } else {
            let base: u128 = self.ipv6_cidr.addr().into();
            Ipv6Addr::from(base + cursor as u128)
        }
    }

    fn resolve_internal(&self, domain: &str, qtype: QTYPE) -> Result<String> {
        let cache_key = match qtype {
            QTYPE::TYPE(TYPE::A) => format!("{}:A", domain),
            QTYPE::TYPE(TYPE::AAAA) => format!("{}:AAAA", domain),
            _ => bail!("qtype unspported"),
        };

        if let Ok(Some(r)) = self.cache.get(&cache_key) {
            return Ok(r.0);
        }

        let ip_str = match qtype {
            QTYPE::TYPE(TYPE::A) => {
                let c = self.next_ipv4_cursor();
                self.get_fake_ipv4(c).to_string()
            }
            QTYPE::TYPE(TYPE::AAAA) => {
                let c = self.next_ipv6_cursor();
                self.get_fake_ipv6(c).to_string()
            }
            _ => bail!("unspported"),
        };

        self.cache.set(&cache_key, &ip_str)?;

        let ptr_key = format!("ptr:{}", ip_str);
        let domain_val = domain.to_string();
        self.cache.set(&ptr_key, &domain_val)?;

        Ok(ip_str)
    }

    pub fn resolve_v4(&self, domain: &str) -> Result<Ipv4Addr> {
        let res = self.resolve_internal(domain, QTYPE::TYPE(TYPE::A))?;
        Ok(Ipv4Addr::from_str(&res.trim()).context("parse string ip failed")?)
    }

    pub fn resolve_v6(&self, domain: &str) -> Result<Ipv6Addr> {
        let res = self.resolve_internal(domain, QTYPE::TYPE(TYPE::AAAA))?;
        Ok(Ipv6Addr::from_str(&res.trim()).context("parse string ip failed")?)
    }

    pub fn reverse_lookup(&self, ip: &IpAddr) -> Option<String> {
        let ptr_key = format!("ptr:{}", ip);

        match self.cache.get(&ptr_key) {
            Ok(Some(r)) => {
                let domain = r.0.trim().to_string();
                if domain.is_empty() {
                    None
                } else {
                    Some(domain)
                }
            }
            Ok(None) => None,
            Err(e) => {
                error!("{}", e);
                None
            }
        }
    }
}

#[async_trait::async_trait]
impl AnyDNS for FakeIPDNS {
    fn tag(&self) -> &str {
        &self.tag
    }

    fn cache(&self) -> &DnsCache {
        &None
    }

    fn reject_ipv6(&self) -> bool {
        self.reject_ipv6
    }

    async fn lookup_ipv4(
        &self,
        domain: &str,
        _outbound: &Arc<dyn AnyOutbound>,
    ) -> Result<Option<Ipv4Addr>> {
        Ok(Some(self.resolve_v4(domain)?))
    }

    async fn lookup_ipv6(
        &self,
        domain: &str,
        _outbound: &Arc<dyn AnyOutbound>,
    ) -> Result<Option<Ipv6Addr>> {
        Ok(Some(self.resolve_v6(domain)?))
    }

    async fn lookup_with_type(
        &self,
        domain: &str,
        qtype: QTYPE,
        _outbound: &Arc<dyn AnyOutbound>,
    ) -> Result<Vec<IpAddr>> {
        match qtype {
            QTYPE::TYPE(TYPE::A) => {
                let ip_opt = self.lookup_ipv4(domain, _outbound).await?;
                Ok(ip_opt.map(|ip| vec![IpAddr::V4(ip)]).unwrap_or_default())
            }
            QTYPE::TYPE(TYPE::AAAA) => {
                let ip_opt = self.lookup_ipv6(domain, _outbound).await?;
                Ok(ip_opt.map(|ip| vec![IpAddr::V6(ip)]).unwrap_or_default())
            }
            _ => Ok(Vec::new()),
        }
    }

    async fn exchange(&self, packet_bytes: &[u8]) -> Result<Vec<u8>> {
        let packet = Packet::parse(packet_bytes)
            .map_err(|e| anyhow::anyhow!("Failed to parse DNS packet: {e}"))?
            .to_owned();

        if packet.questions.is_empty() {
            bail!("DNS packet has no questions");
        }

        let question = &packet.questions[0];
        let domain = question.qname.to_string();
        let qtype = question.qtype;
        let id = packet.id();

        let mut reply = Packet::new_reply(id);
        reply.questions.push(question.clone());

        let ttl = self.min_ttl().unwrap_or(Duration::from_secs(60)).as_secs() as u32;

        match qtype {
            QTYPE::TYPE(TYPE::A) => {
                if let Ok(ip) = self.resolve_v4(&domain) {
                    reply.answers.push(ResourceRecord {
                        name: question.qname.clone(),
                        class: CLASS::IN,
                        ttl: ttl,
                        rdata: RData::A(simple_dns::rdata::A { address: ip.into() }),
                        cache_flush: false,
                    });
                }
            }
            QTYPE::TYPE(TYPE::AAAA) => {
                if let Ok(ip) = self.resolve_v6(&domain) {
                    reply.answers.push(ResourceRecord {
                        name: question.qname.clone(),
                        class: CLASS::IN,
                        ttl: ttl,
                        rdata: RData::AAAA(simple_dns::rdata::AAAA { address: ip.into() }),
                        cache_flush: false,
                    });
                }
            }
            _ => {
                bail!("FakeIP DNS only supports A and AAAA queries, got {qtype:?}");
            }
        }

        let reply_bytes = reply
            .build_bytes_vec()
            .with_context(|| format!("Failed to build reply"))?;

        Ok(reply_bytes)
    }

    async fn reverse(&self, ip: &IpAddr) -> Option<String> {
        match self.reverse_lookup(ip) {
            Some(domain) => {
                info!("Reverse lookup success: {} -> {}", ip, domain);
                Some(domain)
            }
            None => {
                info!("Reverse lookup failed for {}", ip);
                None
            }
        }
    }

    async fn is_fakeip(&self, ip: &IpAddr) -> bool {
        match ip {
            IpAddr::V4(ip) => self.ipv4_cidr.contains(ip),
            IpAddr::V6(ip) => self.ipv6_cidr.contains(ip),
        }
    }

    async fn exchange_with_outbound(
        &self,
        packet_bytes: &[u8],
        _outbound: Arc<dyn AnyOutbound>,
    ) -> Result<Vec<u8>> {
        self.exchange(packet_bytes).await
    }

    fn default_outbound(&self) -> Arc<dyn AnyOutbound> {
        unimplemented!("FakeIPDNS don't need a outbound.")
    }

    fn min_ttl(&self) -> Option<Duration> {
        self.min_ttl
    }

    fn max_ttl(&self) -> Option<Duration> {
        self.min_ttl
    }
}
