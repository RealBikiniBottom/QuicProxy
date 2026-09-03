use crate::cache::{Cache, CacheWithExpire};
use crate::config::{Config, DnsServerConfig};
use crate::proxy::observe::get_observer;
use crate::proxy::outbound::{AnyOutbound, get_default_outbound, get_outbound_by_tag};
use crate::proxy::{SourceAddr, TargetAddr};
use crate::utils::{format_duration, now_timestamp};
use anyhow::{Context, Result, anyhow, bail, ensure};
use bytes::Bytes;
use dashmap::DashMap;
use hyper::header::HeaderMap;
use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use rand::seq::IndexedRandom;
use simple_dns::rdata::RData;
use simple_dns::{
    CLASS, Name, Packet, PacketFlag, QCLASS, QTYPE, Question, RCODE, ResourceRecord, TYPE,
};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, LazyLock};
use std::time::{Duration, Instant};
use tokio::time::timeout;
use tracing::{debug, error, info, warn};

use crate::utils::http_outbound;

static DNS_MAP: LazyLock<DashMap<String, Arc<dyn AnyDNS>>> = LazyLock::new(DashMap::new);
static BLOCK_DDR: AtomicBool = AtomicBool::new(false);
pub type DnsByteCache = Option<CacheWithExpire<Vec<u8>>>;

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
    BLOCK_DDR.store(cfg.dns.block_ddr, Ordering::Relaxed);
    if cfg.dns.block_ddr {
        info!("DDR discovery blocking enabled for resolver.arpa");
    }
    Ok(())
}

/// 关闭所有 DNS 服务器并清空 DNS 缓存，释放底层的 redb 数据库引用。
/// 应在进程退出前调用，确保 redb 文件锁能被正常释放。
pub fn shutdown_dns() {
    BLOCK_DDR.store(false, Ordering::Relaxed);
    DNS_MAP.clear();
}

fn is_resolver_arpa_name(name: &Name<'_>) -> bool {
    let normalized = name.to_string().trim_end_matches('.').to_ascii_lowercase();

    normalized == "resolver.arpa" || normalized.ends_with(".resolver.arpa")
}

fn build_ddr_nodata_response(packet: &Packet<'_>) -> Result<Option<Vec<u8>>> {
    if !packet
        .questions
        .iter()
        .any(|question| is_resolver_arpa_name(&question.qname))
    {
        return Ok(None);
    }

    let mut reply = Packet::new_reply(packet.id());
    reply.questions.extend(packet.questions.iter().cloned());
    if packet.has_flags(PacketFlag::RECURSION_DESIRED) {
        reply.set_flags(PacketFlag::RECURSION_DESIRED);
    }
    reply.set_flags(PacketFlag::RECURSION_AVAILABLE);
    *reply.rcode_mut() = RCODE::NoError;

    debug!(
        questions = ?packet
            .questions
            .iter()
            .map(|question| (question.qname.to_string(), question.qtype))
            .collect::<Vec<_>>(),
        "blocked DDR discovery query with NODATA"
    );

    reply
        .build_bytes_vec()
        .map(|bytes| Some(bytes.to_vec()))
        .map_err(|e| anyhow!("Failed to build DDR NODATA reply: {e}"))
}

fn into_owned_packet(packet: Packet<'_>) -> Packet<'static> {
    let mut owned = Packet::new_query(packet.id());
    *owned.opcode_mut() = packet.opcode();
    *owned.rcode_mut() = packet.rcode();

    for flag in [
        PacketFlag::RESPONSE,
        PacketFlag::AUTHORITATIVE_ANSWER,
        PacketFlag::TRUNCATION,
        PacketFlag::RECURSION_DESIRED,
        PacketFlag::RECURSION_AVAILABLE,
        PacketFlag::AUTHENTIC_DATA,
        PacketFlag::CHECKING_DISABLED,
    ] {
        if packet.has_flags(flag) {
            owned.set_flags(flag);
        }
    }

    *owned.opt_mut() = packet.opt().cloned().map(|opt| opt.into_owned());
    owned.questions = packet
        .questions
        .into_iter()
        .map(|question| question.into_owned())
        .collect();
    owned.answers = packet
        .answers
        .into_iter()
        .map(|record| record.into_owned())
        .collect();
    owned.name_servers = packet
        .name_servers
        .into_iter()
        .map(|record| record.into_owned())
        .collect();
    owned.additional_records = packet
        .additional_records
        .into_iter()
        .map(|record| record.into_owned())
        .collect();
    owned
}

fn parse_owned_packet(packet_bytes: &[u8], kind: &str) -> Result<Packet<'static>> {
    Packet::parse(packet_bytes)
        .map(into_owned_packet)
        .map_err(|e| anyhow!("Failed to parse DNS {kind}: {e}"))
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
        .choose(&mut rand::rng())
        .copied()
        .with_context(|| format!("DNS lookup failed for: {domain}"))?;

    if let Some(observer) = get_observer() {
        observer.record_dns_time(now.elapsed().as_micros() as u64);
    }
    info!(
        "resolved ip: {}, cost: {}",
        ip,
        format_duration(now.elapsed())
    );

    Ok(ip)
}

fn persist_realip_domains(packet: &Packet<'_>, domain: &str) {
    if packet.rcode() != RCODE::NoError {
        return;
    }

    let Some(observer) = get_observer() else {
        return;
    };

    let domain = domain.to_string();
    for answer in &packet.answers {
        let ip = match &answer.rdata {
            RData::A(a) => IpAddr::V4(a.address.into()),
            RData::AAAA(aaaa) => IpAddr::V6(aaaa.address.into()),
            _ => continue,
        };

        if let Err(e) = observer.realip2domain.set(&ip.to_string(), &domain) {
            warn!("failed to persist real IP domain mapping for {ip}: {e}");
        }
    }
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
    packet: &mut Packet<'_>,
    min_ttl: Option<Duration>,
    max_ttl: Option<Duration>,
) -> Option<u32> {
    let mut min_effective_ttl = None;

    for record in packet
        .answers
        .iter_mut()
        .chain(packet.name_servers.iter_mut())
        .chain(packet.additional_records.iter_mut())
    {
        let mut effective_ttl = record.ttl;
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
        record.ttl = effective_ttl;

        min_effective_ttl = Some(
            min_effective_ttl.map_or(effective_ttl, |current: u32| current.min(effective_ttl)),
        );
    }

    min_effective_ttl
}

fn cap_record_ttls(packet: &mut Packet<'_>, remaining_ttl: u32) {
    for record in packet
        .answers
        .iter_mut()
        .chain(packet.name_servers.iter_mut())
        .chain(packet.additional_records.iter_mut())
    {
        record.ttl = record.ttl.min(remaining_ttl);
    }
}

#[async_trait::async_trait]
pub trait AnyDNS: Send + Sync + 'static {
    fn tag(&self) -> &str;
    fn byte_cache(&self) -> &DnsByteCache {
        &None
    }

    async fn lookup_with_type(
        &self,
        domain: &str,
        qtype: QTYPE,
        outbound: &Arc<dyn AnyOutbound>,
    ) -> Result<Vec<IpAddr>> {
        if !matches!(qtype, QTYPE::TYPE(TYPE::A) | QTYPE::TYPE(TYPE::AAAA)) {
            return Ok(Vec::new());
        }

        let temp = build_dns_query_packet(domain, qtype)?;
        let packet = self.exchange_with_cache(&temp, outbound.clone()).await?;

        if packet.rcode() != RCODE::NoError {
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

    fn dns_server(&self) -> Option<&str> {
        None
    }

    async fn exchange_with_cache(
        &self,
        packet: &Packet<'_>,
        outbound: Arc<dyn AnyOutbound>,
    ) -> Result<Packet<'static>> {
        if packet.questions.is_empty() {
            return self.exchange_without_cache(packet, outbound).await;
        }

        let question = &packet.questions[0];
        let domain = question.qname.to_string();
        let qtype = question.qtype;

        let cache_key = format!("{}:{}:{:?}", outbound.tag(), domain, qtype);

        if let Some(byte_cache) = self.byte_cache() {
            if let Ok(Some((cached_bytes, remaining_ttl, source))) = byte_cache.get(&cache_key) {
                let remaining = Duration::from_secs(remaining_ttl.saturating_sub(now_timestamp()));
                info!(
                    "hit dns byte cache from {:?}({}) for {}({:?})",
                    source,
                    format_duration(remaining),
                    domain,
                    qtype,
                );
                let mut response = cached_bytes;
                let query_id = packet.id();
                response[0] = (query_id >> 8) as u8;
                response[1] = query_id as u8;
                let mut response = parse_owned_packet(&response, "cached response")?;
                cap_record_ttls(
                    &mut response,
                    remaining.as_secs().min(u32::MAX as u64) as u32,
                );
                return Ok(response);
            }
        }

        let mut resp_packet = self.exchange_without_cache(packet, outbound).await?;

        let min_ttl = self.min_ttl();
        let max_ttl = self.max_ttl();

        let min_effective_ttl = apply_ttl_to_response(&mut resp_packet, min_ttl, max_ttl);
        persist_realip_domains(&resp_packet, &domain);

        if let Some(cache_ttl) = min_effective_ttl.filter(|ttl| *ttl > 0) {
            if let Some(byte_cache) = self.byte_cache() {
                let response_bytes = resp_packet
                    .build_bytes_vec()
                    .map_err(|e| anyhow!("Failed to build DNS response for cache: {e}"))?;
                let _ = byte_cache.set(&cache_key, &response_bytes, cache_ttl as u64);
                info!(
                    "cached dns response for {}({:?}), ttl: {}s",
                    domain, qtype, cache_ttl
                );
            }
        }

        Ok(resp_packet)
    }

    async fn exchange_without_cache(
        &self,
        packet: &Packet<'_>,
        outbound: Arc<dyn AnyOutbound>,
    ) -> Result<Packet<'static>>;

    fn default_outbound(&self) -> Arc<dyn AnyOutbound>;

    async fn hijack_exchange(&self, packet_bytes: &[u8]) -> Result<Vec<u8>> {
        let packet = Packet::parse(packet_bytes)
            .map_err(|e| anyhow::anyhow!("Failed to parse DNS query: {e}"))?
            .to_owned();

        if BLOCK_DDR.load(Ordering::Relaxed) {
            if let Some(response) = build_ddr_nodata_response(&packet)? {
                return Ok(response);
            }
        }

        if self.reject_ipv6()
            && packet
                .questions
                .iter()
                .any(|q| q.qtype == QTYPE::TYPE(TYPE::AAAA))
        {
            let mut reply = Packet::new_reply(packet.id());
            for question in &packet.questions {
                reply.questions.push(question.clone());
            }
            debug!("rejected ipv6 query with empty reply");
            return reply
                .build_bytes_vec()
                .map(|b| b.to_vec())
                .map_err(|e| anyhow!("Failed to build DNS reply: {e}"));
        }
        self.exchange_with_cache(&packet, self.default_outbound())
            .await?
            .build_bytes_vec()
            .map_err(|e| anyhow!("Failed to build DNS response: {e}"))
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
    pub byte_cache: DnsByteCache,
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

        let byte_cache = match cfg.cache.as_ref() {
            Some(c) => Some(
                CacheWithExpire::new_with_tag(c, format!("{}_bytes", tag))
                    .map_err(|e| anyhow!("dns '{}' failed to init byte cache: {:?}", tag, e))?,
            ),
            None => None,
        };

        let outbound_tag = cfg
            .outbound
            .as_deref()
            .ok_or_else(|| anyhow!("dns '{}' requires outbound", tag))?;
        let outbound = get_outbound_by_tag(outbound_tag).with_context(|| {
            format!(
                "dns '{}' references unknown outbound '{}'",
                tag, outbound_tag
            )
        })?;

        let reject_ipv6 = cfg.reject_ipv6;

        Ok(Arc::new(Self {
            tag,
            address,
            min_ttl,
            max_ttl,
            outbound,
            byte_cache,
            reject_ipv6,
        }))
    }
}

#[async_trait::async_trait]
impl AnyDNS for UdpDns {
    fn tag(&self) -> &str {
        &self.tag
    }

    fn byte_cache(&self) -> &DnsByteCache {
        &self.byte_cache
    }

    fn reject_ipv6(&self) -> bool {
        self.reject_ipv6
    }

    async fn exchange_without_cache(
        &self,
        packet: &Packet<'_>,
        outbound: Arc<dyn AnyOutbound>,
    ) -> Result<Packet<'static>> {
        let target = resolve_target(&self.address, self.dns_server()).await?;
        let target = TargetAddr::Ip(target);
        let socket = outbound.connect_packet(&target).await?;

        let closer = socket.closer();

        let result = async {
            let packet_bytes = packet
                .build_bytes_vec()
                .map_err(|e| anyhow!("Failed to build DNS query packet: {e}"))?;
            let buf = Bytes::from(packet_bytes);

            socket.send_to(buf, &SourceAddr::dummy(), &target).await?;

            let (_, _, payload) = timeout(outbound.connect_timeout(), socket.recv_from())
                .await
                .map_err(|_| anyhow!("DNS query timed out"))??;

            parse_owned_packet(&payload, "UDP response")
        }
        .await;

        if let Some(closer) = closer {
            closer.close();
        }

        result
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
    pub byte_cache: DnsByteCache,
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

        let byte_cache = match cfg.cache.as_ref() {
            Some(c) => Some(
                CacheWithExpire::new_with_tag(c, format!("{}_bytes", tag))
                    .map_err(|e| anyhow!("dns '{}' failed to init byte cache: {:?}", tag, e))?,
            ),
            None => None,
        };

        let outbound_tag = cfg
            .outbound
            .as_deref()
            .ok_or_else(|| anyhow!("dns '{}' requires outbound", tag))?;
        let outbound = get_outbound_by_tag(outbound_tag).with_context(|| {
            format!(
                "dns '{}' references unknown outbound '{}'",
                tag, outbound_tag
            )
        })?;

        let reject_ipv6 = cfg.reject_ipv6;

        Ok(Arc::new(Self {
            tag,
            min_ttl,
            max_ttl,
            outbound,
            dns_server_name: cfg.dns.clone(),
            byte_cache,
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

    fn byte_cache(&self) -> &DnsByteCache {
        &self.byte_cache
    }

    fn reject_ipv6(&self) -> bool {
        self.reject_ipv6
    }

    fn dns_server(&self) -> Option<&str> {
        self.dns_server_name.as_deref()
    }

    async fn exchange_without_cache(
        &self,
        packet: &Packet<'_>,
        outbound: Arc<dyn AnyOutbound>,
    ) -> Result<Packet<'static>> {
        let packet_bytes = packet
            .build_bytes_vec()
            .map_err(|e| anyhow!("Failed to build DNS query packet: {e}"))?;
        let mut headers = HeaderMap::new();
        headers.insert("Content-Type", "application/dns-message".parse().unwrap());

        let response = http_outbound::request_post_via_outbound(
            outbound.clone(),
            self.dns_server(),
            &self.url,
            outbound.connect_timeout(),
            Some(&headers),
            Bytes::from(packet_bytes),
        )
        .await?;

        if !response.status.is_success() {
            bail!("DoH server returned error: {}", response.status)
        }

        parse_owned_packet(&response.body, "HTTPS response")
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
    pub default_outbound: Arc<dyn AnyOutbound>,
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
            default_outbound: get_default_outbound()?,
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
                error!("{:?}", e);
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

    async fn exchange_with_cache(
        &self,
        packet: &Packet<'_>,
        outbound: Arc<dyn AnyOutbound>,
    ) -> Result<Packet<'static>> {
        self.exchange_without_cache(packet, outbound).await
    }

    async fn exchange_without_cache(
        &self,
        packet: &Packet<'_>,
        _outbound: Arc<dyn AnyOutbound>,
    ) -> Result<Packet<'static>> {
        if packet.questions.is_empty() {
            bail!("DNS packet has no questions");
        }

        let question = &packet.questions[0];
        let domain = question.qname.to_string();
        let qtype = question.qtype;
        let id = packet.id();

        let mut reply: Packet<'static> = Packet::new_reply(id);
        reply.questions.push(question.clone().into_owned());

        let ttl = self.min_ttl().unwrap_or(Duration::from_secs(60)).as_secs() as u32;

        match qtype {
            QTYPE::TYPE(TYPE::A) => {
                if let Ok(ip) = self.resolve_v4(&domain) {
                    reply.answers.push(ResourceRecord {
                        name: question.qname.clone().into_owned(),
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
                        name: question.qname.clone().into_owned(),
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

        Ok(reply)
    }

    fn default_outbound(&self) -> Arc<dyn AnyOutbound> {
        self.default_outbound.clone()
    }

    fn min_ttl(&self) -> Option<Duration> {
        self.min_ttl
    }

    fn max_ttl(&self) -> Option<Duration> {
        self.min_ttl
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dns_query(name: &'static str, qtype: QTYPE) -> Packet<'static> {
        build_dns_query_packet(name, qtype).unwrap()
    }

    #[test]
    fn ddr_zone_queries_receive_nodata() {
        for (name, qtype) in [
            ("_dns.resolver.arpa", QTYPE::TYPE(TYPE::SVCB)),
            ("_DNS.ReSoLvEr.ArPa.", QTYPE::TYPE(TYPE::SVCB)),
            ("resolver.arpa", QTYPE::TYPE(TYPE::A)),
            ("child.resolver.arpa", QTYPE::TYPE(TYPE::HTTPS)),
        ] {
            let query = dns_query(name, qtype);
            let response = build_ddr_nodata_response(&query)
                .unwrap()
                .expect("resolver.arpa query should be blocked");
            let packet = Packet::parse(&response).unwrap();

            assert_eq!(packet.rcode(), RCODE::NoError);
            assert!(packet.answers.is_empty());
            assert!(packet.name_servers.is_empty());
            assert!(packet.additional_records.is_empty());
            assert!(packet.has_flags(PacketFlag::RESPONSE));
            assert!(packet.has_flags(PacketFlag::RECURSION_DESIRED));
            assert!(packet.has_flags(PacketFlag::RECURSION_AVAILABLE));
            assert_eq!(packet.questions.len(), 1);
            assert_eq!(packet.questions[0].qtype, qtype);
        }
    }

    #[test]
    fn non_ddr_names_are_not_blocked() {
        for name in [
            "example.com",
            "resolver.arpa.example.com",
            "notresolver.arpa",
        ] {
            let query = dns_query(name, QTYPE::TYPE(TYPE::SVCB));
            assert!(build_ddr_nodata_response(&query).unwrap().is_none());
        }
    }

    #[test]
    fn parsed_owned_packet_outlives_source_bytes() {
        let packet = {
            let query = dns_query("example.com", QTYPE::TYPE(TYPE::A));
            let bytes = query.build_bytes_vec().unwrap();
            parse_owned_packet(&bytes, "test query").unwrap()
        };

        assert!(packet.has_flags(PacketFlag::RECURSION_DESIRED));
        assert_eq!(packet.questions.len(), 1);
        assert_eq!(packet.questions[0].qname.to_string(), "example.com");
        assert_eq!(packet.questions[0].qtype, QTYPE::TYPE(TYPE::A));
    }

    #[test]
    fn ttl_adjustment_returns_earliest_expiry() {
        let name = Name::new("example.com").unwrap();
        let mut packet = Packet::new_reply(1);
        let record = |address: Ipv4Addr, ttl| ResourceRecord {
            name: name.clone(),
            class: CLASS::IN,
            ttl,
            rdata: RData::A(simple_dns::rdata::A {
                address: address.into(),
            }),
            cache_flush: false,
        };
        packet
            .answers
            .push(record(Ipv4Addr::new(192, 0, 2, 1), 100));
        packet
            .name_servers
            .push(record(Ipv4Addr::new(192, 0, 2, 2), 10));
        packet
            .additional_records
            .push(record(Ipv4Addr::new(192, 0, 2, 3), 1_000));

        let min_ttl = apply_ttl_to_response(
            &mut packet,
            Some(Duration::from_secs(30)),
            Some(Duration::from_secs(300)),
        );

        assert_eq!(min_ttl, Some(30));
        assert_eq!(packet.answers[0].ttl, 100);
        assert_eq!(packet.name_servers[0].ttl, 30);
        assert_eq!(packet.additional_records[0].ttl, 300);

        cap_record_ttls(&mut packet, 20);
        assert_eq!(packet.answers[0].ttl, 20);
        assert_eq!(packet.name_servers[0].ttl, 20);
        assert_eq!(packet.additional_records[0].ttl, 20);

        assert_eq!(
            apply_ttl_to_response(&mut Packet::new_reply(2), None, None),
            None
        );
    }

    #[test]
    fn ddr_nodata_preserves_query_id_and_all_questions() {
        let mut query = Packet::new_query(0x1234);
        query.set_flags(PacketFlag::RECURSION_DESIRED);
        query.questions.push(Question::new(
            Name::new("_dns.resolver.arpa").unwrap(),
            QTYPE::TYPE(TYPE::SVCB),
            QCLASS::CLASS(CLASS::IN),
            false,
        ));
        query.questions.push(Question::new(
            Name::new("example.com").unwrap(),
            QTYPE::TYPE(TYPE::A),
            QCLASS::CLASS(CLASS::IN),
            false,
        ));

        let response = build_ddr_nodata_response(&query)
            .unwrap()
            .expect("packet containing a DDR question should be blocked");
        let response = Packet::parse(&response).unwrap();

        assert_eq!(response.id(), 0x1234);
        assert_eq!(response.questions.len(), 2);
        assert!(response.answers.is_empty());
    }
}
