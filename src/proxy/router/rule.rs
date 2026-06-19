use ipnet::IpNet;
use simple_dns::QTYPE;
use std::sync::Arc;
use tracing::error;

use crate::config::{NetworkType, RouterMode, RuleConfig};
use crate::dns::{AnyDNS, get_dns_by_tag};
use crate::proxy::TargetAddr;
use crate::proxy::outbound::{AnyOutbound, get_outbound_by_tag};
use anyhow::{Context, Result, ensure};

use super::geoip::get_geoip_by_tag;

#[derive(Clone)]
pub enum RuleAction {
    Route(Arc<dyn AnyOutbound>),
}

pub struct Rule {
    pub mode: Option<Vec<RouterMode>>,
    pub domain: Option<Vec<String>>,
    pub domain_suffix: Option<Vec<String>>,
    pub inbounds_tag: Option<Vec<String>>,
    pub ip_cidr: Option<Vec<IpNet>>,
    pub port: Option<Vec<u16>>,
    pub port_range: Option<Vec<(u16, u16)>>,
    pub network: Option<Vec<NetworkType>>,
    pub protocol: Option<Vec<String>>,
    pub query_type: Option<Vec<QTYPE>>,

    pub dns: Option<Arc<dyn AnyDNS>>,
    pub geoip: Option<Vec<String>>,
    pub reverse: Option<Arc<dyn AnyDNS>>,
    pub outbound: Arc<dyn AnyOutbound>,
}

impl Rule {
    pub fn new(cfg: &RuleConfig) -> Result<Self> {
        // 1. Network: 使用 .context() 附加整体解析上下文，内部返回 Err 时会携带
        let network = cfg
            .network
            .as_ref()
            .map(|net_list| {
                net_list
                    .iter()
                    .map(|t| match t.to_uppercase().as_str() {
                        "TCP" => Ok(NetworkType::Tcp),
                        "UDP" => Ok(NetworkType::Udp),
                        _ => Err(anyhow::anyhow!("Unsupported NetworkType: {}", t)),
                    })
                    .collect::<Result<Vec<_>>>()
                    .context("Failed to parse network types")
            })
            .transpose()?;

        // 2. Mode: 同上
        let mode = cfg
            .mode
            .as_ref()
            .map(|mode_list| {
                mode_list
                    .iter()
                    .map(|t| match t.to_lowercase().as_str() {
                        "rule" => Ok(RouterMode::Rule),
                        "proxy" => Ok(RouterMode::Proxy),
                        "direct" => Ok(RouterMode::Direct),
                        _ => Err(anyhow::anyhow!("Unsupported RouterMode: {}", t)),
                    })
                    .collect::<Result<Vec<_>>>()
                    .context("Failed to parse router modes")
            })
            .transpose()?;

        // 3. IP CIDR: 使用 .with_context() 延迟求值，避免不必要的字符串分配
        let ip_cidr = cfg
            .ip_cidr
            .as_ref()
            .map(|cidrs| {
                cidrs
                    .iter()
                    .map(|s| {
                        s.parse::<IpNet>()
                            .with_context(|| format!("Invalid IP CIDR format: {}", s))
                    })
                    .collect::<Result<Vec<_>>>()
                    .context("Failed to parse IP CIDR list")
            })
            .transpose()?;

        // 4. Port Range: 结合 .with_context() 与 ensure! 宏
        let port_range = cfg
            .port_range
            .as_ref()
            .map(|ranges| {
                ranges
                    .iter()
                    .map(|s| {
                        if let Some((start_s, end_s)) = s.split_once('-') {
                            let start = start_s
                                .trim()
                                .parse::<u16>()
                                .with_context(|| format!("Invalid start port in '{}'", s))?;
                            let end = end_s
                                .trim()
                                .parse::<u16>()
                                .with_context(|| format!("Invalid end port in '{}'", s))?;
                            ensure!(start <= end, "Port range start > end: {}", s);
                            Ok((start, end))
                        } else {
                            let port = s
                                .trim()
                                .parse::<u16>()
                                .with_context(|| format!("Invalid port in '{}'", s))?;
                            Ok((port, port))
                        }
                    })
                    .collect::<Result<Vec<_>>>()
                    .context("Failed to parse port ranges")
            })
            .transpose()?;

        // 5. Query Type: 空列表直接返回 None，非空则严格校验
        let query_type = cfg
            .query_type
            .as_ref()
            .filter(|types| !types.is_empty()) // 空列表直接转为 None，不进入 map
            .map(|types| {
                types
                    .iter()
                    .map(|t| match t.to_uppercase().as_str() {
                        "A" => Ok(simple_dns::QTYPE::TYPE(simple_dns::TYPE::A)),
                        "AAAA" => Ok(simple_dns::QTYPE::TYPE(simple_dns::TYPE::AAAA)),
                        _ => Err(anyhow::anyhow!("Unsupported DNS query type: {}", t)),
                    })
                    .collect::<anyhow::Result<Vec<_>>>()
                    .context("Failed to parse DNS query types")
            })
            .transpose()?;

        // 6. DNS / Reverse: 直接借用，避免多余 clone
        let reverse = cfg
            .reverse
            .as_ref()
            .map(|tag| get_dns_by_tag(tag))
            .transpose()?;
        let dns = cfg
            .dns
            .as_ref()
            .map(|tag| get_dns_by_tag(tag))
            .transpose()?;

        // 7. 字符串/集合字段: 过滤空值并克隆
        let port = cfg.port.as_ref().filter(|v| !v.is_empty()).cloned();
        let domain = cfg.domain.as_ref().filter(|v| !v.is_empty()).cloned();
        let inbounds_tag = cfg.inbounds.as_ref().filter(|v| !v.is_empty()).cloned();
        let domain_suffix = cfg
            .domain_suffix
            .as_ref()
            .filter(|v| !v.is_empty())
            .cloned();
        let protocol = cfg.protocol.as_ref().filter(|v| !v.is_empty()).cloned();

        // 8. Outbound (必填): 对 Option 直接使用 .context() 转 Result
        let outbound_tag = cfg
            .outbound
            .as_ref()
            .context("require outbound in rule config")?;
        let outbound = get_outbound_by_tag(outbound_tag);

        Ok(Self {
            mode,
            outbound,
            domain,
            domain_suffix,
            inbounds_tag,
            geoip: cfg.geoip.clone(),
            ip_cidr,
            port,
            port_range,
            network,
            protocol,
            query_type,
            dns,
            reverse,
        })
    }

    pub async fn matches(
        &self,
        target: &TargetAddr,
        inbound_tag: &str,
        network: Option<NetworkType>,
        protocol: Option<&str>,
        query_type: Option<QTYPE>,
    ) -> (bool, Option<TargetAddr>) {
        if let Some(inbounds) = &self.inbounds_tag {
            if !inbounds.is_empty() {
                if !inbounds.iter().any(|s| s == inbound_tag) {
                    return (false, None);
                }
            }
        }

        if let Some(protocols) = &self.protocol {
            if !protocols.is_empty() {
                if let Some(ctx_proto) = protocol {
                    if !protocols.iter().any(|p| p == ctx_proto) {
                        return (false, None);
                    }
                } else {
                    return (false, None);
                }
            }
        }

        if let Some(networks) = &self.network {
            if !networks.is_empty() {
                if let Some(net) = &network {
                    if !networks.contains(net) {
                        return (false, None);
                    }
                } else {
                    return (false, None);
                }
            }
        }

        let has_port_rules = self.port.as_ref().map_or(false, |v| !v.is_empty())
            || self.port_range.as_ref().map_or(false, |v| !v.is_empty());

        if has_port_rules {
            let port = target.port();
            let mut port_match = false;

            if let Some(ports) = &self.port {
                if ports.contains(&port) {
                    port_match = true;
                }
            }

            if !port_match {
                if let Some(ranges) = &self.port_range {
                    for (start, end) in ranges {
                        if port >= *start && port <= *end {
                            port_match = true;
                            break;
                        }
                    }
                }
            }

            if !port_match {
                return (false, None);
            }
        }

        let has_domain_rules = self.domain.as_ref().map_or(false, |v| !v.is_empty())
            || self.domain_suffix.as_ref().map_or(false, |v| !v.is_empty());

        if has_domain_rules {
            if let TargetAddr::Domain(domain, _) = target {
                let mut matched = false;

                if let Some(domains) = &self.domain {
                    for d in domains.iter() {
                        if d == domain {
                            matched = true;
                            break;
                        }
                    }
                }

                if !matched {
                    if let Some(domain_suffixes) = &self.domain_suffix {
                        for d in domain_suffixes {
                            // 确保 domain 是 &str，d 也是 &str
                            if domain.ends_with(d.as_str()) {
                                matched = true;
                                break;
                            }
                        }
                    }
                }
                if !matched {
                    return (false, None);
                }
            } else {
                return (false, None);
            }
        }

        if let Some(types) = &self.query_type {
            if let Some(qtype) = query_type {
                if !types.contains(&qtype) {
                    return (false, None);
                }
            } else {
                return (false, None);
            }
        }

        if let Some(ip_cidrs) = &self.ip_cidr {
            if !ip_cidrs.is_empty() {
                if let TargetAddr::Ip(socket_addr) = target {
                    if !ip_cidrs.iter().any(|cidr| cidr.contains(&socket_addr.ip())) {
                        return (false, None);
                    }
                } else {
                    return (false, None);
                }
            }
        }

        if let Some(reverse_dns) = &self.reverse {
            if let TargetAddr::Ip(socket_addr) = target {
                match reverse_dns.reverse(&socket_addr.ip()).await {
                    Some(domain) => {
                        return (true, Some(TargetAddr::Domain(domain, socket_addr.port())));
                    }
                    None => {
                        return (false, None);
                    }
                };
            } else {
                return (false, None);
            }
        }

        if let Some(geoip) = &self.geoip {
            if !geoip.is_empty() {
                let mut is_matched = false;
                for item in geoip.iter() {
                    let geoip = match get_geoip_by_tag(item) {
                        Ok(g) => g,
                        Err(e) => {
                            error!("can not find geoip tag [{}]", item);
                            continue;
                        }
                    };
                    match geoip.lookup(target).await {
                        Ok(r) => {
                            if r {
                                is_matched = true;
                                break;
                            }
                        }
                        Err(e) => error!("can not find geoip [{}]: {:#}", item, e),
                    }
                }
                if !is_matched {
                    return (false, None);
                }
            }
        }

        (true, None)
    }
}
