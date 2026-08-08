use anyhow::{Context, bail};
use hashbrown::HashMap;
use serde::{Deserialize, Serialize};
use serde_json;
use serde_json5;
use std::fs::File;
use std::io::Read;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;
use tracing::info;

use crate::proxy::TargetAddr;

const DEFAULT_IDLE_TIMEOUT: Duration = Duration::from_secs(30);
const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

fn duration_from_secs_or(value: Option<u64>, default: Duration) -> Duration {
    value.map(Duration::from_secs).unwrap_or(default)
}

fn required_endpoint<'a>(
    address: &'a Option<String>,
    port: Option<u16>,
    bound: &str,
) -> anyhow::Result<(&'a str, u16)> {
    let address = address
        .as_deref()
        .with_context(|| format!("{bound} requires address"))?;
    let port = port.with_context(|| format!("{bound} requires port"))?;
    Ok((address, port))
}

fn required_credentials<'a>(
    username: &'a Option<String>,
    password: &'a Option<String>,
    bound: &str,
) -> anyhow::Result<(&'a str, &'a str)> {
    let username = username
        .as_deref()
        .with_context(|| format!("{bound} requires username"))?;
    let password = password
        .as_deref()
        .with_context(|| format!("{bound} requires password"))?;
    Ok((username, password))
}

#[derive(Debug, Deserialize, Clone)]
pub struct CacheConfig {
    #[serde(
        default = "default_cache_size",
        alias = "memory_size",
        alias = "menmory_size"
    )]
    pub memory_size: u64,
    pub path: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub inbounds: HashMap<String, InboundConfig>,
    pub outbounds: Outbounds,
    pub router: RouterConfig,
    #[serde(default)]
    pub dns: DnsConfig,
    #[serde(default)]
    pub cache: HashMap<String, CacheConfig>,
    pub observe: Option<ObserveConfig>,
    #[serde(default = "default_log_config")]
    pub log: LogConfig,
    pub api: Option<ApiConfig>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct ApiConfig {
    pub address: String,
    pub port: u16,
    pub password: String,
    /// Web 端持久化数据文件路径（可选），用于跨浏览器/标签页共享状态
    #[serde(default)]
    pub persist_path: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(untagged)]
pub enum LogConfig {
    Level(String),
    Detailed {
        #[serde(default = "default_true")]
        enable: bool,
        level: String,
        path: Option<String>,
        #[serde(default = "default_true")]
        color: bool,
        #[serde(default = "default_true")]
        stdout: bool,
        #[serde(default = "default_log_max_size")]
        max_size: Option<u64>,
        #[serde(default = "default_backtrace")]
        backtrace: BacktraceMode,
    },
}

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "lowercase")]
pub enum BacktraceMode {
    Off,
    On,
    Full,
}

impl BacktraceMode {
    pub fn as_env_value(&self) -> &str {
        match self {
            BacktraceMode::Off => "0",
            BacktraceMode::On => "1",
            BacktraceMode::Full => "full",
        }
    }
}

fn default_backtrace() -> BacktraceMode {
    BacktraceMode::On
}

fn default_log_max_size() -> Option<u64> {
    Some(10 * 1024 * 1024)
}

impl Default for LogConfig {
    fn default() -> Self {
        LogConfig::Level("info".to_string())
    }
}

fn default_true() -> bool {
    true
}

fn default_mtu() -> u16 {
    1400
}

fn default_false() -> bool {
    false
}

fn default_log_config() -> LogConfig {
    LogConfig::default()
}

impl Config {
    pub fn load(path: Option<PathBuf>) -> anyhow::Result<Self> {
        let config_path = match path {
            Some(p) => p,
            None => PathBuf::from("config.json"),
        };
        if !config_path.exists() {
            bail!("configuration file not found: {:?}", config_path);
        }

        let mut file = File::open(&config_path)
            .with_context(|| format!("cannot open configuration file {:?}", config_path))?;
        let mut raw = String::new();
        file.read_to_string(&mut raw)
            .with_context(|| format!("cannot read configuration file {:?}", config_path))?;

        let value: serde_json::Value = serde_json5::from_str(&raw)
            .with_context(|| format!("JSON5 parse error in {:?}", config_path))?;

        let normalized = serde_json::to_string(&value)
            .with_context(|| format!("cannot normalize JSON in {:?}", config_path))?;

        let mut deserializer = serde_json::Deserializer::from_str(&normalized);
        let config: Config = serde_path_to_error::deserialize(&mut deserializer).map_err(|e| {
            anyhow::anyhow!(
                "configuration schema error in {:?}:\n  -> {}: {}",
                config_path,
                e.path(),
                e.inner()
            )
        })?;

        info!("Successfully loaded config from {:?}", config_path);
        Ok(config)
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            inbounds: HashMap::new(),
            outbounds: Outbounds::default(),
            router: RouterConfig::default(),
            dns: DnsConfig::default(),
            cache: HashMap::new(),
            observe: None,
            log: LogConfig::default(),
            api: None,
        }
    }
}

#[derive(Debug, Deserialize, Clone)]
pub struct ObserveConfig {
    pub enabled: bool,
    #[serde(default = "default_log_interval")]
    pub log_interval: u64,
}

fn default_log_interval() -> u64 {
    30
}

#[derive(Debug, Deserialize, Clone)]
pub struct DnsConfig {
    #[serde(default)]
    pub servers: HashMap<String, DnsServerConfig>,
    #[serde(default)]
    pub default_server: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct DnsCacheConfig {
    #[serde(default)]
    pub enabled: bool,
    pub path: Option<String>,
    #[serde(default = "default_cache_size")]
    pub size: u64,
}

impl Default for DnsConfig {
    fn default() -> Self {
        Self {
            servers: HashMap::new(),
            default_server: None,
        }
    }
}

#[derive(Debug, Deserialize, Clone, Copy, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum DnsStrategy {
    PreferIpv4,
    PreferIpv6,
    Ipv4Only,
    Ipv6Only,
}

#[derive(Debug, Deserialize, Clone)]
pub struct DnsServerConfig {
    #[serde(rename = "type")]
    pub protocol_type: String,
    pub address: Option<String>,
    pub port: Option<u16>,
    pub min_ttl: Option<u64>,
    pub max_ttl: Option<u64>,
    pub outbound: Option<String>,
    pub cache: Option<String>,
    pub dns: Option<String>,
    pub range: Option<Vec<String>>,
    #[serde(default)]
    pub reject_ipv6: bool,
}

#[derive(Debug, Deserialize, Clone)]
pub struct InboundTlsConfig {
    #[serde(default = "default_false")]
    pub enable: bool,
    #[serde(alias = "sni")]
    pub server_name: Option<String>,
    pub cert: Option<String>,
    pub key: Option<String>,
    pub alpn: Option<Vec<String>>,

    #[serde(default = "default_false")]
    pub enable_jls: bool,
    pub jls_username: Option<String>,
    pub jls_password: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct OutboundTlsConfig {
    #[serde(default = "default_false")]
    pub enable: bool,
    pub insecure: Option<bool>,
    #[serde(alias = "sni")]
    pub server_name: Option<String>,
    pub ca: Option<String>,
    pub alpn: Option<Vec<String>>,

    #[serde(default = "default_false")]
    pub enable_jls: bool,
    pub jls_username: Option<String>,
    pub jls_password: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct TransportConfig {
    #[serde(rename = "type")]
    pub protocol_type: String,
    pub path: Option<String>,
    pub host: Option<String>,
    pub service_name: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct InboundConfig {
    #[serde(rename = "type")]
    pub protocol_type: String,
    pub address: Option<String>,
    pub port: Option<u16>,
    #[serde(default = "default_false")]
    pub set_system_proxy: bool,
    pub tls: Option<InboundTlsConfig>,
    pub transport: Option<TransportConfig>,

    pub idle_timeout: Option<u64>,
    pub username: Option<String>,
    pub password: Option<String>,
    pub udp_mod: Option<String>,
    pub congestion_controller: Option<String>,

    #[serde(default = "default_false")]
    pub gso: bool,
    #[serde(default = "default_true")]
    pub mtu_discoveriy: bool,
    pub mtu: Option<u16>,
    #[serde(default = "default_mtu")]
    pub min_mtu: u16,
    #[serde(default = "default_mtu")]
    pub initial_mtu: u16,
    pub auto_route: Option<bool>,
    #[serde(default = "default_false")]
    pub strict_route: bool,
    #[serde(default = "default_false")]
    pub block_ipv6: bool,
    pub tun_name: Option<String>,
    pub tun_address: Option<Vec<String>>,
    pub tun_fd: Option<i32>,
}

impl InboundConfig {
    /// Returns the configured idle timeout, or the common 30-second default.
    pub fn idle_timeout(&self) -> Duration {
        self.idle_timeout_or(DEFAULT_IDLE_TIMEOUT)
    }

    /// Returns the configured idle timeout, or a protocol-specific default.
    pub fn idle_timeout_or(&self, default: Duration) -> Duration {
        duration_from_secs_or(self.idle_timeout, default)
    }

    /// Returns the required host and port for this inbound.
    pub fn endpoint(&self, tag: &str) -> anyhow::Result<(&str, u16)> {
        let bound = format!("{} inbound '{}'", self.protocol_type, tag);
        required_endpoint(&self.address, self.port, &bound)
    }

    /// Returns the inbound endpoint parsed as a socket address.
    pub fn socket_addr(&self, tag: &str) -> anyhow::Result<SocketAddr> {
        let (address, port) = self.endpoint(tag)?;
        format!("{address}:{port}").parse().with_context(|| {
            format!(
                "{} inbound '{}' has an invalid socket address",
                self.protocol_type, tag
            )
        })
    }

    /// Returns the required username and password for this inbound.
    pub fn credentials(&self, tag: &str) -> anyhow::Result<(&str, &str)> {
        let bound = format!("{} inbound '{}'", self.protocol_type, tag);
        required_credentials(&self.username, &self.password, &bound)
    }

    /// Returns a string-valued mode setting or the protocol-specific default.
    pub fn udp_mode_or<'a>(&'a self, default: &'a str) -> &'a str {
        self.udp_mod.as_deref().unwrap_or(default)
    }
}

#[derive(Debug, Deserialize)]
pub struct Outbounds {
    #[serde(default)]
    pub servers: HashMap<String, OutboundConfig>,
    pub final_outbound: Option<String>,
}

impl Default for Outbounds {
    fn default() -> Self {
        Self {
            servers: HashMap::new(),
            final_outbound: None,
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct OutboundConfig {
    #[serde(rename = "type")]
    pub protocol_type: String,
    pub address: Option<String>,
    pub port: Option<u16>,
    pub connect_timeout: Option<u64>,
    pub bind_interface: Option<String>,

    pub dns: Option<String>,

    pub idle_timeout: Option<u64>,
    pub username: Option<String>,
    pub password: Option<String>,
    pub uuid: Option<String>,
    pub udp_mod: Option<String>,
    pub congestion_controller: Option<String>,

    pub pool_size: Option<u16>,
    #[serde(default = "default_false")]
    pub gso: bool,
    #[serde(default = "default_true")]
    pub mtu_discoveriy: bool,
    #[serde(default = "default_mtu")]
    pub min_mtu: u16,
    #[serde(default = "default_mtu")]
    pub initial_mtu: u16,
    pub outbounds: Option<Vec<String>>,
    pub default_outbound: Option<String>,
    pub url: Option<String>,
    pub interval: Option<u64>,
    pub tolerance: Option<u64>,
    pub prefer_ipv6: Option<bool>,
    pub cache: Option<String>,
    pub tls: Option<OutboundTlsConfig>,
    pub transport: Option<TransportConfig>,

    /// 禁用多路复用：每个代理连接独占一条 TLS 连接（Session）
    #[serde(default = "default_false")]
    pub disable_mux: bool,
}

impl OutboundConfig {
    /// Returns the configured idle timeout, or the common 30-second default.
    pub fn idle_timeout(&self) -> Duration {
        duration_from_secs_or(self.idle_timeout, DEFAULT_IDLE_TIMEOUT)
    }

    /// Returns the configured connection timeout, or the common 30-second default.
    pub fn connect_timeout(&self) -> Duration {
        duration_from_secs_or(self.connect_timeout, DEFAULT_CONNECT_TIMEOUT)
    }

    /// Returns the required endpoint parsed as a proxy target address.
    pub fn endpoint(&self, tag: &str) -> anyhow::Result<TargetAddr> {
        let bound = format!("{} outbound '{}'", self.protocol_type, tag);
        let (address, port) = required_endpoint(&self.address, self.port, &bound)?;
        TargetAddr::from_str2(address, port)
    }

    /// Returns the required username and password for this outbound.
    pub fn credentials(&self, tag: &str) -> anyhow::Result<(&str, &str)> {
        let bound = format!("{} outbound '{}'", self.protocol_type, tag);
        required_credentials(&self.username, &self.password, &bound)
    }

    /// Returns a string-valued mode setting or the protocol-specific default.
    pub fn udp_mode_or<'a>(&'a self, default: &'a str) -> &'a str {
        self.udp_mod.as_deref().unwrap_or(default)
    }
}

/// Cache configuration for selector outbound
#[derive(Debug, Deserialize, Clone)]
pub struct SelectorCacheConfig {
    pub enabled: bool,
    pub path: Option<String>,
}

use std::fmt;

#[derive(Debug, Clone, Deserialize)]
pub struct GeoIpConfig {
    #[serde(rename = "type")]
    pub db_type: String,
    pub path: String,
    pub url: Option<String>,
    pub download_outbound: Option<String>,
    pub update_interval: Option<String>,
    pub cache: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct GeoipDBConfig {
    #[serde(rename = "type")]
    pub db_type: String,
    pub path: String,
    pub url: Option<String>,
    pub download_outbound: Option<String>,
    pub update_interval: Option<String>,
    pub cache: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct RouterConfig {
    #[serde(default, alias = "mode")]
    pub default_mode: RouterMode,
    #[serde(default)]
    pub rules: Vec<RuleConfig>,
    #[serde(default, rename = "db")]
    pub geoip_db: HashMap<String, GeoipDBConfig>,
    #[serde(default)]
    pub geoip: HashMap<String, GeoipConfig>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NetworkType {
    Tcp,
    Udp,
}

impl std::str::FromStr for NetworkType {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "tcp" => Ok(NetworkType::Tcp),
            "udp" => Ok(NetworkType::Udp),
            _ => Err(format!("Invalid network type: {}", s)),
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct RuleConfig {
    pub mode: Option<Vec<String>>,
    pub domain: Option<Vec<String>>,
    pub domain_suffix: Option<Vec<String>>,
    pub inbounds: Option<Vec<String>>,
    pub ip_cidr: Option<Vec<String>>,
    pub port: Option<Vec<u16>>,
    pub port_range: Option<Vec<String>>,
    pub network: Option<Vec<String>>,
    pub protocol: Option<Vec<String>>,
    pub query_type: Option<Vec<String>>,
    pub outbound: Option<String>,

    pub dns: Option<String>,
    pub geoip: Option<Vec<String>>,
    pub reverse: Option<String>, // for FakeIP
}

#[derive(Debug, Deserialize, Serialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum RouterMode {
    Rule,
    Proxy,
    Direct,
}

impl fmt::Display for RouterMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RouterMode::Rule => write!(f, "rule"),
            RouterMode::Proxy => write!(f, "proxy"),
            RouterMode::Direct => write!(f, "direct"),
        }
    }
}

impl Default for RouterMode {
    fn default() -> Self {
        RouterMode::Rule
    }
}

#[derive(Debug, Deserialize, Clone)]
pub struct GeoipConfig {
    #[serde(rename = "db")]
    pub db: String,
    pub ip_country: Vec<String>,
    pub dns: Option<String>,
    pub ttl: u64,
    pub cache: Option<String>,
}

fn default_cache_size() -> u64 {
    100
}

#[allow(dead_code)]
fn default_cache_ttl() -> u64 {
    3600 // 1 hour
}

impl Default for RouterConfig {
    fn default() -> Self {
        Self {
            default_mode: RouterMode::default(),
            rules: Vec::new(),
            geoip_db: HashMap::new(),
            geoip: HashMap::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{InboundConfig, OutboundConfig, duration_from_secs_or};
    use serde_json::json;
    use std::time::Duration;

    #[test]
    fn duration_from_secs_uses_configured_value_or_default() {
        let default = Duration::from_secs(30);

        assert_eq!(
            duration_from_secs_or(Some(12), default),
            Duration::from_secs(12)
        );
        assert_eq!(duration_from_secs_or(None, default), default);
    }

    #[test]
    fn bound_config_resolves_common_values() {
        let inbound: InboundConfig = serde_json::from_value(json!({
            "type": "socks5",
            "address": "127.0.0.1",
            "port": 1080
        }))
        .unwrap();
        assert_eq!(inbound.socket_addr("local").unwrap().port(), 1080);
        assert_eq!(inbound.idle_timeout(), Duration::from_secs(30));

        let outbound: OutboundConfig = serde_json::from_value(json!({
            "type": "shadowquic",
            "address": "proxy.example.com",
            "port": 443,
            "username": "user",
            "password": "secret",
            "udp_mod": "datagram"
        }))
        .unwrap();
        let endpoint = outbound.endpoint("proxy").unwrap();
        assert_eq!(endpoint.host(), "proxy.example.com");
        assert_eq!(endpoint.port(), 443);
        assert_eq!(outbound.credentials("proxy").unwrap(), ("user", "secret"));
        assert_eq!(outbound.connect_timeout(), Duration::from_secs(30));
        assert_eq!(outbound.udp_mode_or("stream"), "datagram");
    }
}
