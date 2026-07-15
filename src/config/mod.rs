use anyhow::{Context, bail};
use hashbrown::HashMap;
use serde::{Deserialize, Serialize};
use serde_json;
use serde_json5;
use std::fs::File;
use std::io::Read;
use std::path::PathBuf;
use tracing::info;

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
    #[serde(default = "default_true")]
    pub disable_mux: bool,
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
