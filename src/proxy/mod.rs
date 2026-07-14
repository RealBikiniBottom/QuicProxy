pub mod anytls_proto;
pub mod inbound;
pub mod observe;
pub mod outbound;
pub mod router;
pub mod shadowquic_udp;

use crate::config::{InboundConfig, OutboundConfig};
use crate::utils::new_io_other_error;
use anyhow::{Context, Result, bail};
use serde::Serialize;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::sync::Notify;

pub type SourceAddr = TargetAddr;

#[derive(Debug, Clone, Hash, Eq, PartialEq, Serialize)]
pub enum TargetAddr {
    Ip(SocketAddr),
    Domain(String, u16),
}

impl TargetAddr {
    pub fn port(&self) -> u16 {
        match self {
            TargetAddr::Ip(addr) => addr.port(),
            TargetAddr::Domain(_, port) => *port,
        }
    }

    pub fn host(&self) -> String {
        match self {
            TargetAddr::Ip(socket_addr) => socket_addr.ip().to_string(),
            TargetAddr::Domain(domain, _port) => domain.clone(),
        }
    }

    /// Convert the target address to bytes according to SOCKS5 / Trojan address format
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut packet = Vec::new();
        match self {
            TargetAddr::Ip(SocketAddr::V4(addr)) => {
                packet.push(1); // IPv4
                packet.extend_from_slice(&addr.ip().octets());
                packet.extend_from_slice(&addr.port().to_be_bytes());
            }
            TargetAddr::Ip(SocketAddr::V6(addr)) => {
                packet.push(4); // IPv6
                packet.extend_from_slice(&addr.ip().octets());
                packet.extend_from_slice(&addr.port().to_be_bytes());
            }
            TargetAddr::Domain(domain, port) => {
                packet.push(3); // Domain
                packet.push(domain.len() as u8);
                packet.extend_from_slice(domain.as_bytes());
                packet.extend_from_slice(&port.to_be_bytes());
            }
        }
        packet
    }

    /// Read a TargetAddr from an async stream according to SOCKS5 / Trojan address format
    pub async fn read_from<S: AsyncRead + Unpin>(stream: &mut S) -> anyhow::Result<Self> {
        let atyp = stream.read_u8().await.context("faild to read_u8")?;
        match atyp {
            1 => {
                let mut ip_bytes = [0u8; 4];
                stream.read_exact(&mut ip_bytes).await?;
                let port = stream.read_u16().await?;
                Ok(TargetAddr::Ip(SocketAddr::new(
                    std::net::IpAddr::V4(std::net::Ipv4Addr::from(ip_bytes)),
                    port,
                )))
            }
            3 => {
                let len = stream.read_u8().await?;
                let mut domain_bytes = vec![0u8; len as usize];
                stream.read_exact(&mut domain_bytes).await?;
                let port = stream.read_u16().await?;
                let domain = String::from_utf8(domain_bytes)
                    .map_err(|e| new_io_other_error(format!("Invalid domain: {}", e)))?;
                Ok(TargetAddr::Domain(domain, port))
            }
            4 => {
                let mut ip_bytes = [0u8; 16];
                stream.read_exact(&mut ip_bytes).await?;
                let port = stream.read_u16().await?;
                Ok(TargetAddr::Ip(SocketAddr::new(
                    std::net::IpAddr::V6(std::net::Ipv6Addr::from(ip_bytes)),
                    port,
                )))
            }
            _ => bail!("Invalid ATYP: {}", atyp),
        }
    }

    pub fn dummy() -> Self {
        TargetAddr::Ip(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0))
    }

    /// Parse a TargetAddr from string format
    ///
    /// Supported formats:
    /// - IPv4: `"192.168.1.1:8080"`
    /// - IPv6: `"[::1]:8080"` (bracketed, as per RFC 3986)
    /// - Domain: `"example.com:443"` or `"sub.domain.co.uk:80"`
    ///
    /// # Examples
    /// ```
    /// use quicproxy::proxy::TargetAddr;
    ///
    /// let _addr = TargetAddr::from_str("1.1.1.1:53").unwrap();
    /// let _addr = TargetAddr::from_str("[2001:db8::1]:443").unwrap();
    /// let _addr = TargetAddr::from_str("google.com:80").unwrap();
    /// ```
    pub fn from_str(s: &str) -> anyhow::Result<Self> {
        // 1. Try standard SocketAddr parsing (handles IPv4 + bracketed IPv6)
        if let Ok(addr) = SocketAddr::from_str(s) {
            return Ok(TargetAddr::Ip(addr));
        }

        // 2. Fallback: parse as domain:port
        // Find the last colon to handle domains that might contain colons (edge cases)
        let (host, port_str) =
            s.rfind(':')
                .map(|pos| (&s[..pos], &s[pos + 1..]))
                .context(format!(
                    "Invalid address format '{}': expected host:port",
                    s
                ))?;

        // Validate and parse port
        let port = port_str
            .parse::<u16>()
            .context(format!("Invalid port '{}' in address: {}", port_str, s))?;

        // Basic host validation
        if host.is_empty() {
            bail!("Empty hostname in address: {}", s);
        }
        if host.len() > 255 {
            bail!("Hostname exceeds 255 characters: {}", s);
        }

        // Accept domain as-is (DNS resolution deferred to connect time)
        // Allow permissive charset to support IDN, internal hostnames, etc.
        Ok(TargetAddr::Domain(host.to_string(), port))
    }

    pub fn from_str2(domain: &str, port: u16) -> anyhow::Result<Self> {
        TargetAddr::from_str(format!("{}:{}", domain, port).as_ref())
    }
}

impl fmt::Display for TargetAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TargetAddr::Ip(addr) => write!(f, "{}", addr),
            TargetAddr::Domain(domain, port) => write!(f, "{}:{}", domain, port),
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct TlsConfig {
    pub enable: bool,
    pub insecure: bool,
    pub zero_rtt: bool,
    pub sni: Option<String>,
    pub cert: Option<String>,
    pub key: Option<String>,
    pub alpns: Option<Vec<String>>,

    pub enable_jls: bool,
    pub jls_username: String,
    pub jls_password: String,
}

fn validate_jls(enable: bool, username: &str, password: &str) -> Result<()> {
    if enable && (username.is_empty() || password.is_empty()) {
        bail!("JLS requires both jls_username and jls_password");
    }
    Ok(())
}

/// Apply the shared JLS client settings used by TCP-based TLS protocols.
pub(crate) fn configure_jls_client(config: &mut rustls::ClientConfig, tls: &TlsConfig) {
    if tls.enable_jls {
        config.jls_config = rustls::jls::JlsClientConfig::new(&tls.jls_password, &tls.jls_username);
    }
}

/// Apply the shared JLS server settings used by TCP-based TLS protocols.
pub(crate) fn configure_jls_server(config: &mut rustls::ServerConfig, tls: &TlsConfig) {
    if !tls.enable_jls {
        return;
    }

    let mut jls_config = rustls::jls::JlsServerConfig::default()
        .enable(true)
        .add_user(tls.jls_password.clone(), tls.jls_username.clone());
    if let Some(server_name) = tls.sni.as_ref() {
        jls_config = jls_config.with_server_name(server_name.clone());
    }
    config.jls_config = jls_config.into();
}

impl TlsConfig {
    pub fn from_inbound(config: &InboundConfig) -> Result<Self> {
        let tls = config.tls.as_ref();

        let (cert, key, alpns, jls_username, jls_password, enable_jls) = match tls {
            Some(t) => (
                t.cert.clone(),
                t.key.clone(),
                t.alpn.clone(),
                t.jls_username.clone().unwrap_or_default(),
                t.jls_password.clone().unwrap_or_default(),
                t.enable_jls,
            ),
            None => (None, None, None, String::new(), String::new(), false),
        };

        validate_jls(enable_jls, &jls_username, &jls_password)?;

        Ok(Self {
            enable: tls.map(|t| t.enable).unwrap_or(true),
            insecure: false,
            zero_rtt: false,
            sni: tls.and_then(|t| t.server_name.clone()),
            cert,
            key,
            alpns,
            enable_jls,
            jls_username,
            jls_password,
        })
    }

    pub fn from_outbound(config: &OutboundConfig) -> Result<Self> {
        let tls = config.tls.as_ref();

        let (insecure, sni, cert, alpns, jls_username, jls_password, enable_jls) = match tls {
            Some(t) => (
                t.insecure.unwrap_or(false),
                t.server_name.clone(),
                t.ca.clone(),
                t.alpn.clone(),
                t.jls_username.clone().unwrap_or_default(),
                t.jls_password.clone().unwrap_or_default(),
                t.enable_jls,
            ),
            None => (false, None, None, None, String::new(), String::new(), false),
        };

        validate_jls(enable_jls, &jls_username, &jls_password)?;

        Ok(Self {
            enable: tls.map(|t| t.enable).unwrap_or(true),
            insecure,
            zero_rtt: false,
            sni,
            cert,
            key: None,
            alpns,
            enable_jls,
            jls_username,
            jls_password,
        })
    }
}

#[derive(Clone)]
pub struct SessionCloser {
    closed: Arc<AtomicBool>,
    notify: Arc<Notify>,
}

impl SessionCloser {
    pub fn new() -> Self {
        Self {
            closed: Arc::new(AtomicBool::new(false)),
            notify: Arc::new(Notify::new()),
        }
    }

    /// 关闭关联的会话
    pub fn close(&self) {
        if !self.closed.swap(true, Ordering::Release) {
            self.notify.notify_waiters();
        }
    }

    /// 等待关闭信号
    pub async fn wait(&self) {
        while !self.is_closed() {
            self.notify.notified().await;
        }
    }

    /// 检查是否已关闭
    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }
}

#[cfg(test)]
mod jls_tests {
    use super::*;
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio_rustls::{TlsAcceptor, TlsConnector};

    #[tokio::test]
    async fn tcp_tls_jls_authenticates_both_peers() {
        let _ = rustls::crypto::ring::default_provider().install_default();

        let tls = TlsConfig {
            enable_jls: true,
            jls_username: "jls-user".into(),
            jls_password: "jls-password".into(),
            sni: Some("localhost".into()),
            ..TlsConfig::default()
        };
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let cert_chain = vec![cert.cert.der().clone()];
        let private_key =
            rustls::pki_types::PrivateKeyDer::try_from(cert.signing_key.serialize_der()).unwrap();

        let mut server_config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(cert_chain, private_key)
            .unwrap();
        configure_jls_server(&mut server_config, &tls);

        let mut client_config = rustls::ClientConfig::builder()
            .with_root_certificates(rustls::RootCertStore::empty())
            .with_no_client_auth();
        configure_jls_client(&mut client_config, &tls);

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut stream = TlsAcceptor::from(Arc::new(server_config))
                .accept(stream)
                .await
                .unwrap();
            assert!(matches!(
                stream.get_ref().1.jls_state(),
                rustls::jls::JlsState::AuthSuccess(_)
            ));
            stream.write_all(b"ok").await.unwrap();
        });

        let tcp = tokio::net::TcpStream::connect(address).await.unwrap();
        let server_name = rustls::pki_types::ServerName::try_from("localhost")
            .unwrap()
            .to_owned();
        let mut stream = TlsConnector::from(Arc::new(client_config))
            .connect(server_name, tcp)
            .await
            .unwrap();
        assert!(matches!(
            stream.get_ref().1.jls_state(),
            rustls::jls::JlsState::AuthSuccess(_)
        ));
        let mut response = [0; 2];
        stream.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"ok");
        server.await.unwrap();
    }
}
