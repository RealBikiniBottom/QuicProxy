pub mod datagram;
pub mod stream;

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use async_trait::async_trait;
// futures used via Sink/Stream supertrait methods in vmess
use shadowsocks::{
    ProxyClientStream, ProxySocket, ServerConfig, config::ServerType, context::Context as SsContext,
    relay::udprelay::proxy_socket::UdpSocketType,
};

use crate::config::OutboundConfig;
use crate::proxy::outbound::{AnyOutbound, AnyPacket, AnyStream, PacketInfo};
use crate::proxy::{SourceAddr, TargetAddr};
use crate::utils::new_io_other_error;

use bytes::Bytes;
use tokio::sync::Mutex;

use self::stream::ShadowSocksStream;

pub struct ShadowsocksOutbound {
    tag: String,
    server: TargetAddr,
    password: String,
    cipher: String,
    connect_timeout: Duration,
    dns_server_name: Option<String>,
    bind_interface: Option<String>,
}

fn map_cipher(cipher: &str) -> std::io::Result<shadowsocks::crypto::CipherKind> {
    use shadowsocks::crypto::CipherKind;
    match cipher {
        "aes-128-gcm" => Ok(CipherKind::AES_128_GCM),
        "aes-256-gcm" => Ok(CipherKind::AES_256_GCM),
        "chacha20-ietf-poly1305" => Ok(CipherKind::CHACHA20_POLY1305),
        "2022-blake3-aes-128-gcm" => Ok(CipherKind::AEAD2022_BLAKE3_AES_128_GCM),
        "2022-blake3-aes-256-gcm" => Ok(CipherKind::AEAD2022_BLAKE3_AES_256_GCM),
        "2022-blake3-chacha20-ietf-poly1305" => {
            Ok(CipherKind::AEAD2022_BLAKE3_CHACHA20_POLY1305)
        }
        "rc4-md5" => Ok(CipherKind::SS_RC4_MD5),
        _ => Err(std::io::Error::other("unsupported cipher")),
    }
}

impl ShadowsocksOutbound {
    pub fn new(tag: String, cfg: &OutboundConfig) -> Result<Arc<dyn AnyOutbound>> {
        let address = cfg
            .address
            .clone()
            .context(format!("shadowsocks outbound '{}' requires address", tag))?;
        let port = cfg
            .port
            .context(format!("shadowsocks outbound '{}' requires port", tag))?;
        let server = TargetAddr::from_str2(&address, port)?;

        let password = cfg.password.clone().context(format!(
            "shadowsocks outbound '{}' requires password",
            tag
        ))?;

        let cipher = cfg
            .udp_mod
            .clone()
            .unwrap_or_else(|| "chacha20-ietf-poly1305".to_string());

        Ok(Arc::new(Self {
            tag,
            server,
            password,
            cipher,
            connect_timeout: Duration::from_secs(cfg.connect_timeout.unwrap_or(30)),
            dns_server_name: cfg.dns.clone(),
            bind_interface: cfg.bind_interface.clone(),
        }))
    }

    fn server_config(&self) -> Result<ServerConfig, std::io::Error> {
        ServerConfig::new(
            (self.server.host(), self.server.port()),
            self.password.clone(),
            map_cipher(self.cipher.as_str())?,
        )
        .map_err(|e| std::io::Error::other(e.to_string()))
    }
}

#[async_trait]
impl AnyOutbound for ShadowsocksOutbound {
    fn tag(&self) -> &str {
        &self.tag
    }

    fn protocol(&self) -> &str {
        "shadowsocks"
    }

    fn dns_server_name(&self) -> Option<&str> {
        self.dns_server_name.as_deref()
    }

    fn bind_interface(&self) -> Option<&str> {
        self.bind_interface.as_deref()
    }

    fn connect_timeout(&self) -> Duration {
        self.connect_timeout
    }

    async fn connect_stream_base(&self) -> anyhow::Result<AnyStream> {
        let proxy_addr = self.resolve_addr(&self.server).await?;
        let stream = self.new_tcp_stream(proxy_addr).await?;
        Ok(Box::new(stream))
    }

    async fn connect_stream_with(
        &self,
        target: &TargetAddr,
        stream: AnyStream,
    ) -> anyhow::Result<AnyStream> {
        let ctx = SsContext::new_shared(ServerType::Local);
        let cfg = self
            .server_config()
            .map_err(|e| new_io_other_error(format!("ss config: {}", e)))?;

        let ss_stream = ProxyClientStream::from_stream(
            ctx,
            stream,
            &cfg,
            (target.host(), target.port()),
        );

        Ok(Box::new(ShadowSocksStream(ss_stream)))
    }

    async fn connect_packet(&self, _target: &TargetAddr) -> anyhow::Result<Arc<dyn AnyPacket>> {
        let ctx = SsContext::new_shared(ServerType::Local);
        let cfg = self
            .server_config()
            .map_err(|e| new_io_other_error(format!("ss config: {}", e)))?;

        let proxy_addr = self.resolve_addr(&self.server).await?;
        let tokio_socket = self
            .new_udp_socket(proxy_addr)
            .await
            .map_err(|e| new_io_other_error(format!("ss udp socket: {}", e)))?;

        // Convert tokio UdpSocket to shadowsocks UdpSocket (which implements DatagramSend/Receive)
        let ss_socket: shadowsocks::net::udp::UdpSocket = tokio_socket.into();
        let proxy_socket = ProxySocket::from_socket(UdpSocketType::Client, ctx, &cfg, ss_socket);

        Ok(Arc::new(SsUdpSocket::new(proxy_socket, proxy_addr)))
    }
}

struct SsUdpSocket<S> {
    inner: Mutex<crate::proxy::outbound::shadowsocks::datagram::OutboundDatagramShadowsocks<S>>,
}

impl<S> SsUdpSocket<S>
where
    S: shadowsocks::relay::udprelay::DatagramSend + shadowsocks::relay::udprelay::DatagramReceive + Unpin,
{
    fn new(socket: ProxySocket<S>, remote_addr: std::net::SocketAddr) -> Self {
        Self {
            inner: Mutex::new(crate::proxy::outbound::shadowsocks::datagram::OutboundDatagramShadowsocks::new(socket, remote_addr)),
        }
    }
}

#[async_trait]
impl<S> AnyPacket for SsUdpSocket<S>
where
    S: shadowsocks::relay::udprelay::DatagramSend
        + shadowsocks::relay::udprelay::DatagramReceive
        + Unpin
        + Send
        + Sync
        + 'static,
{
    async fn send_to(
        &self,
        buf: Bytes,
        _from: &SourceAddr,
        target: &TargetAddr,
    ) -> Result<usize> {
        use futures::SinkExt;
        let len = buf.len();
        let mut inner = self.inner.lock().await;
        inner
            .send((target.clone(), buf))
            .await
            .map_err(|e| new_io_other_error(format!("ss udp send: {}", e)))?;
        Ok(len)
    }

    async fn recv_from(&self) -> Result<PacketInfo> {
        use futures::StreamExt;
        let mut inner = self.inner.lock().await;
        match inner.next().await {
            Some(packet) => Ok(packet),
            None => anyhow::bail!("ss udp stream closed"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::OutboundConfig;

    fn make_config() -> OutboundConfig {
        serde_json::from_value(serde_json::json!({
            "type": "shadowsocks",
            "address": "127.0.0.1",
            "port": 8388,
            "password": "test-password",
            "udp_mod": "chacha20-ietf-poly1305",
            "connect_timeout": 10,
            "mtu_discoveriy": false,
            "gso": false,
            "min_mtu": 1200,
            "initial_mtu": 1200,
        })).unwrap()
    }

    #[test]
    fn test_ss_outbound_construction() {
        let cfg = make_config();
        let result = ShadowsocksOutbound::new("test-ss".to_string(), &cfg);
        assert!(result.is_ok());
        let outbound = result.unwrap();
        assert_eq!(outbound.tag(), "test-ss");
        assert_eq!(outbound.protocol(), "shadowsocks");
    }

    #[test]
    fn test_ss_outbound_missing_password() {
        let mut cfg = make_config();
        cfg.password = None;
        let result = ShadowsocksOutbound::new("test-ss".to_string(), &cfg);
        assert!(result.is_err());
    }

    #[test]
    fn test_ss_outbound_missing_address() {
        let mut cfg = make_config();
        cfg.address = None;
        let result = ShadowsocksOutbound::new("test-ss".to_string(), &cfg);
        assert!(result.is_err());
    }

    #[test]
    fn test_ss_outbound_missing_port() {
        let mut cfg = make_config();
        cfg.port = None;
        let result = ShadowsocksOutbound::new("test-ss".to_string(), &cfg);
        assert!(result.is_err());
    }

    #[test]
    fn test_ss_outbound_connect_timeout() {
        let cfg = make_config();
        let outbound = ShadowsocksOutbound::new("test-ss".to_string(), &cfg).unwrap();
        assert_eq!(outbound.connect_timeout(), Duration::from_secs(10));
    }

    #[test]
    fn test_ss_outbound_default_connect_timeout() {
        let mut cfg = make_config();
        cfg.connect_timeout = None;
        let outbound = ShadowsocksOutbound::new("test-ss".to_string(), &cfg).unwrap();
        assert_eq!(outbound.connect_timeout(), Duration::from_secs(30));
    }

    #[test]
    fn test_ss_outbound_default_cipher() {
        let mut cfg = make_config();
        cfg.udp_mod = None;
        let result = ShadowsocksOutbound::new("test-ss".to_string(), &cfg);
        // Should default to chacha20-ietf-poly1305
        assert!(result.is_ok());
    }

    #[test]
    fn test_ss_map_cipher() {
        assert!(map_cipher("aes-128-gcm").is_ok());
        assert!(map_cipher("aes-256-gcm").is_ok());
        assert!(map_cipher("chacha20-ietf-poly1305").is_ok());
        assert!(map_cipher("2022-blake3-aes-128-gcm").is_ok());
        assert!(map_cipher("2022-blake3-aes-256-gcm").is_ok());
        assert!(map_cipher("2022-blake3-chacha20-ietf-poly1305").is_ok());
        assert!(map_cipher("rc4-md5").is_ok());
        assert!(map_cipher("unknown-cipher").is_err());
    }

    #[test]
    fn test_ss_server_config() {
        let cfg = make_config();
        let outbound = ShadowsocksOutbound::new("test-ss".to_string(), &cfg).unwrap();
        // Downcast to concrete type to test server_config
        let handler = &*outbound as *const dyn AnyOutbound as *const ShadowsocksOutbound;
        let handler = unsafe { &*handler };
        let result = handler.server_config();
        assert!(result.is_ok());
    }
}
