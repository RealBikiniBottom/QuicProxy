use anyhow::{Context, Result, bail};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;

use async_trait::async_trait;
use sha2::{Digest, Sha224};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::time::timeout;
use tokio_rustls::{TlsConnector, rustls};

use crate::config::{OutboundConfig, TransportConfig};
use crate::proxy::outbound::pool::PoolOutbound;
use crate::proxy::outbound::transport::wrap_transport_stream;
use crate::proxy::{
    SourceAddr, TargetAddr, TlsConfig,
    outbound::{AnyOutbound, AnyPacket, AnyStream, LazyHandshakeStream, PacketInfo},
};
use crate::utils::new_io_other_error;
use crate::utils::read_ahead;
use bytes::{Buf, Bytes, BytesMut};
use tokio::io::AsyncWriteExt;

pub struct TrojanOutbound {
    pub address: TargetAddr,
    pub password: String,
    pub tls: TlsConfig,
    pub transport: Option<TransportConfig>,
    pub connect_timeout: Duration,
    pub dns_server_name: Option<String>,
    pub bind_interface: Option<String>,
    pub pool_size: u16,

    password_hash: String,
    tag: String,
    /// Built once so every connection shares the TLS session cache and skips reloading certificates.
    tls_connector: TlsConnector,
    server_name: rustls::pki_types::ServerName<'static>,
}

impl TrojanOutbound {
    pub fn new(tag: String, cfg: &OutboundConfig) -> Result<Arc<dyn AnyOutbound>> {
        let address = cfg.endpoint(&tag)?;

        let password = cfg
            .password
            .clone()
            .context(format!("trojan outbound '{}' requires password", tag))?;

        let tls = TlsConfig::from_outbound(cfg)?;
        let connect_timeout = cfg.connect_timeout();
        let pool_size = cfg.pool_size.unwrap_or(0);

        let mut hasher = Sha224::new();
        hasher.update(password.as_bytes());
        let result = hasher.finalize();
        let password_hash = hex::encode(result);

        let tls_connector = TlsConnector::from(Arc::new(crate::utils::tls::client_config(&tls)?));
        let server_name = Self::tls_server_name(&tls, &address)?;

        let trojan = Self {
            address,
            password,
            tls,
            transport: cfg.transport.clone(),
            connect_timeout,
            dns_server_name: cfg.dns.clone(),
            bind_interface: cfg.bind_interface.clone(),
            pool_size,
            password_hash,
            tag,
            tls_connector,
            server_name,
        };

        if trojan.pool_size > 0 {
            Ok(PoolOutbound::new(
                trojan.pool_size as usize,
                Arc::new(trojan),
            )?)
        } else {
            Ok(Arc::new(trojan))
        }
    }

    fn generate_handshake(&self, target: &TargetAddr, is_udp: bool) -> Vec<u8> {
        // Handshake logic
        // 1. Send password hash + CRLF
        let mut buf = Vec::new();
        buf.extend_from_slice(self.password_hash.as_bytes());
        buf.extend_from_slice(b"\r\n");

        // 2. Send Command (CONNECT=1, UDP_ASSOCIATE=3) + Atyp + Addr + Port
        buf.push(if is_udp { 3 } else { 1 });

        buf.extend_from_slice(&target.to_bytes());

        buf.extend_from_slice(b"\r\n");
        buf
    }

    fn tls_server_name(
        tls: &TlsConfig,
        address: &TargetAddr,
    ) -> Result<rustls::pki_types::ServerName<'static>> {
        let host = address.host();
        let name = tls.sni.as_deref().unwrap_or(&host);
        Ok(rustls::pki_types::ServerName::try_from(name)
            .map_err(|e| new_io_other_error(e))?
            .to_owned())
    }

    async fn connect_tls<S>(&self, stream: S) -> Result<tokio_rustls::client::TlsStream<S>>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send,
    {
        let domain = self.server_name.clone();
        let timeout_duration = self.connect_timeout();

        let tls_stream = timeout(timeout_duration, self.tls_connector.connect(domain, stream))
            .await
            .with_context(|| format!("Trojan TLS handshake timeout after {:?}", timeout_duration))?
            .context("TLS handshake failed")?;

        crate::proxy::verify_jls_connection(&self.tls, tls_stream.get_ref().1.jls_state())
            .context("Trojan JLS handshake failed")?;

        Ok(tls_stream)
    }

    async fn trojan_connect_header(&self, target: &TargetAddr, is_udp: bool) -> Result<AnyStream> {
        let stream = self.connect_stream_base().await?;
        let handshake = self.generate_handshake(target, is_udp);
        Ok(Box::new(LazyHandshakeStream::new(stream, handshake)))
    }
}

#[async_trait]
impl AnyOutbound for TrojanOutbound {
    fn tag(&self) -> &str {
        &self.tag
    }

    fn protocol(&self) -> &str {
        "trojan"
    }

    fn dns_server_name(&self) -> Option<&str> {
        self.dns_server_name.as_deref()
    }

    fn bind_interface(&self) -> Option<&str> {
        self.bind_interface.as_deref()
    }

    async fn connect_packet(&self, target: &TargetAddr) -> anyhow::Result<Arc<dyn AnyPacket>> {
        let stream = self.trojan_connect_header(target, true).await?;
        Ok(Arc::new(TrojanUdpSocket::new(stream)))
    }

    fn connect_timeout(&self) -> Duration {
        self.connect_timeout
    }

    async fn connect_stream_base(&self) -> anyhow::Result<AnyStream> {
        let socket_addr = self.resolve_addr(&self.address).await?;
        let stream = self.new_tcp_stream(socket_addr).await?;

        let stream: AnyStream = if self.tls.enable {
            Box::new(self.connect_tls(stream).await?)
        } else {
            Box::new(stream)
        };

        // A transport (e.g. ws) sits on top of the base connection: the TLS
        // stream - when enabled - is the raw transport underneath it, which
        // matches how sing-box layers trojan transports.
        wrap_transport_stream(
            self.transport.as_ref(),
            &self.address,
            stream,
            self.connect_timeout(),
        )
        .await
        .with_context(|| format!("trojan outbound '{}' transport failed", self.tag))
    }

    async fn connect_stream_with(
        &self,
        target: &TargetAddr,
        stream: AnyStream,
    ) -> anyhow::Result<AnyStream> {
        let handshake = self.generate_handshake(target, false);
        Ok(Box::new(LazyHandshakeStream::new(stream, handshake)))
    }
}

/// Reads Trojan UDP packets (`addr | u16 length | CRLF | payload`) through one read-ahead
/// buffer, so a packet costs one buffered read instead of six small ones and the payload is
/// cut out without copying. Cancel safe: a packet is consumed only once it is fully buffered.
pub(crate) struct UdpPacketReader<R> {
    rx: R,
    buf: BytesMut,
}

impl<R: AsyncRead + Unpin> UdpPacketReader<R> {
    pub(crate) fn new(rx: R) -> Self {
        Self {
            rx,
            buf: BytesMut::new(),
        }
    }

    pub(crate) async fn read_packet(&mut self) -> Result<(TargetAddr, Bytes)> {
        loop {
            let mut need = self.buf.len() + 1;
            if let Some((addr, addr_len)) = TargetAddr::decode(&self.buf)? {
                let header_len = addr_len + 4;
                if self.buf.len() >= header_len {
                    if &self.buf[addr_len + 2..header_len] != b"\r\n" {
                        bail!("Invalid CRLF in Trojan UDP packet")
                    }
                    let len =
                        u16::from_be_bytes([self.buf[addr_len], self.buf[addr_len + 1]]) as usize;
                    if self.buf.len() >= header_len + len {
                        self.buf.advance(header_len);
                        return Ok((addr, self.buf.split_to(len).freeze()));
                    }
                    need = header_len + len;
                }
            }
            read_ahead::fill(&mut self.rx, &mut self.buf, need, false).await?;
        }
    }
}

struct TrojanUdpSocket {
    rx: Mutex<UdpPacketReader<tokio::io::ReadHalf<AnyStream>>>,
    tx: Mutex<tokio::io::WriteHalf<AnyStream>>,
}

impl TrojanUdpSocket {
    fn new(stream: AnyStream) -> Self {
        let (rx, tx) = tokio::io::split(stream);
        Self {
            rx: Mutex::new(UdpPacketReader::new(rx)),
            tx: Mutex::new(tx),
        }
    }
}

#[async_trait]
impl AnyPacket for TrojanUdpSocket {
    async fn send_to(&self, buf: Bytes, _from: &SourceAddr, target: &TargetAddr) -> Result<usize> {
        let mut packet = Vec::with_capacity(target.encoded_len() + 4 + buf.len());
        target.write_to(&mut packet);

        packet.extend_from_slice(&(buf.len() as u16).to_be_bytes());
        packet.extend_from_slice(b"\r\n");
        packet.extend_from_slice(&buf);

        let mut tx = self.tx.lock().await;
        tx.write_all(&packet).await?;
        tx.flush().await?;

        Ok(buf.len())
    }

    async fn recv_from(&self) -> Result<PacketInfo> {
        // A reply datagram carries the source address of the responding peer.
        let (source, payload) = self.rx.lock().await.read_packet().await?;
        Ok((source, TargetAddr::dummy(), payload))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn udp_reader_handles_split_and_coalesced_packets() {
        let mut wire = Vec::new();
        let first = TargetAddr::Domain("example.com".to_string(), 53);
        let second = TargetAddr::from_str("[2001:db8::1]:443").unwrap();
        for (addr, payload) in [(&first, &b"hello"[..]), (&second, &[7u8; 3000][..])] {
            addr.write_to(&mut wire);
            wire.extend_from_slice(&(payload.len() as u16).to_be_bytes());
            wire.extend_from_slice(b"\r\n");
            wire.extend_from_slice(payload);
        }

        // Feed the bytes 7 at a time so headers and payloads arrive split up.
        let (mut client, server) = tokio::io::duplex(7);
        let writer = tokio::spawn(async move { client.write_all(&wire).await });
        let mut reader = UdpPacketReader::new(server);

        let (addr, payload) = reader.read_packet().await.unwrap();
        assert_eq!(addr, first);
        assert_eq!(&payload[..], b"hello");
        let (addr, payload) = reader.read_packet().await.unwrap();
        assert_eq!(addr, second);
        assert_eq!(&payload[..], &[7u8; 3000][..]);

        writer.await.unwrap().unwrap();
        assert!(
            reader.read_packet().await.is_err(),
            "EOF after the last packet"
        );
    }

    #[test]
    fn decode_needs_the_whole_address() {
        let mut encoded = Vec::new();
        TargetAddr::Domain("example.com".to_string(), 80).write_to(&mut encoded);
        for end in 0..encoded.len() {
            assert!(TargetAddr::decode(&encoded[..end]).unwrap().is_none());
        }
        let (addr, used) = TargetAddr::decode(&encoded).unwrap().unwrap();
        assert_eq!(addr, TargetAddr::Domain("example.com".to_string(), 80));
        assert_eq!(used, encoded.len());
        assert!(TargetAddr::decode(&[9]).is_err());
    }
}
