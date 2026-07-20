use anyhow::{Context, Result, bail};
use std::fs::File;
use std::io::BufReader;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;

use async_trait::async_trait;
use rustls::pki_types::CertificateDer;
use sha2::{Digest, Sha224};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::time::timeout;
use tokio_rustls::{TlsConnector, rustls};

use crate::config::OutboundConfig;
use crate::proxy::outbound::pool::PoolOutbound;
use crate::proxy::{
    SourceAddr, TargetAddr, TlsConfig, configure_jls_client,
    outbound::{AnyOutbound, AnyPacket, AnyStream, LazyHandshakeStream, PacketInfo},
};
use crate::utils::new_io_other_error;
use bytes::Bytes;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub struct TrojanOutbound {
    pub address: TargetAddr,
    pub password: String,
    pub tls: TlsConfig,
    pub connect_timeout: Duration,
    pub dns_server_name: Option<String>,
    pub bind_interface: Option<String>,
    pub pool_size: u16,

    password_hash: String,
    tag: String,
}

impl TrojanOutbound {
    pub fn new(tag: String, cfg: &OutboundConfig) -> Result<Arc<dyn AnyOutbound>> {
        let address = cfg.address.clone().context(format!(
            "shadowquic outbound '{}' requires address",
            tag.clone()
        ))?;
        let port = cfg.port.context(format!(
            "shadowquic outbound '{}' requires port",
            tag.clone()
        ))?;
        let address = TargetAddr::from_str2(&address, port)?;

        let password = cfg
            .password
            .clone()
            .context(format!("trojan outbound '{}' requires password", tag))?;

        let tls = TlsConfig::from_outbound(cfg)?;
        let connect_timeout = Duration::from_secs(cfg.connect_timeout.unwrap_or(30));
        let pool_size = cfg.pool_size.unwrap_or(0);

        let mut hasher = Sha224::new();
        hasher.update(password.as_bytes());
        let result = hasher.finalize();
        let password_hash = hex::encode(result);

        let trojan = Self {
            address,
            password,
            tls,
            connect_timeout,
            dns_server_name: cfg.dns.clone(),
            bind_interface: cfg.bind_interface.clone(),
            pool_size,
            password_hash,
            tag,
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

    fn tls_server_name(&self) -> Result<rustls::pki_types::ServerName<'static>> {
        let host = self.address.host();
        let name = self.tls.sni.as_deref().unwrap_or(&host);
        Ok(rustls::pki_types::ServerName::try_from(name)
            .map_err(|e| new_io_other_error(e))?
            .to_owned())
    }

    fn build_tls_client_config(&self) -> Result<rustls::ClientConfig> {
        let _ = rustls::crypto::ring::default_provider().install_default();

        if !self.tls.insecure {
            let mut root_store = rustls::RootCertStore::empty();
            if let Some(cert_path) = self.tls.cert.as_deref() {
                for cert in load_certs(cert_path)? {
                    root_store.add(cert).map_err(|e| new_io_other_error(e))?;
                }
            } else {
                root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            }

            let mut config = rustls::ClientConfig::builder()
                .with_root_certificates(root_store)
                .with_no_client_auth();
            configure_jls_client(&mut config, &self.tls);
            Ok(config)
        } else {
            let config = rustls::ClientConfig::builder()
                .with_root_certificates(rustls::RootCertStore::empty())
                .with_no_client_auth();
            let mut config = config;
            config
                .dangerous()
                .set_certificate_verifier(Arc::new(SkipServerVerification));
            configure_jls_client(&mut config, &self.tls);
            Ok(config)
        }
    }

    async fn connect_tls<S>(&self, stream: S) -> Result<tokio_rustls::client::TlsStream<S>>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send,
    {
        let config = Arc::new(self.build_tls_client_config()?);
        let connector = TlsConnector::from(config);
        let domain = self.tls_server_name()?;
        let timeout_duration = self.connect_timeout();

        let tls_stream = timeout(timeout_duration, connector.connect(domain, stream))
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

fn load_certs(path: &str) -> anyhow::Result<Vec<CertificateDer<'static>>> {
    let file =
        File::open(path).with_context(|| format!("Failed to open certificate file: {}", path))?;

    let mut reader = BufReader::new(file);

    rustls_pemfile::certs(&mut reader)
        .map(|result| {
            result
                .map(|c| c.into_owned())
                .context("Failed to parse PEM certificate")
        })
        .collect()
}

#[derive(Debug)]
struct SkipServerVerification;

impl rustls::client::danger::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ED25519,
        ]
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

        if self.tls.enable {
            Ok(Box::new(self.connect_tls(stream).await?))
        } else {
            Ok(Box::new(stream))
        }
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

struct TrojanUdpSocket {
    rx: Mutex<tokio::io::ReadHalf<AnyStream>>,
    tx: Mutex<tokio::io::WriteHalf<AnyStream>>,
}

impl TrojanUdpSocket {
    fn new(stream: AnyStream) -> Self {
        let (rx, tx) = tokio::io::split(stream);
        Self {
            rx: Mutex::new(rx),
            tx: Mutex::new(tx),
        }
    }
}

#[async_trait]
impl AnyPacket for TrojanUdpSocket {
    async fn send_to(&self, buf: Bytes, target: &TargetAddr, _from: &SourceAddr) -> Result<usize> {
        let mut packet = target.to_bytes();

        packet.extend_from_slice(&(buf.len() as u16).to_be_bytes());
        packet.extend_from_slice(b"\r\n");
        packet.extend_from_slice(&buf);

        let mut tx = self.tx.lock().await;
        tx.write_all(&packet).await?;
        tx.flush().await?;

        Ok(buf.len())
    }

    async fn recv_from(&self) -> Result<PacketInfo> {
        let mut rx = self.rx.lock().await;

        let target = TargetAddr::read_from(&mut *rx).await?;

        let length = rx.read_u16().await?;
        let mut crlf = [0u8; 2];
        rx.read_exact(&mut crlf).await?;

        if &crlf != b"\r\n" {
            bail!("Invalid CRLF in Trojan UDP packet")
        }

        let mut payload = vec![0u8; length as usize];
        rx.read_exact(&mut payload).await?;

        let dummy_target = TargetAddr::dummy();

        Ok((target, dummy_target, Bytes::from(payload)))
    }
}
