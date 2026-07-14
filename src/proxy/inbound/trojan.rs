use crate::config::InboundConfig;
use crate::proxy::TlsConfig;
use crate::proxy::outbound::{AnyPacket, AnyStream, PacketInfo};
use crate::proxy::router::{Router, get_router};
use crate::proxy::{SourceAddr, TargetAddr, inbound};
use crate::utils::new_io_other_error;
use anyhow::Context;
use async_trait::async_trait;
use bytes::Bytes;
use inbound::AnyInbound;
use sha2::{Digest, Sha224};
use std::fs::File;
use std::io::BufReader;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::Mutex;
use tokio_rustls::{TlsAcceptor, rustls};
use tracing::{Instrument, error, field, info, info_span};

struct TrojanInboundPacket {
    rx: Mutex<tokio::io::ReadHalf<AnyStream>>,
    tx: Mutex<tokio::io::WriteHalf<AnyStream>>,
    client_addr: TargetAddr,
}

impl TrojanInboundPacket {
    fn new(stream: AnyStream, client_addr: TargetAddr) -> Self {
        let (rx, tx) = tokio::io::split(stream);
        Self {
            rx: Mutex::new(rx),
            tx: Mutex::new(tx),
            client_addr,
        }
    }
}

#[async_trait]
impl AnyPacket for TrojanInboundPacket {
    async fn send_to(
        &self,
        buf: Bytes,
        from: &SourceAddr,
        _target: &TargetAddr,
    ) -> anyhow::Result<usize> {
        let mut packet = from.to_bytes();
        packet.extend_from_slice(&(buf.len() as u16).to_be_bytes());
        packet.extend_from_slice(b"\r\n");
        packet.extend_from_slice(&buf);

        let mut tx = self.tx.lock().await;
        tx.write_all(&packet).await?;
        tx.flush().await?;

        Ok(buf.len())
    }

    async fn recv_from(&self) -> anyhow::Result<PacketInfo> {
        let mut rx = self.rx.lock().await;

        let target = TargetAddr::read_from(&mut *rx).await?;

        let length = rx.read_u16().await?;
        let mut crlf = [0u8; 2];
        rx.read_exact(&mut crlf).await?;

        if &crlf != b"\r\n" {
            return Err(anyhow::anyhow!("Invalid CRLF in Trojan UDP packet"));
        }

        let mut payload = vec![0u8; length as usize];
        rx.read_exact(&mut payload).await?;

        Ok((self.client_addr.clone(), target, Bytes::from(payload)))
    }
}

#[derive(Clone)]
pub struct TrojanInbound {
    tag: String,
    address: SocketAddr,
    idle_timeout: Duration,
    password_hash: String,
    tls: TlsConfig,
}

#[derive(Debug)]
pub enum TrojanHandler<S> {
    Stream(S, TargetAddr),
    Udp(S, TargetAddr),
}

impl TrojanInbound {
    pub fn new(tag: String, cfg: &InboundConfig) -> anyhow::Result<Self> {
        let password = cfg.password.clone().context("requires password")?;
        let mut hasher = Sha224::new();
        hasher.update(password.as_bytes());
        let result = hasher.finalize();
        let password_hash = hex::encode(result);

        let tls = TlsConfig::from_inbound(cfg)?;

        let address: SocketAddr = format!(
            "{}:{}",
            cfg.address.clone().context("requires address")?,
            cfg.port.context("requires port")?
        )
        .parse()
        .context("Invalid address")?;

        Ok(Self {
            tag,
            password_hash,
            address,
            idle_timeout: Duration::from_secs(cfg.idle_timeout.unwrap_or(30)),
            tls,
        })
    }

    async fn listen_tcp(&self) -> anyhow::Result<()> {
        let listener = super::create_tcp_listener(self.address).await?;

        let _ = rustls::crypto::ring::default_provider().install_default();

        let server_config =
            if let (Some(cert_path), Some(key_path)) = (&self.tls.cert, &self.tls.key) {
                let certs = load_certs(cert_path)?;
                let key = load_keys(key_path)?;
                rustls::ServerConfig::builder()
                    .with_no_client_auth()
                    .with_single_cert(certs, key)
                    .map_err(|e| new_io_other_error(format!("TLS config error: {}", e)))?
            } else {
                info!("No TLS cert configured, generating default self-signed certificate");
                let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
                    .map_err(|e| new_io_other_error(format!("Failed to generate cert: {}", e)))?;
                let cert_der = cert.cert.der().to_vec();
                let key_der = cert.signing_key.serialize_der();

                let cert_chain = vec![rustls::pki_types::CertificateDer::from(cert_der)];
                let private_key = rustls::pki_types::PrivateKeyDer::try_from(key_der)
                    .map_err(|e| new_io_other_error(format!("Invalid private key: {}", e)))?;

                rustls::ServerConfig::builder()
                    .with_no_client_auth()
                    .with_single_cert(cert_chain, private_key)
                    .map_err(|e| new_io_other_error(format!("TLS config error: {}", e)))?
            };

        let tls_acceptor = TlsAcceptor::from(Arc::new(server_config));

        info!("Trojan TLS Inbound listening on {}", self.address);

        loop {
            let (socket, peer_addr) = match listener.accept().await {
                Ok(conn) => conn,
                Err(e) => {
                    error!("Trojan inbound accept error: {}", e);
                    continue;
                }
            };
            let peer_addr_str = peer_addr.to_string();
            let router = get_router();
            let password_hash = self.password_hash.clone();
            let tag = self.tag.clone();
            let udp_timeout = self.idle_timeout;
            let acceptor = tls_acceptor.clone();

            info!(
                "TrojanInbound accept proxy request from {}",
                peer_addr.to_string()
            );
            tokio::spawn(async move {
                let stream = match run_with_timeout(
                    acceptor.accept(socket),
                    udp_timeout,
                    &format!("Trojan TLS handshake timeout from {}", peer_addr_str),
                    &format!("Trojan TLS handshake error from {}", peer_addr_str),
                )
                .await
                {
                    Some(s) => Box::new(s) as AnyStream,
                    None => return,
                };

                handle_connection(
                    stream,
                    router,
                    password_hash,
                    tag,
                    peer_addr,
                    "TLS",
                    udp_timeout,
                )
                .await;
            });
        }
    }
}

#[async_trait]
impl AnyInbound for TrojanInbound {
    fn protocol(&self) -> &str {
        "trojan"
    }

    fn idle_timeout(&self) -> Duration {
        self.idle_timeout
    }

    async fn listen(&self) -> anyhow::Result<()> {
        self.listen_tcp().await
    }
}

fn load_certs(path: &str) -> std::io::Result<Vec<rustls::pki_types::CertificateDer<'static>>> {
    let file = File::open(path)?;
    let mut reader = BufReader::new(file);
    rustls_pemfile::certs(&mut reader)
        .map(|result| result.map(|c| c.into_owned()))
        .collect()
}

fn load_keys(path: &str) -> std::io::Result<rustls::pki_types::PrivateKeyDer<'static>> {
    let file = File::open(path)?;
    let mut reader = BufReader::new(file);
    let key = rustls_pemfile::private_key(&mut reader)?;
    key.ok_or(new_io_other_error("No private key found"))
}

async fn run_with_timeout<F, T, E>(
    fut: F,
    timeout_duration: Duration,
    timeout_msg: &str,
    error_msg: &str,
) -> Option<T>
where
    F: std::future::Future<Output = Result<T, E>>,
    E: std::fmt::Display,
{
    match tokio::time::timeout(timeout_duration, fut).await {
        Ok(Ok(res)) => Some(res),
        Ok(Err(e)) => {
            error!("{}: {}", error_msg, e);
            None
        }
        Err(_) => {
            error!("{}", timeout_msg);
            None
        }
    }
}

async fn handle_connection<S>(
    stream: S,
    router: Arc<Router>,
    password_hash: String,
    tag: String,
    peer_addr: SocketAddr,
    protocol: &'static str,
    udp_timeout: Duration,
) where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    async move {
        let result = match run_with_timeout(
            handle_client(stream, &password_hash),
            udp_timeout,
            &format!(
                "Trojan {} handshake timeout for client {}",
                protocol, peer_addr
            ),
            &format!("Error handling Trojan client {}", peer_addr),
        )
        .await
        {
            Some(res) => res,
            None => return,
        };

        match result {
            Some(TrojanHandler::Stream(stream, target)) => {
                let span = info_span!(
                    "tcp",
                    i = tag,
                    s = peer_addr.to_string(),
                    d = field::Empty,
                    r = field::Empty,
                    o = field::Empty
                );
                async move {
                    if let Err(e) = router
                        .dispatch_stream(Box::new(stream), &target, tag.as_ref())
                        .await
                    {
                        error!("Routing stream error: {:?}", e);
                    }
                }
                .instrument(span)
                .await;
            }
            Some(TrojanHandler::Udp(stream, target)) => {
                let span = info_span!(
                    "udp",
                    i = tag,
                    s = peer_addr.to_string(),
                    d = field::Empty,
                    r = field::Empty,
                    o = field::Empty
                );
                let client_addr = TargetAddr::Ip(peer_addr);
                let in_packet = Arc::new(TrojanInboundPacket::new(
                    Box::new(stream),
                    client_addr.clone(),
                ));
                async move {
                    if let Err(e) = router
                        .dispatch_packet(
                            in_packet,
                            &target,
                            &client_addr,
                            &tag,
                            None,
                            udp_timeout,
                            None,
                        )
                        .await
                    {
                        error!("Routing udp error: {:?}", e);
                    }
                }
                .instrument(span)
                .await;
            }
            None => {}
        }
    }
    .await;
}

async fn handle_client<S>(
    mut stream: S,
    password_hash: &str,
) -> std::io::Result<Option<TrojanHandler<S>>>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    // 1. Read password (56 bytes hex -> 28 bytes? No, sha224 is 28 bytes, hex is 56 chars)
    // Trojan protocol:
    // +-----------------------+---------+----------------+---------+----------+
    // | hex(SHA224(password)) |  CRLF   | Trojan Request |  CRLF   | Payload  |
    // +-----------------------+---------+----------------+---------+----------+
    // |          56           | X'0D0A' |    Variable    | X'0D0A' | Variable |
    // +-----------------------+---------+----------------+---------+----------+

    let mut buf = [0u8; 58]; // 56 bytes hash + 2 bytes CRLF
    stream.read_exact(&mut buf).await?;

    let hash = &buf[0..56];
    let crlf = &buf[56..58];

    if crlf != b"\r\n" {
        return Err(new_io_other_error(format!(
            "Invalid Trojan request: missing CRLF after password, got {:?}",
            crlf
        )));
    }

    // Avoid allocation: compare bytes directly instead of converting to String
    let received_hash =
        std::str::from_utf8(hash).map_err(|_| new_io_other_error("Invalid UTF-8 in hash"))?;
    if !received_hash.eq_ignore_ascii_case(&password_hash) {
        return Err(new_io_other_error("Invalid Trojan password"));
    }

    // 2. Read Trojan Request
    // +-----+------+----------+----------+
    // | Cmd | Atyp | DST.ADDR | DST.PORT |
    // +-----+------+----------+----------+

    let cmd = stream.read_u8().await?;
    let target_addr = TargetAddr::read_from(&mut stream)
        .await
        .map_err(|e| new_io_other_error(format!("{e}")))?;

    // 3. Read CRLF after Request
    let mut crlf = [0u8; 2];
    stream.read_exact(&mut crlf).await?;
    if &crlf != b"\r\n" {
        return Err(new_io_other_error(
            "Invalid Trojan request: missing CRLF after request",
        ));
    }

    match cmd {
        1 => {
            // CONNECT
            // The remaining stream is the payload.
            Ok(Some(TrojanHandler::Stream(stream, target_addr)))
        }
        3 => {
            // UDP ASSOCIATE
            Ok(Some(TrojanHandler::Udp(stream, target_addr)))
        }
        _ => Err(new_io_other_error(format!("Unsupported CMD: {}", cmd))),
    }
}
