use crate::config::InboundConfig;
use crate::proxy::QuicTlsConfig;
use crate::proxy::anytls_proto::*;
use crate::proxy::outbound::{AnyPacket, PacketInfo};
use crate::proxy::router::{Router, get_router};
use crate::proxy::{SessionCloser, SourceAddr, TargetAddr, inbound};
use crate::utils::new_io_other_error;
use anyhow::{Context as _, Result, bail};
use async_trait::async_trait;
use bytes::Bytes;
use dashmap::DashMap;
use inbound::AnyInbound;
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::BufReader;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{Mutex, mpsc};
use tokio_rustls::{TlsAcceptor, rustls};
use tracing::{Instrument, debug, error, field, info, info_span, warn};

// ─── Inbound Stream / UDP ─────────────────────────────────────────────────────

struct AnytlsInboundStream {
    stream_id: u32,
    /// Channel to send data frames to the session's write loop
    write_tx: mpsc::UnboundedSender<(u32, u8, Bytes)>,
    /// Receiver for incoming data
    data_rx: Mutex<mpsc::UnboundedReceiver<Bytes>>,
}

impl AnytlsInboundStream {
    fn new(
        stream_id: u32,
        write_tx: mpsc::UnboundedSender<(u32, u8, Bytes)>,
        data_rx: mpsc::UnboundedReceiver<Bytes>,
    ) -> Self {
        Self {
            stream_id,
            write_tx,
            data_rx: Mutex::new(data_rx),
        }
    }
}

impl AsyncRead for AnytlsInboundStream {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let this = self.get_mut();
        let mut rx = match this.data_rx.try_lock() {
            Ok(g) => g,
            Err(_) => {
                cx.waker().wake_by_ref();
                return std::task::Poll::Pending;
            }
        };
        match rx.try_recv() {
            Ok(data) => {
                let to_copy = data.len().min(buf.remaining());
                buf.put_slice(&data[..to_copy]);
                std::task::Poll::Ready(Ok(()))
            }
            Err(mpsc::error::TryRecvError::Empty) => {
                cx.waker().wake_by_ref();
                std::task::Poll::Pending
            }
            Err(mpsc::error::TryRecvError::Disconnected) => {
                std::task::Poll::Ready(Ok(())) // EOF
            }
        }
    }
}

impl AsyncWrite for AnytlsInboundStream {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        let data = Bytes::copy_from_slice(buf);
        let len = data.len();
        match this.write_tx.send((this.stream_id, Command::Psh as u8, data)) {
            Ok(_) => std::task::Poll::Ready(Ok(len)),
            Err(_) => std::task::Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "session closed",
            ))),
        }
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let this = self.get_mut();
        let _ = this.write_tx.send((this.stream_id, Command::Fin as u8, Bytes::new()));
        std::task::Poll::Ready(Ok(()))
    }
}

struct AnytlsInboundUdp {
    stream_id: u32,
    write_tx: mpsc::UnboundedSender<(u32, u8, Bytes)>,
    data_rx: Mutex<mpsc::UnboundedReceiver<Bytes>>,
    read_buf: Mutex<Vec<u8>>,
    client_addr: TargetAddr,
}

impl AnytlsInboundUdp {
    fn new(
        stream_id: u32,
        write_tx: mpsc::UnboundedSender<(u32, u8, Bytes)>,
        data_rx: mpsc::UnboundedReceiver<Bytes>,
        client_addr: TargetAddr,
    ) -> Self {
        Self {
            stream_id,
            write_tx,
            data_rx: Mutex::new(data_rx),
            read_buf: Mutex::new(Vec::new()),
            client_addr,
        }
    }

    async fn read_next_msg(&self) -> Result<Bytes> {
        loop {
            {
                let mut buf = self.read_buf.lock().await;
                if !buf.is_empty() {
                    // UoT format: target_addr + payload_len(u16 BE) + payload
                    if let Ok((_, target_len)) = uot_decode_target(&buf) {
                        if buf.len() >= target_len + 2 {
                            let payload_len =
                                u16::from_be_bytes([buf[target_len], buf[target_len + 1]]) as usize;
                            let total_needed = target_len + 2 + payload_len;
                            if buf.len() >= total_needed {
                                let msg = Bytes::copy_from_slice(&buf[..total_needed]);
                                buf.drain(..total_needed);
                                return Ok(msg);
                            }
                        }
                    } else if buf.len() > 256 {
                        bail!("invalid UoT packet header");
                    }
                }
            }
            let mut rx = self.data_rx.lock().await;
            match rx.recv().await {
                Some(data) => {
                    let mut buf = self.read_buf.lock().await;
                    buf.extend_from_slice(&data);
                }
                None => bail!("UDP stream closed"),
            }
        }
    }
}

#[async_trait]
impl AnyPacket for AnytlsInboundUdp {
    async fn send_to(
        &self,
        buf: Bytes,
        _from: &SourceAddr,
        target: &TargetAddr,
    ) -> Result<usize> {
        // UoT v2 format: target_addr + payload_len(u16 BE) + payload
        let target_bytes = uot_encode_target(target);
        let mut packet = Vec::with_capacity(target_bytes.len() + 2 + buf.len());
        packet.extend_from_slice(&target_bytes);
        packet.extend_from_slice(&(buf.len() as u16).to_be_bytes());
        packet.extend_from_slice(&buf);

        let len = packet.len();
        self.write_tx
            .send((self.stream_id, Command::Psh as u8, Bytes::from(packet)))
            .map_err(|_| new_io_other_error("UDP write closed"))?;
        Ok(len)
    }

    async fn recv_from(&self) -> Result<PacketInfo> {
        let data = self.read_next_msg().await?;
        // UoT format: target_addr + payload_len(u16 BE) + payload
        let (target, target_len) = uot_decode_target(&data)?;
        if data.len() < target_len + 2 {
            bail!("UoT packet too short for length");
        }
        let payload_len =
            u16::from_be_bytes([data[target_len], data[target_len + 1]]) as usize;
        if data.len() < target_len + 2 + payload_len {
            bail!("UoT packet too short for payload");
        }
        let payload = Bytes::copy_from_slice(
            &data[target_len + 2..target_len + 2 + payload_len],
        );
        Ok((self.client_addr.clone(), target, payload))
    }

    fn closer(&self) -> Arc<SessionCloser> {
        // Minimal stub; actual session close is managed externally
        Arc::new(SessionCloser::new())
    }
}

// ─── Inbound Session ──────────────────────────────────────────────────────────

/// Per-stream lifecycle state
enum StreamState {
    /// Waiting for first PSH (target address)
    Pending,
    /// UDP-over-TCP: target received, waiting for UoT Request header
    #[allow(dead_code)]
    WaitingUotRequest(TargetAddr),
    /// Active TCP stream, data forwarded via this sender
    Active(mpsc::UnboundedSender<Bytes>),
}

/// Server-side session: one per TLS connection, manages multiplexed streams.
struct InboundSession {
    /// Map stream_id -> stream state
    streams: DashMap<u32, StreamState>,
    /// Write channel to the TLS write loop
    write_tx: mpsc::UnboundedSender<(u32, u8, Bytes)>,
    /// Tag of this inbound
    tag: String,
    /// Client address
    peer_addr: SocketAddr,
    /// Router
    router: Arc<Router>,
    /// UDP timeout
    udp_timeout: Duration,
}

impl InboundSession {
    async fn new(
        tls_stream: tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
        password_hash: &[u8; 32],
        tag: String,
        peer_addr: SocketAddr,
        router: Arc<Router>,
        udp_timeout: Duration,
    ) -> Result<()> {
        let (mut tls_read, mut tls_write) = tokio::io::split(tls_stream);

        // 1. Read authentication header
        let mut auth_buf = [0u8; AUTH_HASH_SIZE];
        tls_read.read_exact(&mut auth_buf).await?;

        if &auth_buf != password_hash {
            // Password mismatch — close connection
            warn!(
                "Anytls inbound auth failed from {}: password mismatch",
                peer_addr
            );
            return Err(new_io_other_error("auth failed: password mismatch").into());
        }

        // Read padding0 length and discard padding0
        let padding0_len = tls_read.read_u16().await?;
        if padding0_len > 0 {
            let mut padding = vec![0u8; padding0_len as usize];
            tls_read.read_exact(&mut padding).await?;
        }

        debug!("Anytls inbound auth success from {}", peer_addr);

        // 2. Read cmdSettings
        let (cmd, _stream_id, settings_data) = read_frame(&mut tls_read).await?;
        if cmd != Command::Settings {
            // Protocol violation: send cmdAlert and close
            let alert = format!("expected cmdSettings, got cmd={:?}", cmd);
            write_frame(&mut tls_write, Command::Alert, 0, alert.as_bytes()).await?;
            return Err(new_io_other_error(alert).into());
        }

        let client_ver = parse_version(&settings_data);
        debug!(
            "Anytls inbound client settings from {}: {:?}",
            peer_addr,
            String::from_utf8_lossy(&settings_data)
        );

        // 3. Start session
        let (write_tx, write_rx) = mpsc::unbounded_channel();
        let session = Arc::new(Self {
            streams: DashMap::new(),
            write_tx,
            tag,
            peer_addr,
            router,
            udp_timeout,
        });

        // Send cmdServerSettings if client version >= 2
        if client_ver >= 2 {
            let settings = format!("v={}\n", PROTOCOL_VERSION);
            write_frame(&mut tls_write, Command::ServerSettings, 0, settings.as_bytes()).await?;
        }

        // Spawn write loop
        let session_w = session.clone();
        tokio::spawn(async move {
            if let Err(e) = session_w.write_loop(tls_write, write_rx).await {
                debug!("Anytls inbound session write loop ended: {:?}", e);
            }
        });

        // Run read loop (blocking)
        session.read_loop(tls_read).await?;
        Ok(())
    }

    async fn read_loop(&self, mut tls: impl AsyncRead + Unpin + Send) -> Result<()> {
        loop {
            let (cmd, stream_id, data) = match read_frame(&mut tls).await {
                Ok(f) => f,
                Err(_) => return Ok(()), // client disconnected
            };

            match cmd {
                Command::Syn => {
                    // Go protocol: SYN has no data. Create pending entry, send SYNACK.
                    self.streams.insert(stream_id, StreamState::Pending);
                    let _ = self
                        .write_tx
                        .send((stream_id, Command::SynAck as u8, Bytes::new()));
                }
                Command::Psh => {
                    // Check stream state
                    let state_type = self.streams.get(&stream_id).and_then(|e| {
                        match *e.value() {
                            StreamState::Pending => Some("pending"),
                            StreamState::WaitingUotRequest(_) => Some("waiting_uot"),
                            _ => None,
                        }
                    });
                    if state_type == Some("pending") {
                        let target = match parse_target_from_syn(&data) {
                            Ok(t) => t,
                            Err(e) => {
                                warn!("Anytls inbound bad target from {}: {:?}", self.peer_addr, e);
                                let _ = self.write_tx.send((stream_id, Command::Fin as u8, Bytes::new()));
                                self.streams.remove(&stream_id);
                                continue;
                            }
                        };
                        // Check if UDP-over-TCP
                        if let TargetAddr::Domain(ref domain, _) = target {
                            if domain == UDP_OVER_TCP_TARGET {
                                // Wait for UoT Request (SYNACK already sent in SYN handler)
                                self.streams.insert(stream_id, StreamState::WaitingUotRequest(target));
                                continue;
                            }
                        }
                        // TCP: handle immediately
                        self.handle_target(stream_id, target).await;
                    } else if state_type == Some("waiting_uot") {
                        self.handle_uot_request(stream_id, data).await;
                    } else if let Some(entry) = self.streams.get(&stream_id) {
                        if let StreamState::Active(tx) = entry.value() {
                            let _ = tx.send(data);
                        }
                    }
                }
                Command::Fin => {
                    self.streams.remove(&stream_id);
                }
                Command::Waste => {}
                Command::HeartRequest => {
                    let _ = self
                        .write_tx
                        .send((0, Command::HeartResponse as u8, Bytes::new()));
                }
                Command::Alert => {
                    warn!(
                        "Anytls inbound alert from {}: {}",
                        self.peer_addr,
                        String::from_utf8_lossy(&data)
                    );
                    return Ok(());
                }
                _ => {
                    debug!(
                        "Anytls inbound unknown cmd {:?} from {}",
                        cmd, self.peer_addr
                    );
                }
            }
        }
    }

    async fn write_loop(
        &self,
        mut tls: impl AsyncWrite + Unpin + Send,
        mut rx: mpsc::UnboundedReceiver<(u32, u8, Bytes)>,
    ) -> Result<()> {
        while let Some((stream_id, cmd, data)) = rx.recv().await {
            write_frame(&mut tls, Command::from(cmd), stream_id, &data).await?;
        }
        Ok(())
    }

    /// Handle TCP target: create stream and dispatch to router.
    async fn handle_target(&self, stream_id: u32, target: TargetAddr) {
        let (data_tx, data_rx) = mpsc::unbounded_channel();
        let write_tx = self.write_tx.clone();

        let stream = Box::new(AnytlsInboundStream::new(
            stream_id,
            write_tx,
            data_rx,
        )) as crate::proxy::outbound::AnyStream;

        self.streams
            .insert(stream_id, StreamState::Active(data_tx));

        let router = self.router.clone();
        let tag = self.tag.clone();
        let span = info_span!(
            "tcp",
            i = tag,
            s = self.peer_addr.to_string(),
            d = field::Empty,
            r = field::Empty,
            o = field::Empty
        );
        tokio::spawn(
            async move {
                if let Err(e) = router
                    .dispatch_stream(stream, &target, &tag)
                    .await
                {
                    error!("Anytls inbound TCP routing error: {:?}", e);
                }
            }
            .instrument(span),
        );
    }

    /// Handle UoT Request: parse destination, create UDP socket and dispatch.
    async fn handle_uot_request(&self, stream_id: u32, data: Bytes) {
        // Parse UoT Request: isConnect(u8) + destination(AddrParser)
        if data.is_empty() {
            warn!("Anytls inbound empty UoT request from {}", self.peer_addr);
            let _ = self.write_tx.send((stream_id, Command::Fin as u8, Bytes::new()));
            self.streams.remove(&stream_id);
            return;
        }
        let is_connect = data[0] != 0;
        let (_udp_target, addr_len) = match uot_decode_target(&data[1..]) {
            Ok(t) => t,
            Err(e) => {
                warn!("Anytls inbound bad UoT request from {}: {:?}", self.peer_addr, e);
                let _ = self.write_tx.send((stream_id, Command::Fin as u8, Bytes::new()));
                self.streams.remove(&stream_id);
                return;
            }
        };
        let _ = is_connect;

        // The remaining bytes after the UoT Request header are part of the first packet
        let remaining = if data.len() > 1 + addr_len {
            Bytes::copy_from_slice(&data[1 + addr_len..])
        } else {
            Bytes::new()
        };

        let (data_tx, data_rx) = mpsc::unbounded_channel();
        if !remaining.is_empty() {
            let _ = data_tx.send(remaining);
        }

        let client_addr = TargetAddr::Ip(self.peer_addr);
        let write_tx = self.write_tx.clone();
        let udp = Arc::new(AnytlsInboundUdp::new(
            stream_id,
            write_tx.clone(),
            data_rx,
            client_addr.clone(),
        ));

        // Retrieve the proxy target from WaitingUotRequest state
        let udp_proxy_target = match self.streams.get(&stream_id) {
            Some(entry) => match entry.value() {
                StreamState::WaitingUotRequest(t) => t.clone(),
                _ => {
                    warn!("Anytls inbound unexpected state for UoT stream {}", stream_id);
                    return;
                }
            },
            None => return,
        };

        self.streams
            .insert(stream_id, StreamState::Active(data_tx));

        let router = self.router.clone();
        let tag = self.tag.clone();
        let udp_timeout = self.udp_timeout;
        let span = info_span!(
            "udp",
            i = tag,
            s = self.peer_addr.to_string(),
            d = field::Empty,
            r = field::Empty,
            o = field::Empty
        );
        tokio::spawn(
            async move {
                if let Err(e) = router
                    .dispatch_packet(
                        udp,
                        &udp_proxy_target,
                        &client_addr,
                        &tag,
                        None,
                        udp_timeout,
                        None,
                    )
                    .await
                {
                    error!("Anytls inbound UDP routing error: {:?}", e);
                }
            }
            .instrument(span),
        );
    }
}

// ─── Frame I/O ────────────────────────────────────────────────────────────────

async fn read_frame<S: AsyncRead + Unpin>(stream: &mut S) -> Result<(Command, u32, Bytes)> {
    let cmd = stream.read_u8().await?;
    let stream_id = stream.read_u32().await?;
    let data_len = stream.read_u16().await?;
    let mut data = vec![0u8; data_len as usize];
    if data_len > 0 {
        stream.read_exact(&mut data).await?;
    }
    Ok((Command::from(cmd), stream_id, Bytes::from(data)))
}

async fn write_frame<S: AsyncWrite + Unpin>(stream: &mut S, cmd: Command, stream_id: u32, data: &[u8]) -> Result<()> {
    let mut header = [0u8; FRAME_HEADER_SIZE];
    header[0] = u8::from(cmd);
    header[1..5].copy_from_slice(&stream_id.to_be_bytes());
    header[5..7].copy_from_slice(&(data.len() as u16).to_be_bytes());
    stream.write_all(&header).await?;
    if !data.is_empty() {
        stream.write_all(data).await?;
    }
    stream.flush().await?;
    Ok(())
}

fn parse_version(data: &[u8]) -> u8 {
    let text = String::from_utf8_lossy(data);
    for line in text.lines() {
        if let Some((key, value)) = line.split_once('=') {
            if key.trim() == "v" {
                return value.trim().parse().unwrap_or(1);
            }
        }
    }
    1
}

fn parse_target_from_syn(data: &[u8]) -> Result<TargetAddr> {
    // SYN data is RFC1928 address format: ATYP(1) + Addr(var) + Port(2)
    if data.is_empty() {
        bail!("empty SYN data");
    }
    let atyp = data[0];
    match atyp {
        1 => {
            // IPv4
            if data.len() < 7 {
                bail!("SYN IPv4 data too short");
            }
            let ip = std::net::Ipv4Addr::new(data[1], data[2], data[3], data[4]);
            let port = u16::from_be_bytes([data[5], data[6]]);
            Ok(TargetAddr::Ip(std::net::SocketAddr::new(
                std::net::IpAddr::V4(ip),
                port,
            )))
        }
        3 => {
            // Domain
            let domain_len = data[1] as usize;
            if data.len() < 2 + domain_len + 2 {
                bail!("SYN domain data too short");
            }
            let domain = String::from_utf8(data[2..2 + domain_len].to_vec())
                .map_err(|e| new_io_other_error(format!("invalid domain: {}", e)))?;
            let port = u16::from_be_bytes([data[2 + domain_len], data[3 + domain_len]]);
            Ok(TargetAddr::Domain(domain, port))
        }
        4 => {
            // IPv6
            if data.len() < 19 {
                bail!("SYN IPv6 data too short");
            }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&data[1..17]);
            let ip = std::net::Ipv6Addr::from(octets);
            let port = u16::from_be_bytes([data[17], data[18]]);
            Ok(TargetAddr::Ip(std::net::SocketAddr::new(
                std::net::IpAddr::V6(ip),
                port,
            )))
        }
        _ => bail!("unsupported ATYP in SYN: {}", atyp),
    }
}

// ─── AnytlsInbound ────────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct AnytlsInbound {
    tag: String,
    address: SocketAddr,
    idle_timeout: Duration,
    password_hash: [u8; 32],
    tls: QuicTlsConfig,
}

impl AnytlsInbound {
    pub fn new(tag: String, cfg: &InboundConfig) -> Result<Self> {
        let password = cfg.password.clone().context("anytls inbound requires password")?;
        let mut hasher = Sha256::new();
        hasher.update(password.as_bytes());
        let password_hash: [u8; 32] = hasher.finalize().into();

        let tls = QuicTlsConfig::from_inbound(cfg)?;

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
            idle_timeout: Duration::from_secs(cfg.idle_timeout.unwrap_or(60)),
            tls,
        })
    }

    async fn listen_tcp(&self) -> Result<()> {
        let listener = super::create_tcp_listener(self.address).await?;

        let _ = rustls::crypto::ring::default_provider().install_default();

        let server_config = if let (Some(cert_path), Some(key_path)) = (&self.tls.cert, &self.tls.key) {
            let certs = load_certs(cert_path)?;
            let key = load_keys(key_path)?;
            rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(certs, key)
                .map_err(|e| new_io_other_error(format!("TLS config error: {}", e)))?
        } else {
            info!("Anytls inbound: no TLS cert configured, generating self-signed certificate");
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

        info!("Anytls inbound listening on {}", self.address);

        loop {
            let (socket, peer_addr) = match listener.accept().await {
                Ok(conn) => conn,
                Err(e) => {
                    error!("Anytls inbound accept error: {}", e);
                    continue;
                }
            };

            let router = get_router();
            let password_hash = self.password_hash;
            let tag = self.tag.clone();
            let udp_timeout = self.idle_timeout;
            let acceptor = tls_acceptor.clone();

            info!("Anytls inbound accept from {}", peer_addr);
            tokio::spawn(async move {
                let tls_stream = match tokio::time::timeout(
                    Duration::from_secs(30),
                    acceptor.accept(socket),
                )
                .await
                {
                    Ok(Ok(s)) => s,
                    Ok(Err(e)) => {
                        error!("Anytls inbound TLS error from {}: {}", peer_addr, e);
                        return;
                    }
                    Err(_) => {
                        error!("Anytls inbound TLS timeout from {}", peer_addr);
                        return;
                    }
                };

                if let Err(e) = InboundSession::new(
                    tls_stream,
                    &password_hash,
                    tag,
                    peer_addr,
                    router,
                    udp_timeout,
                )
                .await
                {
                    debug!("Anytls inbound session ended for {}: {:?}", peer_addr, e);
                }
            });
        }
    }
}

#[async_trait]
impl AnyInbound for AnytlsInbound {
    fn protocol(&self) -> &str {
        "anytls"
    }

    fn idle_timeout(&self) -> Duration {
        self.idle_timeout
    }

    async fn listen(&self) -> Result<()> {
        self.listen_tcp().await
    }
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

fn load_certs(path: &str) -> std::io::Result<Vec<rustls::pki_types::CertificateDer<'static>>> {
    let file = File::open(path)?;
    let mut reader = BufReader::new(file);
    rustls_pemfile::certs(&mut reader)
        .map(|r| r.map(|c| c.into_owned()))
        .collect()
}

fn load_keys(path: &str) -> std::io::Result<rustls::pki_types::PrivateKeyDer<'static>> {
    let file = File::open(path)?;
    let mut reader = BufReader::new(file);
    let key = rustls_pemfile::private_key(&mut reader)?;
    key.ok_or_else(|| new_io_other_error("No private key found"))
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn test_parse_target_ipv4() {
        // IPv4: ATYP=1, IP(4), Port(2)
        let data = [1u8, 192, 168, 1, 1, 0x1f, 0x90]; // 192.168.1.1:8080
        let result = parse_target_from_syn(&data).expect("parse IPv4 SYN");
        assert_eq!(
            result,
            TargetAddr::Ip(std::net::SocketAddr::new(
                std::net::IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
                8080
            ))
        );
    }

    #[test]
    fn test_parse_target_domain() {
        // Domain: ATYP=3, len=9(0x09), "localhost", Port(2)
        let domain = b"localhost";
        let mut data = vec![3u8, domain.len() as u8];
        data.extend_from_slice(domain);
        data.extend_from_slice(&443u16.to_be_bytes()); // port 443
        let result = parse_target_from_syn(&data).expect("parse domain SYN");
        assert_eq!(
            result,
            TargetAddr::Domain("localhost".to_string(), 443)
        );
    }

    #[test]
    fn test_parse_target_domain_long() {
        // Test with a longer domain name
        let domain = b"a.test.domain.example.com";
        let mut data = vec![3u8, domain.len() as u8];
        data.extend_from_slice(domain);
        data.extend_from_slice(&80u16.to_be_bytes());
        let result = parse_target_from_syn(&data).expect("parse long domain SYN");
        assert_eq!(
            result,
            TargetAddr::Domain("a.test.domain.example.com".to_string(), 80)
        );
    }

    #[test]
    fn test_parse_target_ipv6() {
        // IPv6: ATYP=4, IP(16), Port(2)
        let ipv6 = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let mut data = vec![4u8];
        data.extend_from_slice(&ipv6.octets());
        data.extend_from_slice(&9000u16.to_be_bytes());
        let result = parse_target_from_syn(&data).expect("parse IPv6 SYN");
        assert_eq!(
            result,
            TargetAddr::Ip(std::net::SocketAddr::new(
                std::net::IpAddr::V6(ipv6),
                9000
            ))
        );
    }

    #[test]
    fn test_parse_target_empty() {
        let result = parse_target_from_syn(&[]);
        assert!(result.is_err(), "empty data should error");
    }

    #[test]
    fn test_parse_target_ipv4_too_short() {
        let data = [1u8, 192, 168, 1]; // missing last octet + port
        let result = parse_target_from_syn(&data);
        assert!(result.is_err(), "truncated IPv4 should error");
    }

    #[test]
    fn test_parse_target_domain_too_short() {
        // ATYP=3, len=10, but only 5 bytes of domain + 0 bytes of port
        let data = [3u8, 10, b'h', b'e', b'l', b'l', b'o'];
        let result = parse_target_from_syn(&data);
        assert!(result.is_err(), "truncated domain should error");
    }

    #[test]
    fn test_parse_target_ipv6_too_short() {
        let data = [4u8, 0, 0, 0, 0, 0, 0, 0, 0]; // only 8 bytes of IP, missing rest + port
        let result = parse_target_from_syn(&data);
        assert!(result.is_err(), "truncated IPv6 should error");
    }

    #[test]
    fn test_parse_target_unknown_atyp() {
        let data = [99u8, 0, 0, 0, 0, 0, 0]; // unknown ATYP
        let result = parse_target_from_syn(&data);
        assert!(result.is_err(), "unknown ATYP should error");
    }

    #[test]
    fn test_parse_version_from_settings() {
        let v = parse_version(b"v=2\nclient=test\n");
        assert_eq!(v, 2);

        let v_default = parse_version(b"no version here\n");
        assert_eq!(v_default, 1);

        let v_empty = parse_version(b"");
        assert_eq!(v_empty, 1);
    }

    #[test]
    fn test_target_addr_to_bytes_roundtrip() {
        // Test IPv4 roundtrip
        let addr = TargetAddr::Ip(std::net::SocketAddr::new(
            std::net::IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            8080,
        ));
        let bytes = addr.to_bytes();
        let parsed = parse_target_from_syn(&bytes).expect("roundtrip IPv4");
        assert_eq!(parsed, addr);

        // Test domain roundtrip
        let daddr = TargetAddr::Domain("test.example.com".to_string(), 443);
        let dbytes = daddr.to_bytes();
        let dparsed = parse_target_from_syn(&dbytes).expect("roundtrip domain");
        assert_eq!(dparsed, daddr);
    }
}
