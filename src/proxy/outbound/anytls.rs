use std::{
    collections::HashMap,
    fs::File,
    io::BufReader,
    pin::Pin,
    sync::{
        Arc, Mutex as SyncMutex,
        atomic::{AtomicBool, AtomicU8, AtomicU32, AtomicU64, Ordering},
    },
    task::{Context, Poll},
    time::{Duration, Instant},
};

use anyhow::{Context as _, Result, bail};
use async_trait::async_trait;
use bytes::Bytes;
use dashmap::DashMap;
use rand::Rng;
use rustls::pki_types::CertificateDer;
use sha2::{Digest, Sha256};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf},
    sync::Mutex,
};
use tokio_rustls::{TlsConnector, rustls};
use tracing::{debug, info, warn};

use crate::{
    config::OutboundConfig,
    proxy::{
        TlsConfig, SessionCloser, SourceAddr, TargetAddr,
        anytls_proto::*,
        outbound::{AnyOutbound, AnyPacket, AnyStream, PacketInfo, select_outbound_interface},
    },
    utils::{new_io_other_error, new_io_timeout_error},
};

// ─── Protocol Constants ───────────────────────────────────────────────────────

const CLIENT_NAME: &str = AGENT_NAME;

const DEFAULT_PADDING_SCHEME: &str = "\
stop=8\n\
0=30-30\n\
1=100-400\n\
2=400-500,c,500-1000,c,500-1000,c,500-1000,c,500-1000\n\
3=9-9,500-1000\n\
4=500-1000\n\
5=500-1000\n\
6=500-1000\n\
7=500-1000";

// ─── Padding Scheme ───────────────────────────────────────────────────────────

/// CheckMark: if payload remains, skip; if no payload, stop generating sizes.
const CHECK_MARK: i64 = -1;

#[derive(Debug, Clone)]
enum PaddingEntry {
    /// Fixed size (min == max)
    Fixed(usize),
    /// Random size in [min, max]
    Range(usize, usize),
    /// CheckMark
    CheckMark,
}

#[derive(Debug, Clone)]
struct PaddingScheme {
    stop_at: u32,
    /// Map: packet_index → list of padding entries
    policies: HashMap<u32, Vec<PaddingEntry>>,
    /// MD5 hex of the raw scheme bytes
    hash: String,
    /// Raw scheme bytes (for cmdUpdatePaddingScheme)
    #[allow(dead_code)]
    raw: Vec<u8>,
}

impl PaddingScheme {
    fn parse(raw: &[u8]) -> Result<Self> {
        let text = std::str::from_utf8(raw).context("padding scheme is not UTF-8")?;
        let mut stop_at: u32 = 0;
        let mut policies = HashMap::new();

        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            if let Some((key, value)) = line.split_once('=') {
                let key = key.trim();
                let value = value.trim();
                if key == "stop" {
                    stop_at = value.parse().context("invalid stop value")?;
                } else if let Ok(pkt_idx) = key.parse::<u32>() {
                    let entries = Self::parse_entries(value)?;
                    policies.insert(pkt_idx, entries);
                }
            }
        }

        let hash = format!("{:x}", md5::compute(raw));
        Ok(Self {
            stop_at,
            policies,
            hash,
            raw: raw.to_vec(),
        })
    }

    fn parse_entries(s: &str) -> Result<Vec<PaddingEntry>> {
        let mut entries = Vec::new();
        for part in s.split(',') {
            let part = part.trim();
            if part == "c" {
                entries.push(PaddingEntry::CheckMark);
                continue;
            }
            if let Some(dash_pos) = part.find('-') {
                let min: usize = part[..dash_pos]
                    .trim()
                    .parse()
                    .context("invalid padding min")?;
                let max: usize = part[dash_pos + 1..]
                    .trim()
                    .parse()
                    .context("invalid padding max")?;
                let (min, max) = (min.min(max), min.max(max));
                if min <= 0 || max <= 0 {
                    continue;
                }
                if min == max {
                    entries.push(PaddingEntry::Fixed(min));
                } else {
                    entries.push(PaddingEntry::Range(min, max));
                }
            }
        }
        Ok(entries)
    }

    /// Generate target record payload sizes for a given packet number.
    /// Returns a list of target sizes. `CHECK_MARK` (-1) means CheckMark.
    fn generate_record_payload_sizes(&self, pkt: u32) -> Vec<i64> {
        if let Some(entries) = self.policies.get(&pkt) {
            entries
                .iter()
                .map(|e| match e {
                    PaddingEntry::Fixed(v) => *v as i64,
                    PaddingEntry::Range(min, max) => {
                        let mut rng = rand::thread_rng();
                        rng.gen_range(*min..=*max) as i64
                    }
                    PaddingEntry::CheckMark => CHECK_MARK,
                })
                .collect()
        } else {
            Vec::new()
        }
    }

    fn get_default() -> Self {
        Self::parse(DEFAULT_PADDING_SCHEME.as_bytes())
            .expect("default padding scheme must be valid")
    }
}

// ─── Stream Event ─────────────────────────────────────────────────────────────

enum StreamEvent {
    Data(Bytes),
    Fin,
    SynAckError(Vec<u8>),
}

// ─── Session (Hub) ────────────────────────────────────────────────────────────

/// A session is one TLS connection to the anytls server that multiplexes streams.
///
/// It owns:
/// - A `streams` map: stream_id -> sender to push incoming data to the stream
/// - A write channel: streams push outgoing frames here, a write task drains it
struct Session {
    session_seq: u64,
    /// Map from stream_id to event sender for routing incoming frames
    streams: DashMap<u32, tokio::sync::mpsc::UnboundedSender<StreamEvent>>,
    /// Write channel: (stream_id, cmd, data)
    write_tx: tokio::sync::mpsc::UnboundedSender<(u32, u8, Bytes)>,
    next_stream_id: AtomicU32,
    server_version: AtomicU8,
    is_dead: AtomicBool,
    packet_count: AtomicU64,
    send_padding: AtomicBool,
    padding_scheme: Mutex<PaddingScheme>,
    closer: Arc<SessionCloser>,
}

impl Session {
    async fn new(
        tcp_stream: tokio::net::TcpStream,
        tls_cfg: Arc<rustls::ClientConfig>,
        server_name: rustls::pki_types::ServerName<'static>,
        password_hash: &[u8; 32],
        tls_connect_timeout: Duration,
        session_seq: u64,
        padding_scheme: PaddingScheme,
    ) -> Result<Arc<Self>> {
        // TLS handshake
        let connector = TlsConnector::from(tls_cfg);
        let tls_stream = tokio::time::timeout(
            tls_connect_timeout,
            connector.connect(server_name, tcp_stream),
        )
        .await
        .context("Anytls TLS handshake timeout")?
        .context("Anytls TLS handshake failed")?;

        let (write_tx, write_rx) = tokio::sync::mpsc::unbounded_channel();

        let session = Arc::new(Self {
            session_seq,
            streams: DashMap::new(),
            write_tx,
            next_stream_id: AtomicU32::new(1),
            server_version: AtomicU8::new(1),
            is_dead: AtomicBool::new(false),
            packet_count: AtomicU64::new(1), // pkt=0 used for auth
            send_padding: AtomicBool::new(true),
            padding_scheme: Mutex::new(padding_scheme),
            closer: Arc::new(SessionCloser::new()),
        });

        // Authenticate (pkt=0)
        let scheme = session.padding_scheme.lock().await.clone();
        let (tls_read, mut tls_write) = tokio::io::split(tls_stream);
        Self::authenticate(&mut tls_write, password_hash, &scheme).await?;

        // Queue cmdSettings through write channel (will be buffered in write_loop)
        let settings_data = format!(
            "v={}\nclient={}\npadding-md5={}\n",
            PROTOCOL_VERSION, CLIENT_NAME, scheme.hash
        );
        session
            .write_tx
            .send((0, Command::Settings as u8, Bytes::from(settings_data)))
            .map_err(|_| new_io_other_error("failed to queue settings"))?;

        // Spawn write loop (starts in buffering mode)
        let session_w = session.clone();
        tokio::spawn(async move {
            if let Err(e) = session_w.write_loop(tls_write, write_rx).await {
                debug!("Anytls session {} write loop ended: {:?}", session_seq, e);
            }
            session_w.is_dead.store(true, Ordering::Release);
            session_w.closer.close();
        });

        // Spawn read loop
        let session_r = session.clone();
        tokio::spawn(async move {
            if let Err(e) = session_r.read_loop(tls_read).await {
                debug!("Anytls session {} read loop ended: {:?}", session_seq, e);
            }
            session_r.is_dead.store(true, Ordering::Release);
            session_r.closer.close();
        });

        Ok(session)
    }

    async fn authenticate<S: AsyncWrite + Unpin>(
        tls: &mut S,
        password_hash: &[u8; 32],
        scheme: &PaddingScheme,
    ) -> Result<()> {
        // Auth padding uses pkt=0's first entry
        let padding0_size: usize = scheme
            .generate_record_payload_sizes(0)
            .first()
            .copied()
            .unwrap_or(30) as usize;

        let mut auth_packet =
            Vec::with_capacity(AUTH_HASH_SIZE + AUTH_LENGTH_FIELD_SIZE + padding0_size);
        auth_packet.extend_from_slice(password_hash);
        auth_packet.extend_from_slice(&(padding0_size as u16).to_be_bytes());
        auth_packet.resize(auth_packet.len() + padding0_size, 0);

        tls.write_all(&auth_packet).await?;
        tls.flush().await?;
        Ok(())
    }

    // ── Frame I/O ─────────────────────────────────────────────────────────

    async fn read_frame<S: AsyncRead + Unpin>(stream: &mut S) -> Result<(Command, u32, Bytes)> {
        let cmd = stream.read_u8().await.context("read frame cmd")?;
        let stream_id = stream.read_u32().await.context("read frame stream_id")?;
        let data_len = stream.read_u16().await.context("read frame data_len")?;
        let mut data = vec![0u8; data_len as usize];
        if data_len > 0 {
            stream
                .read_exact(&mut data)
                .await
                .context("read frame data")?;
        }
        Ok((Command::from(cmd), stream_id, Bytes::from(data)))
    }

    // ── Loops ─────────────────────────────────────────────────────────────

    async fn read_loop(&self, mut tls: impl AsyncRead + Unpin + Send) -> Result<()> {
        loop {
            let (cmd, stream_id, data) = match Self::read_frame(&mut tls).await {
                Ok(frame) => frame,
                Err(e) => return Err(e),
            };

            match cmd {
                Command::Waste => {}
                Command::Psh => {
                    if let Some(tx) = self.streams.get(&stream_id) {
                        let _ = tx.send(StreamEvent::Data(data));
                    }
                }
                Command::Fin => {
                    if let Some(tx) = self.streams.get(&stream_id) {
                        let _ = tx.send(StreamEvent::Fin);
                    }
                }
                Command::SynAck => {
                    if !data.is_empty() {
                        if let Some(tx) = self.streams.get(&stream_id) {
                            let _ = tx.send(StreamEvent::SynAckError(data.to_vec()));
                        }
                    }
                }
                Command::Alert => {
                    let msg = String::from_utf8_lossy(&data);
                    warn!(
                        "Anytls session {} received alert: {}",
                        self.session_seq, msg
                    );
                    // Notify all streams
                    for entry in self.streams.iter() {
                        let _ = entry.value().send(StreamEvent::SynAckError(
                            format!("server alert: {}", msg).into_bytes(),
                        ));
                    }
                    return Err(new_io_other_error(format!("server alert: {}", msg)).into());
                }
                Command::UpdatePaddingScheme => match PaddingScheme::parse(&data) {
                    Ok(new_scheme) => {
                        debug!("Anytls session {} updated padding scheme", self.session_seq);
                        *self.padding_scheme.lock().await = new_scheme;
                    }
                    Err(e) => {
                        warn!(
                            "Anytls session {} invalid padding scheme: {:?}",
                            self.session_seq, e
                        );
                    }
                },
                Command::HeartRequest => {
                    // Send heart response via write channel
                    let _ = self
                        .write_tx
                        .send((0, Command::HeartResponse as u8, Bytes::new()));
                }
                Command::HeartResponse => {}
                Command::ServerSettings => {
                    let text = String::from_utf8_lossy(&data);
                    if let Some(ver) = Self::parse_server_version(&text) {
                        self.server_version.store(ver, Ordering::Release);
                        debug!(
                            "Anytls session {} server version: {}",
                            self.session_seq, ver
                        );
                    }
                }
                _ => {
                    debug!("Anytls session {} unknown cmd: {:?}", self.session_seq, cmd);
                }
            }
            self.packet_count.fetch_add(1, Ordering::Relaxed);
        }
    }

    async fn write_loop(
        &self,
        mut tls: impl AsyncWrite + Unpin + Send,
        mut write_rx: tokio::sync::mpsc::UnboundedReceiver<(u32, u8, Bytes)>,
    ) -> Result<()> {
        // Buffering: accumulate frames until the first PSH (target address)
        // is received, then flush all buffered data with padding.
        let mut buffering = true;
        let mut buffer: Vec<u8> = Vec::new();

        while let Some((stream_id, cmd, data)) = write_rx.recv().await {
            let frame_bytes = Self::build_frame_bytes(Command::from(cmd), stream_id, &data);

            if buffering {
                buffer.extend_from_slice(&frame_bytes);
                // First PSH = target address → stop buffering and flush
                if Command::from(cmd) == Command::Psh {
                    buffering = false;
                    let combined = std::mem::take(&mut buffer);
                    if let Err(e) = self.write_with_padding(&mut tls, &combined).await {
                        debug!("Anytls write_with_padding error: {:?}", e);
                        break;
                    }
                }
            } else {
                if let Err(e) = self.write_with_padding(&mut tls, &frame_bytes).await {
                    debug!("Anytls write_with_padding error: {:?}", e);
                    break;
                }
            }
        }
        Ok(())
    }

    /// Build frame bytes without sending them.
    fn build_frame_bytes(cmd: Command, stream_id: u32, data: &[u8]) -> Vec<u8> {
        let mut buf = Vec::with_capacity(FRAME_HEADER_SIZE + data.len());
        buf.push(u8::from(cmd));
        buf.extend_from_slice(&stream_id.to_be_bytes());
        buf.extend_from_slice(&(data.len() as u16).to_be_bytes());
        buf.extend_from_slice(data);
        buf
    }

    /// Write data with padding according to the current scheme.
    /// Matches Go's `writeConn` logic: split payload into target-sized records,
    /// insert WASTE frames for padding.
    async fn write_with_padding(
        &self,
        tls: &mut (impl AsyncWrite + Unpin),
        data: &[u8],
    ) -> Result<()> {
        if !self.send_padding.load(Ordering::Acquire) {
            tls.write_all(data).await?;
            tls.flush().await?;
            return Ok(());
        }

        let pkt = self.packet_count.fetch_add(1, Ordering::Relaxed);
        let scheme = self.padding_scheme.lock().await;

        if pkt >= scheme.stop_at as u64 {
            self.send_padding.store(false, Ordering::Release);
            drop(scheme);
            tls.write_all(data).await?;
            tls.flush().await?;
            return Ok(());
        }

        let sizes = scheme.generate_record_payload_sizes(pkt as u32);
        drop(scheme);

        let mut remaining = data;

        for target_size in &sizes {
            if *target_size == CHECK_MARK {
                if remaining.is_empty() {
                    break; // no payload left, stop
                } else {
                    continue; // payload remains, skip this mark
                }
            }

            let target_size = *target_size as usize;
            let remain_len = remaining.len();

            if remain_len > target_size {
                // This record is all payload
                tls.write_all(&remaining[..target_size]).await?;
                remaining = &remaining[target_size..];
            } else if remain_len > 0 {
                // This record contains payload + padding
                let padding_len = target_size.saturating_sub(remain_len + FRAME_HEADER_SIZE);
                if padding_len > 0 {
                    // Build WASTE frame header + padding data
                    let mut waste = vec![0u8; FRAME_HEADER_SIZE + padding_len];
                    waste[0] = u8::from(Command::Waste);
                    waste[1..5].copy_from_slice(&0u32.to_be_bytes());
                    waste[5..7].copy_from_slice(&(padding_len as u16).to_be_bytes());
                    tls.write_all(remaining).await?;
                    tls.write_all(&waste).await?;
                } else {
                    tls.write_all(remaining).await?;
                }
                remaining = &[];
            } else {
                // This record is all padding (WASTE frame)
                let mut waste = vec![0u8; FRAME_HEADER_SIZE + target_size];
                waste[0] = u8::from(Command::Waste);
                waste[1..5].copy_from_slice(&0u32.to_be_bytes());
                waste[5..7].copy_from_slice(&(target_size as u16).to_be_bytes());
                tls.write_all(&waste).await?;
                remaining = &[];
            }
        }

        // Write any remaining payload beyond the scheme's entries
        if !remaining.is_empty() {
            tls.write_all(remaining).await?;
        }

        tls.flush().await?;
        Ok(())
    }

    fn parse_server_version(settings: &str) -> Option<u8> {
        for line in settings.lines() {
            if let Some((key, value)) = line.split_once('=') {
                if key.trim() == "v" {
                    return value.trim().parse().ok();
                }
            }
        }
        None
    }

    fn is_dead(&self) -> bool {
        self.is_dead.load(Ordering::Acquire)
    }

    #[allow(dead_code)]
    fn server_version(&self) -> u8 {
        self.server_version.load(Ordering::Acquire)
    }

    fn next_stream_id(&self) -> u32 {
        self.next_stream_id.fetch_add(1, Ordering::Relaxed)
    }

    /// Register a new stream and get its event receiver
    fn register_stream(&self, stream_id: u32) -> tokio::sync::mpsc::UnboundedReceiver<StreamEvent> {
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        self.streams.insert(stream_id, tx);
        rx
    }

    /// Unregister a stream (called when stream is dropped)
    fn unregister_stream(&self, stream_id: u32) {
        self.streams.remove(&stream_id);
    }
}

// ─── AnytlsClient (Session Manager) ──────────────────────────────────────────

struct IdleSession {
    session: Arc<Session>,
    idle_since: Instant,
}

pub struct AnytlsClient {
    address: TargetAddr,
    password_hash: [u8; 32],
    tls_client_config: Arc<rustls::ClientConfig>,
    tls_server_name: rustls::pki_types::ServerName<'static>,
    connect_timeout: Duration,
    bind_interface: Option<String>,
    dns_server_name: Option<String>,
    disable_mux: bool,

    active_sessions: Mutex<Vec<Arc<Session>>>,
    idle_sessions: Arc<Mutex<Vec<IdleSession>>>,
    session_seq: AtomicU64,
    padding_scheme: Mutex<PaddingScheme>,

    #[allow(dead_code)]
    idle_session_check_interval: Duration,
    #[allow(dead_code)]
    idle_session_timeout: Duration,
    #[allow(dead_code)]
    min_idle_session: usize,
}

impl AnytlsClient {
    pub fn new(
        address: TargetAddr,
        password: &str,
        tls: &TlsConfig,
        connect_timeout: Duration,
        bind_interface: Option<String>,
        dns_server_name: Option<String>,
        disable_mux: bool,
    ) -> Result<Self> {
        let mut hasher = Sha256::new();
        hasher.update(password.as_bytes());
        let password_hash: [u8; 32] = hasher.finalize().into();

        let tls_client_config = Self::build_tls_client_config(tls)?;

        let host = address.host();
        let sni = tls.sni.as_deref().unwrap_or(&host);
        let tls_server_name = rustls::pki_types::ServerName::try_from(sni)
            .map_err(|e| new_io_other_error(e))?
            .to_owned();

        let idle_sessions = Arc::new(Mutex::new(Vec::new()));

        // Spawn cleanup task
        let idle_sessions_c = idle_sessions.clone();
        let check_interval = Duration::from_secs(30);
        let session_timeout = Duration::from_secs(60);
        let min_idle = 1usize;
        tokio::spawn(async move {
            Self::cleanup_loop(idle_sessions_c, check_interval, session_timeout, min_idle).await;
        });

        Ok(Self {
            address,
            password_hash,
            tls_client_config: Arc::new(tls_client_config),
            tls_server_name,
            connect_timeout,
            bind_interface,
            dns_server_name,
            disable_mux,
            active_sessions: Mutex::new(Vec::new()),
            idle_sessions,
            session_seq: AtomicU64::new(0),
            padding_scheme: Mutex::new(PaddingScheme::get_default()),
            idle_session_check_interval: check_interval,
            idle_session_timeout: session_timeout,
            min_idle_session: min_idle,
        })
    }

    fn build_tls_client_config(tls: &TlsConfig) -> Result<rustls::ClientConfig> {
        let _ = rustls::crypto::ring::default_provider().install_default();

        if !tls.insecure {
            let mut root_store = rustls::RootCertStore::empty();
            if let Some(cert_path) = tls.cert.as_deref() {
                for cert in load_certs(cert_path)? {
                    root_store.add(cert).map_err(|e| new_io_other_error(e))?;
                }
            } else {
                root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            }
            let mut config = rustls::ClientConfig::builder()
                .with_root_certificates(root_store)
                .with_no_client_auth();
            crate::proxy::configure_jls_client(&mut config, tls);
            Ok(config)
        } else {
            let mut config = rustls::ClientConfig::builder()
                .with_root_certificates(rustls::RootCertStore::empty())
                .with_no_client_auth();
            config
                .dangerous()
                .set_certificate_verifier(Arc::new(SkipServerVerification));
            crate::proxy::configure_jls_client(&mut config, tls);
            Ok(config)
        }
    }

    async fn get_session(&self) -> Result<Arc<Session>> {
        // 禁用多路复用时，每个连接都创建独立 Session
        if self.disable_mux {
            return self.create_session().await;
        }

        // Try to get an idle session (prefer highest seq)
        {
            let mut idle = self.idle_sessions.lock().await;
            if !idle.is_empty() {
                idle.sort_by(|a, b| b.session.session_seq.cmp(&a.session.session_seq));
                let idle_session = idle.remove(0);
                let session = idle_session.session;
                if !session.is_dead() {
                    self.active_sessions.lock().await.push(session.clone());
                    debug!("Anytls reusing idle session seq={}", session.session_seq);
                    return Ok(session);
                }
            }
        }

        self.create_session().await
    }

    async fn create_session(&self) -> Result<Arc<Session>> {
        let seq = self.session_seq.fetch_add(1, Ordering::Relaxed);

        let socket_addr =
            crate::dns::resolve_target(&self.address, self.dns_server_name.as_deref()).await?;

        let used_interface =
            select_outbound_interface(self.bind_interface.as_deref(), Some(socket_addr));

        let tcp_stream = tokio::time::timeout(
            self.connect_timeout,
            crate::utils::socket::socket_helpers::new_tcp_stream(socket_addr, used_interface, None),
        )
        .await
        .map_err(|_| new_io_timeout_error("connect timeout"))?
        .context("TCP connect failed")?;

        let padding_scheme = self.padding_scheme.lock().await.clone();
        let session = Session::new(
            tcp_stream,
            self.tls_client_config.clone(),
            self.tls_server_name.clone(),
            &self.password_hash,
            self.connect_timeout,
            seq,
            padding_scheme,
        )
        .await?;

        self.active_sessions.lock().await.push(session.clone());
        info!("Anytls created new session seq={}", seq);
        Ok(session)
    }

    #[allow(dead_code)]
    async fn mark_idle(&self, session: Arc<Session>) {
        {
            let mut active = self.active_sessions.lock().await;
            active.retain(|s| s.session_seq != session.session_seq);
        }
        // 禁用多路复用时，不将 session 放入空闲池，直接让其消亡
        if self.disable_mux || session.is_dead() {
            return;
        }
        self.idle_sessions.lock().await.push(IdleSession {
            session,
            idle_since: Instant::now(),
        });
    }

    async fn cleanup_loop(
        idle_sessions: Arc<Mutex<Vec<IdleSession>>>,
        check_interval: Duration,
        session_timeout: Duration,
        min_idle: usize,
    ) {
        loop {
            tokio::time::sleep(check_interval).await;
            let mut idle = idle_sessions.lock().await;
            let now = Instant::now();
            idle.sort_by(|a, b| a.idle_since.cmp(&b.idle_since));
            let keep_count = min_idle.min(idle.len());
            let remove_count = idle.len().saturating_sub(keep_count);
            let mut removed = 0;
            idle.retain(|s| {
                if removed >= remove_count {
                    return true;
                }
                if now.duration_since(s.idle_since) > session_timeout {
                    debug!(
                        "Anytls cleaning up idle session seq={}, idle for {:?}",
                        s.session.session_seq,
                        now.duration_since(s.idle_since)
                    );
                    s.session.is_dead.store(true, Ordering::Release);
                    s.session.closer.close();
                    removed += 1;
                    false
                } else {
                    true
                }
            });
        }
    }
}

// ─── AnytlsUdpSocket ─────────────────────────────────────────────────────────

pub struct AnytlsUdpSocket {
    stream_id: u32,
    session: Arc<Session>,
    write_tx: tokio::sync::mpsc::UnboundedSender<(u32, u8, Bytes)>,
    event_rx: Mutex<tokio::sync::mpsc::UnboundedReceiver<StreamEvent>>,
    read_buffer: Mutex<Vec<u8>>,
    is_connect: bool,
}

impl AnytlsUdpSocket {
    fn new(
        stream_id: u32,
        session: Arc<Session>,
        event_rx: tokio::sync::mpsc::UnboundedReceiver<StreamEvent>,
        is_connect: bool,
    ) -> Self {
        Self {
            stream_id,
            write_tx: session.write_tx.clone(),
            session,
            event_rx: Mutex::new(event_rx),
            read_buffer: Mutex::new(Vec::new()),
            is_connect,
        }
    }

    async fn read_next_msg(&self) -> Result<Bytes> {
        loop {
            {
                let mut buf = self.read_buffer.lock().await;
                if self.is_connect {
                    // Connect mode: length(u16) + data
                    if buf.len() >= 2 {
                        let payload_len = u16::from_be_bytes([buf[0], buf[1]]) as usize;
                        let total_needed = 2 + payload_len;
                        if buf.len() >= total_needed {
                            let msg = Bytes::copy_from_slice(&buf[..total_needed]);
                            buf.drain(..total_needed);
                            return Ok(msg);
                        }
                    }
                } else {
                    // Non-connect mode: ATYP(uot) + addr + port + length(u16) + data
                    if !buf.is_empty() {
                        if let Ok((_, target_len)) = uot_decode_target(&buf) {
                            if buf.len() >= target_len + 2 {
                                let payload_len =
                                    u16::from_be_bytes([buf[target_len], buf[target_len + 1]])
                                        as usize;
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
            }

            let mut rx = self.event_rx.lock().await;
            match rx.recv().await {
                Some(StreamEvent::Data(data)) => {
                    let mut buf = self.read_buffer.lock().await;
                    buf.extend_from_slice(&data);
                }
                Some(StreamEvent::Fin) => bail!("UDP stream closed by remote"),
                Some(StreamEvent::SynAckError(e)) => {
                    bail!("UDP stream error: {}", String::from_utf8_lossy(&e));
                }
                None => bail!("UDP stream channel closed"),
            }
        }
    }
}

impl Drop for AnytlsUdpSocket {
    fn drop(&mut self) {
        // Send FIN
        let _ = self
            .write_tx
            .send((self.stream_id, Command::Fin as u8, Bytes::new()));
        self.session.unregister_stream(self.stream_id);
    }
}

#[async_trait]
impl AnyPacket for AnytlsUdpSocket {
    async fn send_to(&self, buf: Bytes, _from: &SourceAddr, target: &TargetAddr) -> Result<usize> {
        let packet = if self.is_connect {
            // Connect mode: length(u16) + data
            let mut p = Vec::with_capacity(2 + buf.len());
            p.extend_from_slice(&(buf.len() as u16).to_be_bytes());
            p.extend_from_slice(&buf);
            p
        } else {
            // Non-connect mode: ATYP(uot) + addr + port + length(u16) + data
            let target_bytes = uot_encode_target(target);
            let mut p = Vec::with_capacity(target_bytes.len() + 2 + buf.len());
            p.extend_from_slice(&target_bytes);
            p.extend_from_slice(&(buf.len() as u16).to_be_bytes());
            p.extend_from_slice(&buf);
            p
        };

        self.write_tx
            .send((self.stream_id, Command::Psh as u8, Bytes::from(packet)))
            .map_err(|_| new_io_other_error("UDP write channel closed"))?;
        Ok(buf.len())
    }

    async fn recv_from(&self) -> Result<PacketInfo> {
        let data = self.read_next_msg().await?;
        if self.is_connect {
            // Connect mode: length(u16) + data
            if data.len() < 2 {
                bail!("UoT connect packet too short");
            }
            let payload_len = u16::from_be_bytes([data[0], data[1]]) as usize;
            if data.len() < 2 + payload_len {
                bail!("UoT connect packet too short for payload");
            }
            let payload = Bytes::copy_from_slice(&data[2..2 + payload_len]);
            Ok((TargetAddr::dummy(), TargetAddr::dummy(), payload))
        } else {
            // Non-connect mode: ATYP(uot) + addr + port + length(u16) + data
            let (target, target_len) = uot_decode_target(&data)?;
            if data.len() < target_len + 2 {
                bail!("UoT packet too short for length");
            }
            let payload_len = u16::from_be_bytes([data[target_len], data[target_len + 1]]) as usize;
            if data.len() < target_len + 2 + payload_len {
                bail!("UoT packet too short for payload");
            }
            let payload =
                Bytes::copy_from_slice(&data[target_len + 2..target_len + 2 + payload_len]);
            Ok((TargetAddr::dummy(), target, payload))
        }
    }

    fn closer(&self) -> Arc<SessionCloser> {
        self.session.closer.clone()
    }
}

// ─── AnytlsOutbound ───────────────────────────────────────────────────────────

pub struct AnytlsOutbound {
    tag: String,
    client: AnytlsClient,
    connect_timeout: Duration,
    dns_server_name: Option<String>,
    bind_interface: Option<String>,
}

impl AnytlsOutbound {
    pub fn new(tag: String, cfg: &OutboundConfig) -> Result<Arc<dyn AnyOutbound>> {
        let address = cfg
            .address
            .clone()
            .context(format!("anytls outbound '{}' requires address", tag))?;
        let port = cfg
            .port
            .context(format!("anytls outbound '{}' requires port", tag))?;
        let address = TargetAddr::from_str2(&address, port)?;

        let password = cfg
            .password
            .clone()
            .context(format!("anytls outbound '{}' requires password", tag))?;

        let tls = TlsConfig::from_outbound(cfg)?;
        let connect_timeout = Duration::from_secs(cfg.connect_timeout.unwrap_or(30));

        let client = AnytlsClient::new(
            address,
            &password,
            &tls,
            connect_timeout,
            cfg.bind_interface.clone(),
            cfg.dns.clone(),
            cfg.disable_mux,
        )?;

        Ok(Arc::new(Self {
            tag,
            client,
            connect_timeout,
            dns_server_name: cfg.dns.clone(),
            bind_interface: cfg.bind_interface.clone(),
        }))
    }
}

#[async_trait]
impl AnyOutbound for AnytlsOutbound {
    fn tag(&self) -> &str {
        &self.tag
    }

    fn protocol(&self) -> &str {
        "anytls"
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

    async fn connect_stream_base(&self) -> Result<AnyStream> {
        bail!("anytls uses session-based connections; use connect_stream instead");
    }

    async fn connect_stream_with(
        &self,
        _target: &TargetAddr,
        _stream: AnyStream,
    ) -> Result<AnyStream> {
        bail!("anytls uses session-based connections; use connect_stream instead");
    }

    async fn connect_stream(&self, target: &TargetAddr) -> Result<AnyStream> {
        let session = self.client.get_session().await?;
        let stream_id = session.next_stream_id();

        // Register stream to receive incoming data
        let event_rx = session.register_stream(stream_id);

        // Go protocol: SYN has no data, target address sent as first PSH
        session
            .write_tx
            .send((stream_id, Command::Syn as u8, Bytes::new()))
            .context("session write channel closed")?;

        let target_data = target.to_bytes();
        session
            .write_tx
            .send((stream_id, Command::Psh as u8, Bytes::from(target_data)))
            .context("session write channel closed")?;

        let proxy = AnytlsProxyStream::new(stream_id, session.clone(), event_rx);
        Ok(Box::new(proxy))
    }

    async fn connect_packet(&self, target: &TargetAddr) -> Result<Arc<dyn AnyPacket>> {
        let udp_target = TargetAddr::Domain(UDP_OVER_TCP_TARGET.to_string(), target.port());

        let session = self.client.get_session().await?;
        let stream_id = session.next_stream_id();

        let event_rx = session.register_stream(stream_id);

        // Go protocol: SYN has no data, target sent as first PSH
        session
            .write_tx
            .send((stream_id, Command::Syn as u8, Bytes::new()))
            .context("session write channel closed")?;

        let target_data = udp_target.to_bytes();
        session
            .write_tx
            .send((stream_id, Command::Psh as u8, Bytes::from(target_data)))
            .context("session write channel closed")?;

        // Send UoT Request header (uses Socksaddr format: ATYP 1/3/4)
        let mut uot_request = vec![0x00]; // IsConnect = false
        uot_request.extend_from_slice(&socksaddr_encode_target(target));
        session
            .write_tx
            .send((stream_id, Command::Psh as u8, Bytes::from(uot_request)))
            .context("session write channel closed")?;

        Ok(Arc::new(AnytlsUdpSocket::new(
            stream_id, session, event_rx, false,
        )))
    }

    async fn retry_connect_stream(&self, target: &TargetAddr) -> Result<AnyStream> {
        self.connect_stream(target).await
    }
}

// ─── AnytlsProxyStream: a TCP stream tunneled through anytls session ──────────

struct AnytlsProxyStream {
    stream_id: u32,
    session: Arc<Session>,
    write_tx: tokio::sync::mpsc::UnboundedSender<(u32, u8, Bytes)>,
    event_rx: SyncMutex<tokio::sync::mpsc::UnboundedReceiver<StreamEvent>>,
    read_buffer: SyncMutex<Vec<u8>>,
    fin_received: AtomicBool,
    fin_sent: AtomicBool,
}

impl AnytlsProxyStream {
    fn new(
        stream_id: u32,
        session: Arc<Session>,
        event_rx: tokio::sync::mpsc::UnboundedReceiver<StreamEvent>,
    ) -> Self {
        Self {
            stream_id,
            write_tx: session.write_tx.clone(),
            session,
            event_rx: SyncMutex::new(event_rx),
            read_buffer: SyncMutex::new(Vec::new()),
            fin_received: AtomicBool::new(false),
            fin_sent: AtomicBool::new(false),
        }
    }
}

impl AsyncRead for AnytlsProxyStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();

        // Serve from read buffer first
        {
            let mut rb = this.read_buffer.lock().unwrap();
            if !rb.is_empty() {
                let to_copy = rb.len().min(buf.remaining());
                buf.put_slice(&rb[..to_copy]);
                rb.drain(..to_copy);
                return Poll::Ready(Ok(()));
            }
        }

        if this.fin_received.load(Ordering::Acquire) {
            return Poll::Ready(Ok(()));
        }

        // Poll the event receiver (properly registers waker)
        let mut rx = this.event_rx.lock().unwrap();
        match rx.poll_recv(cx) {
            Poll::Ready(Some(StreamEvent::Data(data))) => {
                drop(rx);
                let to_copy = data.len().min(buf.remaining());
                buf.put_slice(&data[..to_copy]);
                if to_copy < data.len() {
                    let mut rb = this.read_buffer.lock().unwrap();
                    rb.extend_from_slice(&data[to_copy..]);
                }
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Some(StreamEvent::Fin)) => {
                this.fin_received.store(true, Ordering::Release);
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Some(StreamEvent::SynAckError(e))) => {
                Poll::Ready(Err(std::io::Error::new(
                    std::io::ErrorKind::ConnectionRefused,
                    String::from_utf8_lossy(&e).to_string(),
                )))
            }
            Poll::Ready(None) => {
                this.fin_received.store(true, Ordering::Release);
                Poll::Ready(Ok(()))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for AnytlsProxyStream {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        if this.fin_sent.load(Ordering::Acquire) {
            return Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "stream already closed",
            )));
        }
        match this.write_tx.send((
            this.stream_id,
            Command::Psh as u8,
            Bytes::copy_from_slice(buf),
        )) {
            Ok(_) => Poll::Ready(Ok(buf.len())),
            Err(_) => Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "session closed",
            ))),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        if !this.fin_sent.swap(true, Ordering::AcqRel) {
            let _ = this
                .write_tx
                .send((this.stream_id, Command::Fin as u8, Bytes::new()));
        }
        Poll::Ready(Ok(()))
    }
}

impl Drop for AnytlsProxyStream {
    fn drop(&mut self) {
        if !self.fin_sent.load(Ordering::Acquire) {
            let _ = self
                .write_tx
                .send((self.stream_id, Command::Fin as u8, Bytes::new()));
        }
        self.session.unregister_stream(self.stream_id);
    }
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

fn load_certs(path: &str) -> Result<Vec<CertificateDer<'static>>> {
    let file =
        File::open(path).with_context(|| format!("Failed to open certificate file: {}", path))?;
    let mut reader = BufReader::new(file);
    rustls_pemfile::certs(&mut reader)
        .map(|r| {
            r.map(|c| c.into_owned())
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

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proxy::TlsConfig;
    use sha2::{Digest, Sha256};
    use std::net::SocketAddr;
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};
    use tokio::sync::oneshot;
    use tokio_rustls::TlsAcceptor;

    const TEST_PASSWORD: &str = "test_password_123";
    const TEST_TIMEOUT_S: u64 = 15;

    fn password_hash(password: &str) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(password.as_bytes());
        hasher.finalize().into()
    }

    fn generate_tls_config() -> (rustls::ServerConfig, rustls::ClientConfig) {
        let _ = rustls::crypto::ring::default_provider().install_default();

        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
            .expect("generate cert");
        let cert_der = cert.cert.der().to_vec();
        let key_der = cert.signing_key.serialize_der();

        let server_cert = rustls::pki_types::CertificateDer::from(cert_der.clone());
        let server_key =
            rustls::pki_types::PrivateKeyDer::try_from(key_der.clone()).expect("convert key");

        let server_config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![server_cert], server_key)
            .expect("server config");

        let client_cert = rustls::pki_types::CertificateDer::from(cert_der);
        let mut root_store = rustls::RootCertStore::empty();
        root_store.add(client_cert).expect("add root cert");

        let client_config = rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();

        (server_config, client_config)
    }

    /// Read a frame from an async reader: (cmd, stream_id, data)
    async fn read_frame<R: AsyncRead + Unpin>(r: &mut R) -> Result<(Command, u32, Bytes)> {
        let cmd = r.read_u8().await?;
        let stream_id = r.read_u32().await?;
        let data_len = r.read_u16().await?;
        let mut data = vec![0u8; data_len as usize];
        if data_len > 0 {
            r.read_exact(&mut data).await?;
        }
        Ok((Command::from(cmd), stream_id, Bytes::from(data)))
    }

    /// Write a frame: cmd | stream_id(BE u32) | data_len(BE u16) | data
    async fn write_frame<W: AsyncWrite + Unpin>(
        w: &mut W,
        cmd: Command,
        stream_id: u32,
        data: &[u8],
    ) -> Result<()> {
        let mut header = [0u8; FRAME_HEADER_SIZE];
        header[0] = u8::from(cmd);
        header[1..5].copy_from_slice(&stream_id.to_be_bytes());
        header[5..7].copy_from_slice(&(data.len() as u16).to_be_bytes());
        w.write_all(&header).await?;
        if !data.is_empty() {
            w.write_all(data).await?;
        }
        w.flush().await?;
        Ok(())
    }

    /// Run a mock anytls server that:
    /// 1. Accepts TLS connection
    /// 2. Verifies auth (password hash match)
    /// 3. Reads cmdSettings, sends cmdServerSettings
    /// 4. Reads cmdSYN, sends SYNACK, reads first PSH (target) silently
    /// 5. Echoes subsequent cmdPSH data back
    /// 6. Closes on cmdFIN
    async fn mock_anytls_server(
        listener: TcpListener,
        expected_password_hash: [u8; 32],
        acceptor: TlsAcceptor,
        ready_tx: oneshot::Sender<SocketAddr>,
    ) -> Result<()> {
        let addr = listener.local_addr()?;
        let _ = ready_tx.send(addr);

        let (tcp_stream, _peer) = listener.accept().await?;
        let tls_stream = acceptor.accept(tcp_stream).await?;
        let (mut rd, mut wr) = tokio::io::split(tls_stream);

        // 1. Read auth header
        let mut auth_hash = [0u8; AUTH_HASH_SIZE];
        rd.read_exact(&mut auth_hash).await?;
        assert_eq!(
            &auth_hash, &expected_password_hash,
            "password hash mismatch"
        );

        // Read padding length and padding
        let pad_len = rd.read_u16().await? as usize;
        if pad_len > 0 {
            let mut pad = vec![0u8; pad_len];
            rd.read_exact(&mut pad).await?;
        }

        // 2. Read cmdSettings
        let (settings_cmd, _, _settings_data) = read_frame(&mut rd).await?;
        assert_eq!(
            settings_cmd,
            Command::Settings,
            "expected Command::Settings"
        );

        // 3. Send cmdServerSettings (v=2)
        let server_settings = format!("v={}\n", PROTOCOL_VERSION);
        write_frame(
            &mut wr,
            Command::ServerSettings,
            0,
            server_settings.as_bytes(),
        )
        .await?;

        // 4. Read cmdSYN, send SYNACK, consume target PSH
        let (syn_cmd, stream_id, _target) = read_frame(&mut rd).await?;
        assert_eq!(syn_cmd, Command::Syn, "expected Command::Syn");
        write_frame(&mut wr, Command::SynAck, stream_id, b"").await?;

        // Consume first PSH (target address)
        let (psh_cmd, _, _) = read_frame(&mut rd).await?;
        assert!(
            psh_cmd == Command::Psh || psh_cmd == Command::Fin,
            "expected PSH or FIN, got {:?}",
            psh_cmd
        );

        // 5. Echo loop: echo subsequent PSH data back, break on FIN
        loop {
            let (cmd, sid, data) = read_frame(&mut rd).await?;
            match cmd {
                Command::Psh => {
                    write_frame(&mut wr, Command::Psh, sid, &data).await?;
                }
                Command::Fin => {
                    break;
                }
                _ => {} // Ignore WASTE and other frames
            }
        }

        Ok(())
    }

    /// Run a mock anytls UDP server: same auth flow, but responds with SYNACK
    /// and then echoes UDP messages (PSH frames)
    async fn mock_anytls_udp_server(
        listener: TcpListener,
        expected_password_hash: [u8; 32],
        acceptor: TlsAcceptor,
        ready_tx: oneshot::Sender<SocketAddr>,
    ) -> Result<()> {
        let addr = listener.local_addr()?;
        let _ = ready_tx.send(addr);

        let (tcp_stream, _peer) = listener.accept().await?;
        let tls_stream = acceptor.accept(tcp_stream).await?;
        let (mut rd, mut wr) = tokio::io::split(tls_stream);

        // Auth
        let mut auth_hash = [0u8; AUTH_HASH_SIZE];
        rd.read_exact(&mut auth_hash).await?;
        assert_eq!(&auth_hash, &expected_password_hash);

        let pad_len = rd.read_u16().await? as usize;
        if pad_len > 0 {
            let mut pad = vec![0u8; pad_len];
            rd.read_exact(&mut pad).await?;
        }

        // Settings
        let (settings_cmd, _, _) = read_frame(&mut rd).await?;
        assert_eq!(settings_cmd, Command::Settings);
        write_frame(&mut wr, Command::ServerSettings, 0, b"v=2\n").await?;

        // SYN (expecting empty data in Go protocol)
        let (syn_cmd, stream_id, _) = read_frame(&mut rd).await?;
        assert_eq!(syn_cmd, Command::Syn);
        write_frame(&mut wr, Command::SynAck, stream_id, b"").await?;

        // Consume first PSH (target)
        let (psh_cmd, _, _) = read_frame(&mut rd).await?;
        assert!(
            psh_cmd == Command::Psh || psh_cmd == Command::Fin,
            "expected PSH or FIN"
        );

        // Echo UDP messages
        loop {
            let (cmd, sid, data) = read_frame(&mut rd).await?;
            match cmd {
                Command::Psh => {
                    write_frame(&mut wr, Command::Psh, sid, &data).await?;
                }
                Command::Fin => break,
                _ => {}
            }
        }

        Ok(())
    }

    /// Create a TLS client config for testing
    #[allow(dead_code)]
    fn test_tls_client_config(_client_cfg: rustls::ClientConfig) -> TlsConfig {
        TlsConfig {
            enable: true,
            insecure: false,
            zero_rtt: false,
            sni: Some("localhost".to_string()),
            cert: None,
            key: None,
            alpns: None,
            enable_jls: false,
            jls_username: String::new(),
            jls_password: String::new(),
        }
    }

    /// Mock server that consumes the first PSH as target address (Go-client-compatible).
    /// Subsequently echoes PSH data.
    async fn mock_anytls_server_strip_target(
        listener: TcpListener,
        expected_password_hash: [u8; 32],
        acceptor: TlsAcceptor,
        ready_tx: oneshot::Sender<SocketAddr>,
    ) -> Result<()> {
        let addr = listener.local_addr()?;
        let _ = ready_tx.send(addr);

        let (tcp_stream, _peer) = listener.accept().await?;
        let tls_stream = acceptor.accept(tcp_stream).await?;
        let (mut rd, mut wr) = tokio::io::split(tls_stream);

        // Auth
        let mut auth_hash = [0u8; AUTH_HASH_SIZE];
        rd.read_exact(&mut auth_hash).await?;
        assert_eq!(&auth_hash, &expected_password_hash);

        let pad_len = rd.read_u16().await? as usize;
        if pad_len > 0 {
            let mut pad = vec![0u8; pad_len];
            rd.read_exact(&mut pad).await?;
        }

        // Settings
        let (settings_cmd, _, _) = read_frame(&mut rd).await?;
        assert_eq!(settings_cmd, Command::Settings);
        write_frame(&mut wr, Command::ServerSettings, 0, b"v=2\n").await?;

        // SYN
        let (syn_cmd, stream_id, _) = read_frame(&mut rd).await?;
        assert_eq!(syn_cmd, Command::Syn);
        write_frame(&mut wr, Command::SynAck, stream_id, b"").await?;

        // Read first PSH (target address), consume it silently
        let (psh_cmd, _, _) = read_frame(&mut rd).await?;
        assert!(
            psh_cmd == Command::Psh || psh_cmd == Command::Fin,
            "expected PSH or FIN, got {:?}",
            psh_cmd
        );
        if psh_cmd == Command::Fin {
            return Ok(());
        }

        // Echo subsequent PSH data
        loop {
            let (cmd, sid, data) = read_frame(&mut rd).await?;
            match cmd {
                Command::Psh => {
                    write_frame(&mut wr, Command::Psh, sid, &data).await?;
                }
                Command::Fin => break,
                _ => {}
            }
        }

        Ok(())
    }

    /// Run a mock anytls server that mismatches on auth and closes the connection.
    async fn mock_anytls_auth_fail_server(
        listener: TcpListener,
        _expected_password_hash: [u8; 32],
        acceptor: TlsAcceptor,
        ready_tx: oneshot::Sender<SocketAddr>,
    ) -> Result<()> {
        let addr = listener.local_addr()?;
        let _ = ready_tx.send(addr);

        let (tcp_stream, _peer) = listener.accept().await?;
        let tls_stream = acceptor.accept(tcp_stream).await?;
        let (mut rd, mut wr) = tokio::io::split(tls_stream);

        // Read auth header
        let mut auth_hash = [0u8; AUTH_HASH_SIZE];
        rd.read_exact(&mut auth_hash).await?;

        // Close connection immediately - don't read further
        drop(rd);
        let _ = wr.shutdown().await;
        Ok(())
    }

    // ── TCP Echo Test ──────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_anytls_tcp_echo() {
        let _ = rustls::crypto::ring::default_provider().install_default();

        let (server_tls_cfg, client_tls_cfg) = generate_tls_config();
        let acceptor = TlsAcceptor::from(Arc::new(server_tls_cfg));
        let phash = password_hash(TEST_PASSWORD);

        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let (ready_tx, ready_rx) = oneshot::channel();

        // Spawn mock server
        let server_handle = tokio::spawn(async move {
            let _ = tokio::time::timeout(
                Duration::from_secs(TEST_TIMEOUT_S),
                mock_anytls_server(listener, phash, acceptor, ready_tx),
            )
            .await;
        });

        let server_addr = ready_rx.await.expect("server ready");

        // Create AnytlsClient
        let address = TargetAddr::Ip(server_addr);
        let tls_cfg = TlsConfig {
            enable: true,
            insecure: false,
            zero_rtt: false,
            sni: Some("localhost".to_string()),
            cert: None,
            key: None,
            alpns: None,
            enable_jls: false,
            jls_username: String::new(),
            jls_password: String::new(),
        };

        let _client = AnytlsClient::new(
            address,
            TEST_PASSWORD,
            &tls_cfg,
            Duration::from_secs(10),
            None,
            None,
            false,
        )
        .expect("create client");

        // We connect directly using Session::new with our test TLS config
        let socket_addr = SocketAddr::from(([127, 0, 0, 1], server_addr.port()));
        let tcp_stream = TcpStream::connect(socket_addr).await.expect("connect");

        let server_name = rustls::pki_types::ServerName::try_from("localhost")
            .unwrap()
            .to_owned();

        let session = Session::new(
            tcp_stream,
            Arc::new(client_tls_cfg),
            server_name,
            &phash,
            Duration::from_secs(10),
            0,
            PaddingScheme::get_default(),
        )
        .await
        .expect("create session");

        // Wait for server to process settings and be ready
        tokio::time::sleep(Duration::from_millis(200)).await;

        // Create stream (Go protocol: SYN empty, target as first PSH)
        let stream_id = session.next_stream_id();
        let event_rx = session.register_stream(stream_id);

        // 1. Send empty SYN
        session
            .write_tx
            .send((stream_id, Command::Syn as u8, Bytes::new()))
            .expect("send SYN");

        // 2. Send target address as first PSH
        let target = TargetAddr::Domain("example.com".to_string(), 80);
        let target_data = target.to_bytes();
        session
            .write_tx
            .send((stream_id, Command::Psh as u8, Bytes::from(target_data)))
            .expect("send target PSH");

        let proxy = AnytlsProxyStream::new(stream_id, session.clone(), event_rx);

        let (mut rd, mut wr) = tokio::io::split(proxy);

        // Send data
        let test_data = b"hello anytls!";
        wr.write_all(test_data).await.expect("write");
        wr.flush().await.expect("flush");

        // Read echo
        let mut buf = vec![0u8; test_data.len()];
        rd.read_exact(&mut buf).await.expect("read echo");

        assert_eq!(&buf, test_data, "echo should match sent data");

        // Shutdown
        drop(wr);
        drop(rd);

        server_handle.abort();
    }

    // ── UDP Echo Test ──────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_anytls_udp_echo() {
        let _ = rustls::crypto::ring::default_provider().install_default();

        let (server_tls_cfg, client_tls_cfg) = generate_tls_config();
        let acceptor = TlsAcceptor::from(Arc::new(server_tls_cfg));
        let phash = password_hash(TEST_PASSWORD);

        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let (ready_tx, ready_rx) = oneshot::channel();

        let server_handle = tokio::spawn(async move {
            let _ = tokio::time::timeout(
                Duration::from_secs(TEST_TIMEOUT_S),
                mock_anytls_udp_server(listener, phash, acceptor, ready_tx),
            )
            .await;
        });

        let server_addr = ready_rx.await.expect("server ready");

        let socket_addr = SocketAddr::from(([127, 0, 0, 1], server_addr.port()));
        let tcp_stream = TcpStream::connect(socket_addr).await.expect("connect");

        let server_name = rustls::pki_types::ServerName::try_from("localhost")
            .unwrap()
            .to_owned();

        let session = Session::new(
            tcp_stream,
            Arc::new(client_tls_cfg),
            server_name,
            &phash,
            Duration::from_secs(10),
            0,
            PaddingScheme::get_default(),
        )
        .await
        .expect("create session");

        tokio::time::sleep(Duration::from_millis(200)).await;

        let stream_id = session.next_stream_id();
        let event_rx = session.register_stream(stream_id);

        // Go protocol: SYN empty, target as first PSH
        session
            .write_tx
            .send((stream_id, Command::Syn as u8, Bytes::new()))
            .expect("send SYN");

        let udp_target = TargetAddr::Domain(UDP_OVER_TCP_TARGET.to_string(), 12345);
        let target_data = udp_target.to_bytes();
        session
            .write_tx
            .send((stream_id, Command::Psh as u8, Bytes::from(target_data)))
            .expect("send target PSH");

        let udp_socket = AnytlsUdpSocket::new(stream_id, session.clone(), event_rx, false);

        // Send a UDP packet
        let test_data = Bytes::from_static(b"hello udp!");
        udp_socket
            .send_to(
                test_data.clone(),
                &SourceAddr::dummy(),
                &TargetAddr::dummy(),
            )
            .await
            .expect("send UDP");

        // Receive echo
        let (_from, _to, recv_data) = udp_socket.recv_from().await.expect("recv UDP");

        assert_eq!(
            &recv_data, &test_data,
            "echoed UDP payload should match sent data"
        );

        server_handle.abort();
    }

    // ── Auth Failure Test ──────────────────────────────────────────────────

    #[tokio::test]
    async fn test_anytls_auth_failure() {
        let _ = rustls::crypto::ring::default_provider().install_default();

        let (server_tls_cfg, client_tls_cfg) = generate_tls_config();
        let acceptor = TlsAcceptor::from(Arc::new(server_tls_cfg));
        let correct_phash = password_hash(TEST_PASSWORD);
        let wrong_phash = password_hash("wrong_password");

        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let (ready_tx, ready_rx) = oneshot::channel();

        // Server closes connection after reading auth header (no auth check needed)
        let server_handle = tokio::spawn(async move {
            let _ = tokio::time::timeout(
                Duration::from_secs(TEST_TIMEOUT_S),
                mock_anytls_auth_fail_server(listener, correct_phash, acceptor, ready_tx),
            )
            .await;
        });

        let server_addr = ready_rx.await.expect("server ready");

        let socket_addr = SocketAddr::from(([127, 0, 0, 1], server_addr.port()));
        let tcp_stream = TcpStream::connect(socket_addr).await.expect("connect");

        let server_name = rustls::pki_types::ServerName::try_from("localhost")
            .unwrap()
            .to_owned();

        // Session::new only writes auth + settings, so it succeeds even with wrong password
        let session = Session::new(
            tcp_stream,
            Arc::new(client_tls_cfg),
            server_name,
            &wrong_phash,
            Duration::from_secs(10),
            0,
            PaddingScheme::get_default(),
        )
        .await
        .expect("session creation should succeed (auth is async)");

        // The server closes the connection → read_loop fails → session becomes dead
        let closer = session.closer.clone();
        let wait_result = tokio::time::timeout(Duration::from_secs(5), closer.wait()).await;

        assert!(
            wait_result.is_ok(),
            "session should die within 5s after server closes connection"
        );

        server_handle.abort();
    }

    // ── Go Cross-Verification Helpers ──────────────────────────────────────

    /// Path to the pre-built Go anytls server binary.
    /// Build: `cd anytls-go && go build -o /tmp/anytls-server ./cmd/server`
    const GO_SERVER_PATH: &str = "/tmp/anytls-server";

    /// Path to the pre-built Go anytls client binary.
    /// Build: `cd anytls-go && go build -o /tmp/anytls-client ./cmd/client`
    const GO_CLIENT_PATH: &str = "/tmp/anytls-client";

    fn insecure_tls_client_config() -> Arc<rustls::ClientConfig> {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let mut config = rustls::ClientConfig::builder()
            .with_root_certificates(rustls::RootCertStore::empty())
            .with_no_client_auth();
        config
            .dangerous()
            .set_certificate_verifier(Arc::new(SkipServerVerification));
        Arc::new(config)
    }

    /// Start the Go anytls server on a random port. Returns (child, port).
    /// The server auto-generates TLS cert and proxies to any destination.
    async fn start_go_server(port: u16, password: &str) -> std::process::Child {
        let mut cmd = std::process::Command::new(GO_SERVER_PATH);
        cmd.args(["-l", &format!("127.0.0.1:{}", port), "-p", password]);
        cmd.env("LOG_LEVEL", "info");
        cmd.stdin(std::process::Stdio::null());
        cmd.stdout(std::process::Stdio::piped());
        cmd.stderr(std::process::Stdio::piped());
        cmd.spawn().expect("failed to start Go anytls server")
    }

    /// Start the Go anytls client (SOCKS5 → anytls) on a random port.
    async fn start_go_client(
        socks5_port: u16,
        server_addr: &str,
        password: &str,
    ) -> std::process::Child {
        let mut cmd = std::process::Command::new(GO_CLIENT_PATH);
        cmd.args([
            "-l",
            &format!("127.0.0.1:{}", socks5_port),
            "-s",
            server_addr,
            "-p",
            password,
            "-m",
            "1",
        ]);
        cmd.env("LOG_LEVEL", "info");
        cmd.stdin(std::process::Stdio::null());
        cmd.stdout(std::process::Stdio::piped());
        cmd.stderr(std::process::Stdio::piped());
        cmd.spawn().expect("failed to start Go anytls client")
    }

    /// Wait for port to be connectable (up to 10s).
    async fn wait_port_ready(port: u16, timeout: Duration) {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            let addr = SocketAddr::from(([127, 0, 0, 1], port));
            if TcpStream::connect(addr).await.is_ok() {
                return;
            }
            if tokio::time::Instant::now() > deadline {
                panic!("port {} not ready after {:?}", port, timeout);
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    }

    /// Run a simple TCP echo server that echoes all data back.
    async fn spawn_echo_server() -> (SocketAddr, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind echo");
        let addr = listener.local_addr().expect("echo addr");
        let handle = tokio::spawn(async move {
            loop {
                if let Ok((mut sock, _)) = listener.accept().await {
                    tokio::spawn(async move {
                        let (mut rd, mut wr) = sock.split();
                        let _ = tokio::io::copy(&mut rd, &mut wr).await;
                    });
                }
            }
        });
        (addr, handle)
    }

    /// Run a simple UDP echo server that echoes all data back.
    async fn spawn_udp_echo_server() -> (SocketAddr, tokio::task::JoinHandle<()>) {
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("bind udp echo");
        let addr = socket.local_addr().expect("udp echo addr");
        let handle = tokio::spawn(async move {
            let mut buf = vec![0u8; 65536];
            loop {
                if let Ok((len, peer)) = socket.recv_from(&mut buf).await {
                    let _ = socket.send_to(&buf[..len], peer).await;
                }
            }
        });
        (addr, handle)
    }

    // ── Cross-Verification: Rust client ↔ Go server ────────────────────────

    /// Test that our Rust anytls client can talk to the Go anytls server.
    /// The Go server proxies to a local TCP echo server.
    #[tokio::test]
    async fn test_crossver_rust_client_go_server_tcp_echo() {
        // Ensure Go server binary exists
        if !std::path::Path::new(GO_SERVER_PATH).exists() {
            eprintln!(
                "Skipping: Go server binary not found at {}. Build with: \
                 cd anytls-go && go build -o {} ./cmd/server",
                GO_SERVER_PATH, GO_SERVER_PATH
            );
            return;
        }

        let _ = rustls::crypto::ring::default_provider().install_default();

        // 1. Start TCP echo server
        let (echo_addr, _echo_handle) = spawn_echo_server().await;
        println!("Echo server on {}", echo_addr);

        // 2. Start Go anytls server
        let go_port = {
            let l = TcpListener::bind("127.0.0.1:0").await.expect("bind");
            let p = l.local_addr().unwrap().port();
            drop(l);
            p
        };
        let password = "cross_ver_test";
        let mut go_child = start_go_server(go_port, password).await;
        wait_port_ready(go_port, Duration::from_secs(10)).await;
        println!("Go server on port {}", go_port);

        // 3. Rust client: connect to Go server via TLS
        let tls_cfg = insecure_tls_client_config();
        let server_name = rustls::pki_types::ServerName::try_from("127.0.0.1")
            .unwrap()
            .to_owned();

        let tcp_stream = TcpStream::connect(SocketAddr::from(([127, 0, 0, 1], go_port)))
            .await
            .expect("TCP connect to Go server");

        let session = Session::new(
            tcp_stream,
            tls_cfg,
            server_name,
            &password_hash(password),
            Duration::from_secs(10),
            0,
            PaddingScheme::get_default(),
        )
        .await
        .expect("create session to Go server");

        tokio::time::sleep(Duration::from_millis(300)).await;

        // 4. Open stream: send SYN (empty), then PSH with target address
        let stream_id = session.next_stream_id();
        let event_rx = session.register_stream(stream_id);

        // Send SYN (Go server expects empty SYN data)
        session
            .write_tx
            .send((stream_id, Command::Syn as u8, Bytes::new()))
            .expect("send SYN");

        let proxy = AnytlsProxyStream::new(stream_id, session.clone(), event_rx);
        let (mut rd, mut wr) = tokio::io::split(proxy);

        // Send target address as PSH (Go client sends target via PSH after SYN)
        let target = TargetAddr::Ip(echo_addr);
        let target_bytes = target.to_bytes();
        wr.write_all(&target_bytes).await.expect("write target");
        wr.flush().await.expect("flush target");

        // Wait for Go server to process SYN+target and connect to echo
        tokio::time::sleep(Duration::from_millis(500)).await;

        // 5. Write test data, read echo
        let test_data = b"hello from rust anytls client!";
        wr.write_all(test_data).await.expect("write");
        wr.flush().await.expect("flush");

        let mut buf = vec![0u8; test_data.len()];
        match tokio::time::timeout(Duration::from_secs(10), rd.read_exact(&mut buf)).await {
            Ok(Ok(_n)) => {}
            Ok(Err(e)) => panic!("read echo failed: {:?}", e),
            Err(_) => panic!("read echo timed out"),
        }
        assert_eq!(&buf, test_data, "echo should match");

        println!("Rust client ↔ Go server: TCP echo OK");

        drop(wr);
        drop(rd);

        // Cleanup
        let _ = go_child.kill();
        let _ = go_child.wait();
        _echo_handle.abort();
    }

    // ── Cross-Verification: Go client ↔ Rust server ────────────────────────

    /// Test that the Go anytls client can talk to our Rust mock server.
    /// The mock server echoes data back.
    #[tokio::test]
    async fn test_crossver_go_client_rust_server_tcp_echo() {
        if !std::path::Path::new(GO_CLIENT_PATH).exists() {
            eprintln!(
                "Skipping: Go client binary not found at {}. Build with: \
                 cd anytls-go && go build -o {} ./cmd/client",
                GO_CLIENT_PATH, GO_CLIENT_PATH
            );
            return;
        }

        let _ = rustls::crypto::ring::default_provider().install_default();

        let (server_tls_cfg, _) = generate_tls_config();
        let acceptor = TlsAcceptor::from(Arc::new(server_tls_cfg));
        let phash = password_hash("go_cross_ver");

        // 1. Start Rust mock server
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind rust server");
        let rust_server_addr = listener.local_addr().expect("rust server addr");

        let server_handle = tokio::spawn(async move {
            let _ = tokio::time::timeout(
                Duration::from_secs(30),
                mock_anytls_server_strip_target(listener, phash, acceptor, oneshot::channel().0),
            )
            .await;
        });

        // 2. Start Go anytls client (SOCKS5 → anytls)
        let socks5_port = {
            let l = TcpListener::bind("127.0.0.1:0").await.expect("bind socks");
            let p = l.local_addr().unwrap().port();
            drop(l);
            p
        };

        let mut go_child = start_go_client(
            socks5_port,
            &format!("127.0.0.1:{}", rust_server_addr.port()),
            "go_cross_ver",
        )
        .await;

        // Wait for Go client's SOCKS5 port to be ready
        wait_port_ready(socks5_port, Duration::from_secs(10)).await;
        println!(
            "Go client SOCKS5 on port {}, connecting to Rust server {}",
            socks5_port, rust_server_addr
        );

        tokio::time::sleep(Duration::from_millis(500)).await;

        // 3. SOCKS5 connect: tell Go client to connect to our echo server
        let (echo_addr, _echo_handle) = spawn_echo_server().await;

        // Manual SOCKS5 handshake to Go client
        let mut sock = TcpStream::connect(SocketAddr::from(([127, 0, 0, 1], socks5_port)))
            .await
            .expect("SOCKS5 connect to Go client");

        // SOCKS5 greeting: no auth
        sock.write_all(&[0x05, 0x01, 0x00])
            .await
            .expect("SOCKS5 hello");
        let mut resp = [0u8; 2];
        sock.read_exact(&mut resp).await.expect("SOCKS5 auth resp");
        assert_eq!(resp, [0x05, 0x00], "SOCKS5 no-auth accepted");

        // SOCKS5 CONNECT request to echo server
        let echo_ip = match echo_addr.ip() {
            std::net::IpAddr::V4(v4) => v4,
            _ => panic!("expected IPv4"),
        };
        let mut req = Vec::new();
        req.push(0x05); // version
        req.push(0x01); // CONNECT
        req.push(0x00); // reserved
        req.push(0x01); // IPv4
        req.extend_from_slice(&echo_ip.octets());
        req.extend_from_slice(&echo_addr.port().to_be_bytes());
        sock.write_all(&req).await.expect("SOCKS5 connect req");

        // Read SOCKS5 connect response
        let mut connect_resp = [0u8; 10];
        sock.read_exact(&mut connect_resp)
            .await
            .expect("SOCKS5 connect resp");
        assert_eq!(
            connect_resp[0..4],
            [0x05, 0x00, 0x00, 0x01],
            "SOCKS5 connect succeeded"
        );

        // 4. Now the tunnel is established. Write test data, read echo.
        let test_data = b"hello from go anytls client via rust server!";
        sock.write_all(test_data).await.expect("write data");
        sock.flush().await.expect("flush");

        // Read echo via the tunnel
        let mut buf = vec![0u8; test_data.len()];
        let mut total = 0;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        while total < test_data.len() {
            match tokio::time::timeout_at(
                deadline,
                AsyncReadExt::read(&mut sock, &mut buf[total..]),
            )
            .await
            {
                Ok(Ok(0)) => break,
                Ok(Ok(n)) => total += n,
                Ok(Err(e)) => {
                    eprintln!("read error: {:?}", e);
                    break;
                }
                Err(_) => {
                    eprintln!("read timeout");
                    break;
                }
            }
        }
        assert_eq!(total, test_data.len(), "should receive all echo bytes");
        assert_eq!(&buf[..total], test_data, "echo data mismatch");

        println!("Go client ↔ Rust server: TCP echo OK");

        drop(sock);
        let _ = go_child.kill();
        let _ = go_child.wait();
        server_handle.abort();
        _echo_handle.abort();
    }

    // ── Cross-Verification: Rust AnytlsOutbound → Go server ──────────────

    /// Full-stack test: Rust AnytlsOutbound → Go anytls server → TCP echo.
    /// Uses the real production outbound, not raw Session.
    #[tokio::test]
    async fn test_crossver_rust_outbound_go_server_tcp_echo() {
        if !std::path::Path::new(GO_SERVER_PATH).exists() {
            eprintln!("Skipping: Go server binary not found at {}", GO_SERVER_PATH);
            return;
        }

        // 1. Start TCP echo server
        let (echo_addr, _echo_handle) = spawn_echo_server().await;
        println!("Echo server on {}", echo_addr);

        // 2. Start Go anytls server
        let go_port = {
            let l = TcpListener::bind("127.0.0.1:0").await.expect("bind");
            let p = l.local_addr().unwrap().port();
            drop(l);
            p
        };
        let password = "rust_outbound_go_server";
        let mut go_child = start_go_server(go_port, password).await;
        wait_port_ready(go_port, Duration::from_secs(10)).await;
        println!("Go server on port {}", go_port);

        // 3. Create Rust AnytlsOutbound
        let cfg = crate::config::OutboundConfig {
            protocol_type: "anytls".to_string(),
            address: Some("127.0.0.1".to_string()),
            port: Some(go_port),
            password: Some(password.to_string()),
            connect_timeout: Some(10),
            bind_interface: None,
            dns: None,
            idle_timeout: None,
            username: None,
            uuid: None,
            udp_mod: None,
            congestion_controller: None,
            pool_size: None,
            gso: false,
            mtu_discoveriy: true,
            min_mtu: 1200,
            initial_mtu: 1200,
            outbounds: None,
            default_outbound: None,
            url: None,
            interval: None,
            tolerance: None,
            prefer_ipv6: None,
            cache: None,
            tls: Some(crate::config::OutboundTlsConfig {
                enable: true,
                insecure: Some(true),
                server_name: Some("127.0.0.1".to_string()),
                ca: None,
                alpn: None,
                enable_jls: false,
                jls_username: None,
                jls_password: None,
            }),
            transport: None,
            disable_mux: false,
        };

        let outbound = AnytlsOutbound::new("test_anytls_out".to_string(), &cfg)
            .expect("create AnytlsOutbound");

        // 4. Connect stream targeting echo server
        let target = TargetAddr::Ip(echo_addr);
        let mut stream =
            tokio::time::timeout(Duration::from_secs(15), outbound.connect_stream(&target))
                .await
                .expect("connect_stream timeout")
                .expect("connect_stream failed");

        // 5. Write data, read echo
        let test_data = b"hello from rust AnytlsOutbound via Go server!";
        stream.write_all(test_data).await.expect("write");
        stream.flush().await.expect("flush");

        let mut buf = vec![0u8; test_data.len()];
        match tokio::time::timeout(Duration::from_secs(10), stream.read_exact(&mut buf)).await {
            Ok(Ok(_n)) => {}
            Ok(Err(e)) => panic!("read echo failed: {:?}", e),
            Err(_) => panic!("read echo timed out"),
        }
        assert_eq!(&buf, test_data, "echo should match sent data");

        println!("Rust AnytlsOutbound ↔ Go server: TCP echo OK");

        drop(stream);
        let _ = go_child.kill();
        let _ = go_child.wait();
        _echo_handle.abort();
    }

    #[tokio::test]
    async fn test_crossver_rust_outbound_go_server_udp_echo() {
        if !std::path::Path::new(GO_SERVER_PATH).exists() {
            eprintln!("Skipping: Go server binary not found at {}", GO_SERVER_PATH);
            return;
        }

        // 1. Start UDP echo server
        let (echo_addr, _echo_handle) = spawn_udp_echo_server().await;
        println!("UDP Echo server on {}", echo_addr);

        // 2. Start Go anytls server
        let go_port = {
            let l = TcpListener::bind("127.0.0.1:0").await.expect("bind");
            let p = l.local_addr().unwrap().port();
            drop(l);
            p
        };
        let password = "rust_outbound_go_server_udp";
        let mut go_child = start_go_server(go_port, password).await;
        wait_port_ready(go_port, Duration::from_secs(10)).await;
        println!("Go server on port {}", go_port);

        // 3. Create Rust AnytlsOutbound
        let cfg = crate::config::OutboundConfig {
            protocol_type: "anytls".to_string(),
            address: Some("127.0.0.1".to_string()),
            port: Some(go_port),
            password: Some(password.to_string()),
            connect_timeout: Some(10),
            bind_interface: None,
            dns: None,
            idle_timeout: None,
            username: None,
            uuid: None,
            udp_mod: None,
            congestion_controller: None,
            pool_size: None,
            gso: false,
            mtu_discoveriy: true,
            min_mtu: 1200,
            initial_mtu: 1200,
            outbounds: None,
            default_outbound: None,
            url: None,
            interval: None,
            tolerance: None,
            prefer_ipv6: None,
            cache: None,
            tls: Some(crate::config::OutboundTlsConfig {
                enable: true,
                insecure: Some(true),
                server_name: Some("127.0.0.1".to_string()),
                ca: None,
                alpn: None,
                enable_jls: false,
                jls_username: None,
                jls_password: None,
            }),
            transport: None,
            disable_mux: false,
        };

        let outbound = AnytlsOutbound::new("test_anytls_out".to_string(), &cfg)
            .expect("create AnytlsOutbound");

        // 4. Connect packet targeting echo server
        let target = TargetAddr::Ip(echo_addr);
        let udp_socket =
            tokio::time::timeout(Duration::from_secs(15), outbound.connect_packet(&target))
                .await
                .expect("connect_packet timeout")
                .expect("connect_packet failed");

        // 5. Send data
        let test_data = b"hello UDP from rust AnytlsOutbound via Go server!";
        udp_socket
            .send_to(Bytes::from_static(test_data), &TargetAddr::dummy(), &target)
            .await
            .expect("send_to failed");

        // 6. Read echo
        match tokio::time::timeout(Duration::from_secs(10), udp_socket.recv_from()).await {
            Ok(Ok((_, _, data))) => {
                assert_eq!(&data[..], test_data, "echo should match sent data");
            }
            Ok(Err(e)) => panic!("recv_from failed: {:?}", e),
            Err(_) => panic!("recv_from timed out"),
        }

        println!("Rust AnytlsOutbound ↔ Go server: UDP echo OK");

        let _ = go_child.kill();
        let _ = go_child.wait();
        _echo_handle.abort();
    }
}
