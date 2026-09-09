//! Hysteria2 (https://v2.hysteria.network/) outbound.
//!
//! Speaks the Hysteria2 wire protocol on top of QUIC:
//! - TLS 1.3 with ALPN `h3`; the client authenticates with an HTTP/3
//!   `POST /auth` (see [`http3`]), after which the QUIC connection becomes a
//!   proxy connection.
//! - TCP: one QUIC bidirectional stream per connection, mirroring the
//!   sing-box client: `connect_stream` returns immediately, the first write
//!   fuses the TCPRequest (type `0x401`, "host:port") with the payload, and
//!   the first read consumes the TCPResponse before relaying payload.
//! - UDP: QUIC datagrams carrying the UDPMessage framing (session id,
//!   packet id, fragmentation, destination, payload). Multiple UDP proxy
//!   sessions share one QUIC connection, demultiplexed by session id.
//!
//! Congestion control is the transport default (BBR in this project's quinn
//! build); the Brutal algorithm is intentionally not implemented, and
//! salamander obfuscation is not supported because quinn exposes no packet
//! layer hook to wrap every QUIC datagram.

pub(crate) mod http3;
pub(crate) mod qpack;

use crate::config::OutboundConfig;
use crate::proxy::outbound::{AnyOutbound, AnyPacket, AnyStream, PathState};
use crate::proxy::{SessionCloser, TargetAddr, TlsConfig};
use crate::utils::interface::InterfaceManager;
use crate::utils::{new_io_other_error, now};
use crate::utils::quic_wrap::quinn_wrap::QuinnClient;
use anyhow::{Context, Result, bail};
use async_trait::async_trait;
use bytes::{Buf, BufMut, Bytes, BytesMut};
use dashmap::DashMap;
use http3::{H3Control, STATUS_AUTH_OK, authenticate};
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, LazyLock};
use std::task::{Context as TaskContext, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::{Mutex, Notify, mpsc};
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};

const TCP_REQUEST_TYPE: u64 = 0x401;
/// Bound on a single UDP proxy packet payload.
const MAX_UDP_PAYLOAD: usize = 2048;
/// Max bytes for a destination address carried in a UDPMessage.
const MAX_UDP_ADDRESS_LEN: u64 = 2048;
/// Queue depth of raw datagrams waiting for one UDP session's worker.
const UDP_RAW_QUEUE_CAPACITY: usize = 16;
/// Queue depth of decapsulated UDP packets handed to the router.
const UDP_RECV_QUEUE_CAPACITY: usize = 16;
/// Fragmented packets older than this are discarded.
const UDP_FRAGMENT_TIMEOUT: Duration = Duration::from_secs(10);
/// Upper bound on concurrently tracked fragmented packets per session.
const UDP_MAX_DEFRAG_ENTRIES: usize = 64;
/// Session ids start at 1 (0 is reserved).
const FIRST_SESSION_ID: u32 = 1;

/// Dummy destination used for received UDP packets.
static DUMMY_TARGET: LazyLock<TargetAddr> = LazyLock::new(TargetAddr::dummy);

// ---------------------------------------------------------------------------
// QUIC varints and Hysteria2 wire message codecs
// ---------------------------------------------------------------------------

fn varint_len(value: u64) -> usize {
    match value {
        0..=63 => 1,
        64..=16383 => 2,
        16384..=1_073_741_823 => 4,
        _ => 8,
    }
}

/// Read a varint from the front of `buf`, returning `(value, consumed)`.
fn read_varint(buf: &[u8]) -> Result<(u64, usize)> {
    let first = *buf.first().context("varint truncated")?;
    let len = 1usize << (first >> 6);
    if buf.len() < len {
        bail!("varint truncated");
    }
    let mut value = (first & 0x3f) as u64;
    for b in &buf[1..len] {
        value = (value << 8) | *b as u64;
    }
    Ok((value, len))
}

fn append_varint(out: &mut Vec<u8>, value: u64) {
    match value {
        0..=63 => out.push(value as u8),
        64..=16383 => {
            out.push(0x40 | ((value >> 8) as u8));
            out.push(value as u8);
        }
        16384..=1_073_741_823 => {
            out.push(0x80 | ((value >> 24) as u8));
            out.push((value >> 16) as u8);
            out.push((value >> 8) as u8);
            out.push(value as u8);
        }
        _ => {
            out.push(0xc0 | ((value >> 56) as u8));
            out.push((value >> 48) as u8);
            out.push((value >> 40) as u8);
            out.push((value >> 32) as u8);
            out.push((value >> 24) as u8);
            out.push((value >> 16) as u8);
            out.push((value >> 8) as u8);
            out.push(value as u8);
        }
    }
}

/// Serialize a TCPRequest: `0x401` type, "host:port" address, empty padding.
fn encode_tcp_request(target: &TargetAddr) -> Vec<u8> {
    let addr = target.to_string();
    let mut out = Vec::with_capacity(2 + varint_len(addr.len() as u64) + addr.len() + 1);
    append_varint(&mut out, TCP_REQUEST_TYPE);
    append_varint(&mut out, addr.len() as u64);
    out.extend_from_slice(addr.as_bytes());
    append_varint(&mut out, 0);
    out
}

/// A parsed UDP proxy datagram (Hysteria2 UDPMessage).
#[derive(Debug)]
struct UdpMessage {
    session_id: u32,
    packet_id: u16,
    frag_id: u8,
    frag_count: u8,
    destination: String,
    payload: Bytes,
}

impl UdpMessage {
    /// Bytes of the fixed+variable header (before payload).
    fn header_size(&self) -> usize {
        8 + varint_len(self.destination.len() as u64) + self.destination.len()
    }

    /// Serialize into one QUIC datagram payload.
    fn pack(&self) -> Bytes {
        let mut out = BytesMut::with_capacity(self.header_size() + self.payload.len());
        out.put_u32(self.session_id);
        out.put_u16(self.packet_id);
        out.put_u8(self.frag_id);
        out.put_u8(self.frag_count);
        let mut head = Vec::new();
        append_varint(&mut head, self.destination.len() as u64);
        out.put_slice(&head);
        out.put_slice(self.destination.as_bytes());
        out.put_slice(&self.payload);
        out.freeze()
    }
}

/// Decapsulate one datagram payload into its message fields.
fn parse_udp_message(data: &[u8]) -> Result<UdpMessage> {
    if data.len() < 9 {
        bail!("UDP message too short");
    }
    let session_id = u32::from_be_bytes(data[0..4].try_into().unwrap());
    let packet_id = u16::from_be_bytes(data[4..6].try_into().unwrap());
    let frag_id = data[6];
    let frag_count = data[7];
    let (addr_len, used) = read_varint(&data[8..])?;
    if addr_len == 0 || addr_len > MAX_UDP_ADDRESS_LEN {
        bail!("invalid UDP destination length {addr_len}");
    }
    let addr_len = addr_len as usize;
    let start = 8 + used;
    if data.len() < start + addr_len {
        bail!("UDP message truncated");
    }
    let destination = String::from_utf8_lossy(&data[start..start + addr_len]).into_owned();
    Ok(UdpMessage {
        session_id,
        packet_id,
        frag_id,
        frag_count,
        destination,
        payload: Bytes::copy_from_slice(&data[start + addr_len..]),
    })
}

/// A partially reassembled fragmented UDP packet.
struct Fragments {
    count: u8,
    parts: Vec<Option<Bytes>>,
    created: std::time::Instant,
}

/// Decapsulate one datagram, assembling fragmented packets when complete.
/// Returns `Ok(None)` while fragments are still outstanding.
fn process_udp_datagram(
    raw: Bytes,
    defrag: &mut hashbrown::HashMap<u16, Fragments>,
) -> Result<Option<(String, Bytes)>> {
    let message = parse_udp_message(&raw)?;
    if message.frag_count == 0 || message.frag_id >= message.frag_count {
        bail!("invalid fragment id/count in UDP message");
    }
    if message.frag_count == 1 {
        return Ok(Some((message.destination, message.payload)));
    }
    let now = now();
    if defrag.len() >= UDP_MAX_DEFRAG_ENTRIES {
        defrag.retain(|_, v| now.duration_since(v.created) < UDP_FRAGMENT_TIMEOUT);
    }
    let entry = defrag
        .entry(message.packet_id)
        .or_insert_with(|| Fragments {
            count: message.frag_count,
            parts: vec![None; message.frag_count as usize],
            created: now,
        });
    if entry.count != message.frag_count {
        bail!(
            "conflicting fragment count for packet {}",
            message.packet_id
        );
    }
    if now.duration_since(entry.created) > UDP_FRAGMENT_TIMEOUT {
        entry.created = now;
        entry.count = message.frag_count;
        entry.parts = vec![None; message.frag_count as usize];
    }
    entry.parts[message.frag_id as usize] = Some(message.payload);
    if entry.parts.iter().any(|part| part.is_none()) {
        return Ok(None);
    }
    let destination = message.destination;
    let mut whole = BytesMut::new();
    for part in entry.parts.iter_mut() {
        if let Some(part) = part.take() {
            whole.put_slice(&part);
        }
    }
    defrag.remove(&message.packet_id);
    Ok(Some((destination, whole.freeze())))
}

// ---------------------------------------------------------------------------
// Per-QUIC-connection shared state
// ---------------------------------------------------------------------------

/// State shared by all proxy sessions multiplexed over one QUIC connection.
struct Hy2ConnState {
    conn: Arc<quinn::Connection>,
    /// Kept alive so the connection stays on its control stream (HTTP/3
    /// requires the control stream to remain open for the connection's
    /// lifetime).
    _control: H3Control,
    udp_enabled: bool,
    /// Monotonic per-connection UDP session id allocator.
    next_session_id: AtomicU32,
    /// Raw incoming datagrams routed to the owning UDP session's worker.
    datagram_routes: DashMap<u32, mpsc::Sender<Bytes>>,
    /// Broadcast when the QUIC connection dies or is shut down.
    closed: Notify,
}

impl Hy2ConnState {
    fn close(&self) {
        self.closed.notify_waiters();
        self.conn.close(0u32.into(), b"");
    }
}

/// Demultiplexer task reading QUIC datagrams for one connection. Parses the
/// session id from the fixed header and routes the raw datagram to the
/// owning session worker, which does the full decapsulation.
async fn run_datagram_listener(state: Arc<Hy2ConnState>) {
    loop {
        tokio::select! {
            _ = state.closed.notified() => break,
            result = state.conn.read_datagram() => {
                match result {
                    Ok(data) => {
                        if data.len() < 4 {
                            continue;
                        }
                        let session_id = u32::from_be_bytes(data[0..4].try_into().unwrap());
                        if let Some(tx) = state.datagram_routes.get(&session_id) {
                            // Datagrams are unreliable anyway: drop rather
                            // than ever blocking the shared demuxer.
                            let _ = tx.try_send(data);
                        }
                    }
                    Err(e) => {
                        debug!("hy2 datagram listener ended: {}", e);
                        break;
                    }
                }
            }
        }
    }
    state.closed.notify_waiters();
}

// ---------------------------------------------------------------------------
// UDP proxy session
// ---------------------------------------------------------------------------

struct Hy2UdpSession {
    session_id: u32,
    state: Arc<Hy2ConnState>,
    recv: Mutex<mpsc::Receiver<(TargetAddr, Bytes)>>,
    closer: Arc<SessionCloser>,
    sent_bytes: std::sync::atomic::AtomicU64,
    recv_bytes: std::sync::atomic::AtomicU64,
}

impl Hy2UdpSession {
    fn new(session_id: u32, state: Arc<Hy2ConnState>, closer: Arc<SessionCloser>) -> Arc<Self> {
        let (raw_tx, mut raw_rx) = mpsc::channel::<Bytes>(UDP_RAW_QUEUE_CAPACITY);
        let (done_tx, done_rx) = mpsc::channel::<(TargetAddr, Bytes)>(UDP_RECV_QUEUE_CAPACITY);
        state.datagram_routes.insert(session_id, raw_tx);

        let session = Arc::new(Self {
            session_id,
            state: state.clone(),
            recv: Mutex::new(done_rx),
            closer: closer.clone(),
            sent_bytes: Default::default(),
            recv_bytes: Default::default(),
        });

        // Per-session worker: decapsulate + defragment datagrams and push
        // completed packets to the session's receive queue.
        let worker_session = session.clone();
        let worker_state = state.clone();
        let worker_closer = closer.clone();
        tokio::spawn(async move {
            let mut defrag: hashbrown::HashMap<u16, Fragments> = hashbrown::HashMap::new();
            loop {
                tokio::select! {
                    _ = worker_closer.wait() => break,
                    _ = worker_state.closed.notified() => break,
                    item = raw_rx.recv() => {
                        let Some(raw) = item else { break };
                        match process_udp_datagram(raw, &mut defrag) {
                            Ok(Some((destination, payload))) => {
                                let dest = TargetAddr::from_str(&destination)
                                    .unwrap_or_else(|_| DUMMY_TARGET.clone());
                                worker_session.recv_bytes.fetch_add(
                                    payload.len() as u64,
                                    Ordering::Relaxed,
                                );
                                if done_tx.try_send((dest, payload)).is_err() {
                                    debug!(
                                        "hy2 udp session {} receive queue full, dropping packet",
                                        worker_session.session_id
                                    );
                                }
                            }
                            Ok(None) => {}
                            Err(e) => debug!("hy2 dropped malformed datagram: {:#}", e),
                        }
                    }
                }
            }
            worker_state
                .datagram_routes
                .remove(&worker_session.session_id);
        });

        session
    }
}

impl Drop for Hy2UdpSession {
    fn drop(&mut self) {
        self.state.datagram_routes.remove(&self.session_id);
        self.closer.close();
    }
}

#[async_trait]
impl AnyPacket for Hy2UdpSession {
    async fn send_to(
        &self,
        buf: Bytes,
        _from: &crate::proxy::SourceAddr,
        target: &TargetAddr,
    ) -> Result<usize> {
        if buf.len() > MAX_UDP_PAYLOAD {
            bail!("UDP payload too large: {}", buf.len());
        }
        let conn = &self.state.conn;
        let Some(max_size) = conn.max_datagram_size() else {
            bail!("hy2 peer does not support QUIC datagrams");
        };

        let destination = target.to_string();
        let base = UdpMessage {
            session_id: self.session_id,
            packet_id: 0,
            frag_id: 0,
            frag_count: 1,
            destination: destination.clone(),
            payload: Bytes::new(),
        };
        let header_size = base.header_size();
        let payload_len = buf.len();

        // Single datagram when it fits; otherwise fragment so every piece is
        // within the peer's datagram budget.
        let chunks: Vec<Bytes> = if buf.len() + header_size <= max_size {
            vec![buf]
        } else {
            let per_fragment = max_size.saturating_sub(header_size).max(1);
            let mut rest = buf;
            let mut chunks = Vec::new();
            while !rest.is_empty() {
                let take = rest.len().min(per_fragment);
                chunks.push(rest.split_to(take));
            }
            chunks
        };
        let frag_count = u8::try_from(chunks.len()).context("too many UDP fragments")?;

        let mut packet_id = rand_packet_id();
        for (index, chunk) in chunks.into_iter().enumerate() {
            packet_id = packet_id.wrapping_add(1);
            let message = UdpMessage {
                session_id: self.session_id,
                packet_id,
                frag_id: index as u8,
                frag_count,
                destination: destination.clone(),
                payload: chunk,
            };
            let packed = message.pack();
            match conn.send_datagram(packed) {
                Ok(()) => {}
                Err(quinn::SendDatagramError::TooLarge) => {
                    // Extremely rare (path MTU shrank mid-send): report it;
                    // the packet is dropped like any unreliable datagram.
                    warn!("hy2 datagram too large despite fragmentation budget");
                }
                Err(e) => return Err(anyhow::Error::from(e)),
            }
        }
        self.sent_bytes
            .fetch_add(payload_len as u64, Ordering::Relaxed);
        Ok(payload_len)
    }

    async fn recv_from(&self) -> Result<crate::proxy::outbound::PacketInfo> {
        let mut rx = self.recv.lock().await;
        match rx.recv().await {
            Some((destination, payload)) => Ok((destination, DUMMY_TARGET.clone(), payload)),
            None => bail!("hy2 UDP session closed"),
        }
    }

    async fn recv_many(&self, packets: &mut Vec<crate::proxy::outbound::PacketInfo>) -> Result<()> {
        let mut rx = self.recv.lock().await;
        let first = match rx.recv().await {
            Some((destination, payload)) => (destination, payload),
            None => bail!("hy2 UDP session closed"),
        };
        packets.clear();
        packets.push((first.0, DUMMY_TARGET.clone(), first.1));
        while let Ok(item) = rx.try_recv() {
            packets.push((item.0, DUMMY_TARGET.clone(), item.1));
        }
        Ok(())
    }

    fn closer(&self) -> Option<Arc<SessionCloser>> {
        Some(self.closer.clone())
    }

    fn get_udp_stats(&self) -> Option<(u64, u64, u64)> {
        Some((
            self.sent_bytes.load(Ordering::Relaxed),
            self.recv_bytes.load(Ordering::Relaxed),
            0,
        ))
    }
}

fn rand_packet_id() -> u16 {
    use rand::RngExt;
    let mut rng = rand::rng();
    rng.random_range(u16::MIN..=u16::MAX)
}

// ---------------------------------------------------------------------------
// TCP handshake
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// TCP proxy stream
// ---------------------------------------------------------------------------

/// Bounds on TCPResponse lengths (mirror the reference implementation's DoS
/// protections).
const MAX_TCP_RESPONSE_MESSAGE: usize = 2048;
const MAX_TCP_RESPONSE_PADDING: usize = 4096;

/// One Hysteria2 TCP proxy connection over a QUIC bidirectional stream.
///
/// Mirrors the sing-box client: the TCPRequest prefix is fused into the
/// first application write, and the first read consumes the TCPResponse
/// frame so its bytes never leak into the application stream. A remote dial
/// error surfaces once as an I/O error.
struct Hy2TcpStream {
    send: quinn::SendStream,
    recv: quinn::RecvStream,
    pending_request: Option<Vec<u8>>,
    response: ResponseReader,
}

/// Parses the TCPResponse prefix (`status, message, padding`).
struct ResponseReader {
    buf: BytesMut,
    step: ResponseStep,
    remote_error: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum ResponseStep {
    Status,
    /// Reading the message-length varint (present for both outcomes).
    MsgLen,
    /// Reading `len` message bytes.
    Msg {
        len: usize,
    },
    /// Reading the padding-length varint.
    PadLen,
    /// Reading `len` padding bytes.
    Pad {
        len: usize,
    },
    Done,
}

/// The response parser needs more input bytes before it can continue.
enum ResponseNeed {
    More,
}

impl ResponseReader {
    fn new() -> Self {
        Self {
            buf: BytesMut::new(),
            step: ResponseStep::Status,
            remote_error: None,
        }
    }

    fn is_done(&self) -> bool {
        self.step == ResponseStep::Done
    }

    /// Parse buffered bytes, requesting more input when the frame is
    /// incomplete. Callers top up `buf` whenever `More` is returned.
    fn parse_step(&mut self) -> Result<Option<ResponseNeed>> {
        loop {
            match self.step {
                ResponseStep::Done => return Ok(None),
                ResponseStep::Status => {
                    if self.buf.len() < 1 {
                        return Ok(Some(ResponseNeed::More));
                    }
                    if self.buf[0] != 0 {
                        self.remote_error = Some(String::new());
                    }
                    self.buf.advance(1);
                    self.step = ResponseStep::MsgLen;
                }
                ResponseStep::MsgLen => {
                    if self.buf.is_empty() {
                        return Ok(Some(ResponseNeed::More));
                    }
                    let varint_bytes = 1usize << (self.buf[0] >> 6);
                    if self.buf.len() < varint_bytes {
                        return Ok(Some(ResponseNeed::More));
                    }
                    let (len, used) = read_varint(&self.buf)?;
                    if len > MAX_TCP_RESPONSE_MESSAGE as u64 {
                        bail!("hy2 TCP response message too long");
                    }
                    self.buf.advance(used);
                    self.step = ResponseStep::Msg { len: len as usize };
                }
                ResponseStep::Msg { len } => {
                    if self.buf.len() < len {
                        return Ok(Some(ResponseNeed::More));
                    }
                    if self.remote_error.is_some() {
                        let msg = String::from_utf8_lossy(&self.buf[..len]).into_owned();
                        self.remote_error = Some(msg);
                    }
                    self.buf.advance(len);
                    self.step = ResponseStep::PadLen;
                }
                ResponseStep::PadLen => {
                    if self.buf.is_empty() {
                        return Ok(Some(ResponseNeed::More));
                    }
                    let varint_bytes = 1usize << (self.buf[0] >> 6);
                    if self.buf.len() < varint_bytes {
                        return Ok(Some(ResponseNeed::More));
                    }
                    let (len, used) = read_varint(&self.buf)?;
                    if len > MAX_TCP_RESPONSE_PADDING as u64 {
                        bail!("hy2 TCP response padding too long");
                    }
                    self.buf.advance(used);
                    self.step = ResponseStep::Pad { len: len as usize };
                }
                ResponseStep::Pad { len } => {
                    if self.buf.len() < len {
                        return Ok(Some(ResponseNeed::More));
                    }
                    self.buf.advance(len);
                    self.step = ResponseStep::Done;
                }
            }
        }
    }
}

impl Hy2TcpStream {
    fn new(send: quinn::SendStream, recv: quinn::RecvStream, request: Vec<u8>) -> Self {
        Self {
            send,
            recv,
            pending_request: Some(request),
            response: ResponseReader::new(),
        }
    }

    /// Drive the TCPResponse parse to completion, pulling from the stream as
    /// needed. `Ready(Ok(()))` means the response was consumed (any remote
    /// error is stored in `response.remote_error`).
    fn poll_response(&mut self, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        loop {
            match self.response.parse_step() {
                Ok(None) => return Poll::Ready(Ok(())),
                Ok(Some(ResponseNeed::More)) => {
                    let mut scratch = [0u8; 2048];
                    let mut read_buf = ReadBuf::new(&mut scratch);
                    match Pin::new(&mut self.recv).poll_read(cx, &mut read_buf) {
                        Poll::Ready(Ok(())) => {
                            let filled = read_buf.filled().len();
                            if filled == 0 {
                                return Poll::Ready(Err(new_io_other_error(
                                    "hy2 stream closed before TCP response",
                                )));
                            }
                            self.response.buf.put_slice(&scratch[..filled]);
                        }
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                        Poll::Pending => return Poll::Pending,
                    }
                }
                Err(e) => return Poll::Ready(Err(new_io_other_error(e.to_string()))),
            }
        }
    }
}

impl AsyncRead for Hy2TcpStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        // Surface a remote dial error once, then report EOF.
        if let Some(message) = self.response.remote_error.take() {
            if message.is_empty() {
                return Poll::Ready(Err(new_io_other_error("hy2 remote connection failed")));
            }
            return Poll::Ready(Err(new_io_other_error(format!(
                "hy2 remote error: {message}"
            ))));
        }
        if !self.response.is_done() {
            match self.poll_response(cx)? {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(()) => {}
            }
            if let Some(message) = self.response.remote_error.take() {
                if message.is_empty() {
                    return Poll::Ready(Err(new_io_other_error("hy2 remote connection failed")));
                }
                return Poll::Ready(Err(new_io_other_error(format!(
                    "hy2 remote error: {message}"
                ))));
            }
        }
        // The response parser may have over-read: any bytes buffered past
        // the response frame are payload and must be served first.
        let mut produced = false;
        if !self.response.buf.is_empty() {
            let n = self.response.buf.len().min(out.remaining());
            out.put_slice(&self.response.buf[..n]);
            self.response.buf.advance(n);
            produced = n > 0;
        }
        if out.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        // Never return Pending after bytes were placed in `out`: AsyncRead
        // callers (tokio's read helpers) assert that Pending yields no data.
        match Pin::new(&mut self.recv).poll_read(cx, out) {
            Poll::Ready(result) => Poll::Ready(result),
            Poll::Pending => {
                if produced {
                    Poll::Ready(Ok(()))
                } else {
                    Poll::Pending
                }
            }
        }
    }
}

impl AsyncWrite for Hy2TcpStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.pending_request.is_some() {
            // Fuse the TCPRequest prefix with the first payload write.
            let request = self.pending_request.take().unwrap();
            let mut write = Vec::with_capacity(request.len() + buf.len());
            write.extend_from_slice(&request);
            write.extend_from_slice(buf);
            let request_len = request.len();
            match Pin::new(&mut self.send)
                .poll_write(cx, &write)
                .map_err(io::Error::from)
            {
                Poll::Ready(Ok(n)) => {
                    if n == 0 {
                        self.pending_request = Some(request);
                        return Poll::Ready(Ok(0));
                    }
                    if n >= request_len {
                        return Poll::Ready(Ok(n - request_len));
                    }
                    // Partial write of the request prefix only.
                    self.pending_request = Some(request[n..].to_vec());
                    cx.waker().wake_by_ref();
                    return Poll::Pending;
                }
                Poll::Ready(Err(e)) => {
                    self.pending_request = Some(request);
                    return Poll::Ready(Err(e));
                }
                Poll::Pending => {
                    self.pending_request = Some(request);
                    return Poll::Pending;
                }
            }
        }
        Pin::new(&mut self.send)
            .poll_write(cx, buf)
            .map_err(io::Error::from)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        if self.pending_request.is_some() {
            // Nothing has been written yet.
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.send).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.send).poll_shutdown(cx)
    }
}

// ---------------------------------------------------------------------------
// Outbound
// ---------------------------------------------------------------------------

/// A cached authenticated QUIC connection plus its datagram listener task.
struct CachedHy2Conn {
    state: Arc<Hy2ConnState>,
    _listener: JoinHandle<()>,
}

pub struct Hysteria2Outbound {
    tag: String,
    address: TargetAddr,
    password: String,
    dns_server_name: Option<String>,
    bind_interface: Option<String>,
    connect_timeout: Duration,
    client_config: Arc<quinn::ClientConfig>,
    sni: String,
    cached: Arc<Mutex<Option<Arc<CachedHy2Conn>>>>,
    iface_reset_task: Option<JoinHandle<()>>,
}

impl Hysteria2Outbound {
    pub fn new(tag: String, cfg: &OutboundConfig) -> Result<Arc<dyn AnyOutbound>> {
        let address = cfg.endpoint(&tag)?;
        let password = cfg
            .password
            .clone()
            .context(format!("hysteria2 outbound '{}' requires password", tag))?;
        let tls = TlsConfig::from_outbound(cfg)?;
        let connect_timeout = cfg.connect_timeout();

        let default_sni = match &address {
            TargetAddr::Domain(domain, _) => Some(domain.clone()),
            TargetAddr::Ip(_) => None,
        };
        let sni = tls
            .sni
            .clone()
            .or(default_sni)
            .unwrap_or_else(|| "hysteria".to_string());

        let (client_config, _) = QuinnClient::build_client_config(
            cfg.idle_timeout(),
            !tls.insecure,
            false, // 0-RTT is not used
            tls.cert.as_deref(),
            Some(sni.clone()),
            Some(vec!["h3".to_string()]),
            cfg.congestion_controller.clone(),
            String::new(),
            String::new(),
            false, // hy2 never uses JLS
            cfg.gso,
            cfg.mtu_discoveriy,
            cfg.initial_mtu,
            cfg.min_mtu,
        )
        .with_context(|| format!("[{}] failed to build hy2 client config", tag))?;

        let cached: Arc<Mutex<Option<Arc<CachedHy2Conn>>>> = Arc::new(Mutex::new(None));
        let iface_reset_task = InterfaceManager::subscribe().map(|mut rx| {
            let cache = cached.clone();
            let tag = tag.clone();
            tokio::spawn(async move {
                loop {
                    match rx.recv().await {
                        Ok(()) => {
                            let mut lock = cache.lock().await;
                            if let Some(conn) = lock.take() {
                                info!("[{}] reset hy2 outbound because iface changed", tag);
                                conn.state.close();
                                conn._listener.abort();
                            }
                        }
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                            debug!("[{}] iface change watcher lagged by {} events", tag, n);
                        }
                        Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                    }
                }
            })
        });

        Ok(Arc::new(Self {
            tag,
            address,
            password,
            dns_server_name: cfg.dns.clone(),
            bind_interface: cfg.bind_interface.clone(),
            connect_timeout,
            client_config,
            sni,
            cached,
            iface_reset_task,
        }))
    }

    /// Establish (or reuse) an authenticated QUIC connection.
    async fn ensure_connection(&self) -> Result<Arc<Hy2ConnState>> {
        let mut lock = self.cached.lock().await;
        if let Some(conn) = lock.as_ref() {
            if conn.state.conn.close_reason().is_none() {
                return Ok(conn.state.clone());
            }
            warn!(
                "[{}] cached hy2 connection closed: {:?}",
                self.tag(),
                conn.state.conn.close_reason()
            );
            conn.state.close();
            conn._listener.abort();
        }

        match self.establish_connection().await {
            Ok(conn) => {
                info!(
                    "[{}] new hy2 quic connection to {}",
                    self.tag(),
                    conn.state.conn.remote_address()
                );
                let state = conn.state.clone();
                *lock = Some(conn);
                Ok(state)
            }
            Err(e) => {
                *lock = None;
                Err(e)
            }
        }
    }

    async fn establish_connection(&self) -> Result<Arc<CachedHy2Conn>> {
        let remote_addr = self.resolve_addr(&self.address).await?;
        let socket = self.new_udp_socket(remote_addr).await?;

        let client = QuinnClient::from_config(
            socket.into_std()?,
            self.client_config.clone(),
            self.sni.clone(),
            false,
            false,
        )
        .with_context(|| {
            format!(
                "[{}] failed to create QuinnClient (addr={} sni={})",
                self.tag(),
                remote_addr,
                self.sni
            )
        })?;

        let conn = tokio::time::timeout(self.connect_timeout, client.connect(remote_addr))
            .await
            .map_err(|_| {
                new_io_other_error(format!(
                    "[{}] hy2 connect timed out after {:?} to {}",
                    self.tag(),
                    self.connect_timeout,
                    remote_addr
                ))
            })?
            .map_err(|e| {
                new_io_other_error(format!(
                    "[{}] hy2 connect to {} failed: {:?}",
                    self.tag(),
                    remote_addr,
                    e
                ))
            })?;

        let (auth, control) = authenticate(&conn, &self.password, self.connect_timeout).await?;
        if auth.status != STATUS_AUTH_OK {
            bail!(
                "[{}] hy2 authentication failed with status {}",
                self.tag(),
                auth.status
            );
        }
        if !auth.udp_enabled {
            info!("[{}] hy2 server reported UDP disabled", self.tag());
        }

        let state = Arc::new(Hy2ConnState {
            conn: conn.clone(),
            _control: control,
            udp_enabled: auth.udp_enabled,
            next_session_id: AtomicU32::new(FIRST_SESSION_ID),
            datagram_routes: DashMap::new(),
            closed: Notify::new(),
        });
        let listener = tokio::spawn(run_datagram_listener(state.clone()));
        Ok(Arc::new(CachedHy2Conn {
            state,
            _listener: listener,
        }))
    }

    /// Open a TCP proxy stream, retrying once on a fresh connection when the
    /// cached one turns out to be dead.
    async fn open_bistream_with_retry(&self) -> Result<(quinn::SendStream, quinn::RecvStream)> {
        let state = self.ensure_connection().await?;
        match state.conn.open_bi().await {
            Ok(stream) => Ok(stream),
            Err(e) => {
                warn!(
                    "[{}] cached hy2 connection invalid (open_bi: {}), reconnecting",
                    self.tag(),
                    e
                );
                state.close();
                let mut lock = self.cached.lock().await;
                if let Some(cached) = lock.as_ref() {
                    if Arc::ptr_eq(&cached.state, &state) {
                        cached.state.close();
                        cached._listener.abort();
                        *lock = None;
                    }
                }
                let retry = self.ensure_connection().await?;
                retry.conn.open_bi().await.map_err(|e| {
                    anyhow::anyhow!(
                        "[{}] failed to open hy2 stream after reconnection: {}",
                        self.tag(),
                        e
                    )
                })
            }
        }
    }
}

#[async_trait]
impl AnyOutbound for Hysteria2Outbound {
    fn tag(&self) -> &str {
        &self.tag
    }

    fn protocol(&self) -> &str {
        "hysteria2"
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

    async fn connect_stream(&self, target: &TargetAddr) -> Result<AnyStream> {
        let request = encode_tcp_request(target);
        let (send, recv) = self.open_bistream_with_retry().await?;
        Ok(Box::new(Hy2TcpStream::new(send, recv, request)))
    }

    /// Not supported: the Hysteria2 TCP handshake embeds the destination, so
    /// a stream cannot be opened before the target is known. `connect_stream`
    /// is used instead.
    async fn connect_stream_base(&self) -> Result<AnyStream> {
        bail!("hysteria2 requires a destination; use connect_stream")
    }

    async fn connect_stream_with(
        &self,
        _target: &TargetAddr,
        _stream: AnyStream,
    ) -> Result<AnyStream> {
        bail!("hysteria2 requires a destination; use connect_stream")
    }

    async fn retry_connect_stream(&self, target: &TargetAddr) -> Result<AnyStream> {
        self.connect_stream(target).await
    }

    async fn connect_packet(&self, _target: &TargetAddr) -> Result<Arc<dyn AnyPacket>> {
        let state = self.ensure_connection().await?;
        if !state.udp_enabled {
            bail!("[{}] UDP disabled by hy2 server", self.tag());
        }
        let session_id = state
            .next_session_id
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |id| {
                if id == u32::MAX { None } else { Some(id + 1) }
            })
            .map_err(|_| anyhow::anyhow!("[{}] hy2 UDP session id space exhausted", self.tag()))?;

        let closer = Arc::new(SessionCloser::new());
        Ok(Hy2UdpSession::new(session_id, state, closer))
    }

    async fn get_uplink_state(&self) -> Option<PathState> {
        let state = self.ensure_connection().await.ok()?;
        let conn = &state.conn;
        let stats = conn.stats();
        Some(PathState {
            lost_packets: stats.path.lost_packets,
            sent_packets: stats.path.sent_packets,
            mtu: stats.path.current_mtu,
            rtt: conn.rtt().as_secs_f32() * 1000.0,
        })
    }

    async fn get_downlink_state(&self) -> Option<PathState> {
        None
    }
}

impl Drop for Hysteria2Outbound {
    fn drop(&mut self) {
        if let Some(handle) = self.iface_reset_task.take() {
            handle.abort();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn udp_message_roundtrip() {
        let message = UdpMessage {
            session_id: 0xdead_beef,
            packet_id: 0x1234,
            frag_id: 0,
            frag_count: 1,
            destination: "127.0.0.1:9999".to_string(),
            payload: Bytes::from_static(b"hello udp"),
        };
        let packed = message.pack();
        let parsed = parse_udp_message(&packed).unwrap();
        assert_eq!(parsed.session_id, message.session_id);
        assert_eq!(parsed.packet_id, message.packet_id);
        assert_eq!(parsed.frag_id, 0);
        assert_eq!(parsed.frag_count, 1);
        assert_eq!(parsed.destination, "127.0.0.1:9999");
        assert_eq!(&parsed.payload[..], b"hello udp");
    }

    #[test]
    fn fragmented_udp_packet_is_reassembled() {
        let mut defrag: hashbrown::HashMap<u16, Fragments> = hashbrown::HashMap::new();
        let base = UdpMessage {
            session_id: 7,
            packet_id: 0x77,
            frag_id: 0,
            frag_count: 3,
            destination: "example.com:53".to_string(),
            payload: Bytes::new(),
        };
        for (index, chunk) in [b"aaa".as_slice(), b"bbb", b"ccc"].iter().enumerate() {
            let message = UdpMessage {
                frag_id: index as u8,
                payload: Bytes::copy_from_slice(chunk),
                destination: base.destination.clone(),
                session_id: base.session_id,
                packet_id: base.packet_id,
                frag_count: base.frag_count,
            };
            let result = process_udp_datagram(message.pack(), &mut defrag).unwrap();
            if index < 2 {
                assert!(result.is_none(), "fragment {index} should not complete");
            } else {
                let (destination, data) = result.unwrap();
                assert_eq!(destination, "example.com:53");
                assert_eq!(&data[..], b"aaabbbccc");
            }
        }
    }

    #[test]
    fn tcp_request_encodes_0x401_type() {
        let target = TargetAddr::from_str("1.2.3.4:80").unwrap();
        let request = encode_tcp_request(&target);
        let (frame_type, used) = read_varint(&request).unwrap();
        assert_eq!(frame_type, TCP_REQUEST_TYPE);
        let (addr_len, used2) = read_varint(&request[used..]).unwrap();
        assert_eq!(addr_len as usize + used + used2 + 1, request.len());
    }

    /// Echo one TCP proxy stream through the eager TCP handshake over real
    /// quinn endpoints, verifying the payload is byte-exact at many sizes.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn tcp_stream_echo_is_byte_exact() {
        let _ = quinn::rustls::crypto::ring::default_provider().install_default();

        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let cert_der = cert.cert.der().clone();
        let key_der =
            quinn::rustls::pki_types::PrivateKeyDer::try_from(cert.signing_key.serialize_der())
                .unwrap();
        let mut rustls_server = quinn::rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der], key_der)
            .unwrap();
        rustls_server.alpn_protocols = vec![b"h3".to_vec()];
        let quic_server = quinn::ServerConfig::with_crypto(Arc::new(
            quinn::crypto::rustls::QuicServerConfig::try_from(rustls_server).unwrap(),
        ));

        let server_socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let server_addr = server_socket.local_addr().unwrap();
        let server_endpoint = quinn::Endpoint::new(
            quinn::EndpointConfig::default(),
            Some(quic_server),
            server_socket,
            quinn::default_runtime().unwrap(),
        )
        .unwrap();

        let server_task = tokio::spawn(async move {
            while let Some(incoming) = server_endpoint.accept().await {
                let conn = incoming.await.unwrap();
                tokio::spawn(async move {
                    loop {
                        let Ok((mut send, mut recv)) = conn.accept_bi().await else {
                            return;
                        };
                        tokio::spawn(async move {
                            // Read the full payload.
                            let mut all = Vec::new();
                            let mut buf = [0u8; 8192];
                            loop {
                                match recv.read(&mut buf).await {
                                    Ok(Some(n)) => all.extend_from_slice(&buf[..n]),
                                    Ok(None) => break,
                                    Err(_) => return,
                                }
                            }
                            // Strip the TCPRequest prefix.
                            let mut pos = 0usize;
                            let (_, used) = read_varint(&all[pos..]).unwrap();
                            pos += used;
                            let (addr_len, used) = read_varint(&all[pos..]).unwrap();
                            pos += used + addr_len as usize;
                            let (pad_len, used) = read_varint(&all[pos..]).unwrap();
                            pos += used + pad_len as usize;
                            let payload = &all[pos..];
                            // TCPResponse(status OK, empty msg, empty pad) +
                            // echoed payload.
                            let mut response = vec![0x00, 0x00, 0x00];
                            response.extend_from_slice(payload);
                            let _ = send.write_all(&response).await;
                            let _ = send.finish();
                        });
                    }
                });
            }
        });

        for size in [4096usize, 100_000, 300_000, 600_000, 1_000_000] {
            // Client endpoint.
            let (client_config, _) = QuinnClient::build_client_config(
                Duration::from_secs(30),
                false, // insecure
                false,
                None,
                Some("localhost".to_string()),
                Some(vec!["h3".to_string()]),
                None,
                String::new(),
                String::new(),
                false,
                false,
                false,
                1400,
                1400,
            )
            .unwrap();
            let client_socket = std::net::UdpSocket::bind("0.0.0.0:0").unwrap();
            let client_endpoint = quinn::Endpoint::new(
                quinn::EndpointConfig::default(),
                None,
                client_socket,
                quinn::default_runtime().unwrap(),
            )
            .unwrap();
            client_endpoint.set_default_client_config((*client_config).clone());
            let conn = client_endpoint
                .connect(server_addr, "localhost")
                .unwrap()
                .await
                .unwrap();

            let (send, recv) = conn.open_bi().await.unwrap();
            let target = TargetAddr::from_str("1.2.3.4:80").unwrap();
            let request = encode_tcp_request(&target);
            let mut stream = Hy2TcpStream::new(send, recv, request);
            let payload: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();

            // Request is fused into the first write; the response is
            // consumed on the first read.
            stream.write_all(&payload).await.unwrap();
            stream.shutdown().await.unwrap();
            let mut received = Vec::new();
            stream.read_to_end(&mut received).await.unwrap();
            assert_eq!(received, payload, "echo mismatch at size {size}");
            conn.close(0u32.into(), b"");
        }

        server_task.abort();
    }
}
