use anyhow::Context;
use anyhow::bail;
use async_trait::async_trait;
use bytes::Bytes;
use dashmap::DashMap;
use sha2::{Digest, Sha256};
use std::sync::Arc;
use std::sync::atomic::AtomicU16;
use std::sync::atomic::Ordering;
use std::time::Duration;
use std::time::Instant;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Mutex;
use tokio::sync::mpsc;
use tokio::sync::mpsc::UnboundedReceiver;
use tokio::sync::mpsc::UnboundedSender;
use tokio::time::timeout;
use tracing::Instrument;
use tracing::debug;
use tracing::error;
use tracing::warn;

use crate::proxy::outbound::{AnyPacket, PacketInfo};
use crate::proxy::{SessionCloser, TargetAddr};
use crate::utils::format_duration;
use crate::utils::keyed_notify::KeyedNotify;
use crate::utils::new_io_other_error;
use crate::utils::now;
use crate::utils::quic_wrap::quinn_wrap::QuinnBistream;

use super::SourceAddr;

pub type UdpRecvMap = Arc<DashMap<u16, Arc<ShadowUdpReceiver>>>;
pub type WaitingDatagramBuffer = Arc<DashMap<u16, Arc<ShadowUdpDatagramBuffer>>>;
pub type SenderMapItem = (u16, Option<Arc<Mutex<quinn::SendStream>>>);

pub struct PerConnectionState {
    pub next_context_id: Arc<AtomicU16>,
    pub udp_recv_map: UdpRecvMap,
    pub udp_recv_map_notify: Arc<KeyedNotify>,
    pub waiting_datagram_buffer: WaitingDatagramBuffer,
}

impl PerConnectionState {
    pub fn new() -> Self {
        let udp_recv_map: UdpRecvMap = Arc::new(DashMap::new());
        Self {
            next_context_id: Arc::new(AtomicU16::new(1)),
            udp_recv_map,
            udp_recv_map_notify: Arc::new(KeyedNotify::new()),
            waiting_datagram_buffer: Arc::new(DashMap::new()),
        }
    }
}

pub struct ShadowUdpDatagramBuffer {
    recveiver_sender: UnboundedSender<Bytes>,
    recveiver: Mutex<UnboundedReceiver<Bytes>>,
}

impl ShadowUdpDatagramBuffer {
    pub fn new() -> Self {
        let (sender, recver) = mpsc::unbounded_channel();

        Self {
            recveiver_sender: sender,
            recveiver: Mutex::new(recver),
        }
    }
}

pub struct ShadowUdpReceiver {
    recveiver_sender: UnboundedSender<(TargetAddr, Bytes)>,
    recveiver: Mutex<UnboundedReceiver<(TargetAddr, Bytes)>>,

    binded_coontext_id: DashMap<u16, TargetAddr>,
    udp_recv_map_notify: Arc<KeyedNotify>,

    udp_recv_map: UdpRecvMap,
    closer: Arc<SessionCloser>,

    create_at: Instant, // check for bistream delay but packet(unistream or datagram) had arrived
}

impl ShadowUdpReceiver {
    pub fn new(udp_recv_map: UdpRecvMap, udp_recv_map_notify: Arc<KeyedNotify>) -> Self {
        let (sender, recver) = mpsc::unbounded_channel();
        let closer = Arc::new(SessionCloser::new());

        Self {
            recveiver_sender: sender,
            recveiver: Mutex::new(recver),
            create_at: now(),
            udp_recv_map,
            binded_coontext_id: DashMap::new(),
            udp_recv_map_notify,
            closer,
        }
    }

    // for udp OverStream
    pub fn run_unistream_worker(
        &self,
        unistream: Arc<Mutex<quinn::RecvStream>>,
        context_id: u16,
    ) -> anyhow::Result<()> {
        let remote_src = match self.binded_coontext_id.get(&context_id) {
            Some(r) => r,
            None => bail!("can not find binded context_id"),
        };
        let closer_clone = self.closer.clone();
        let sender_clone = self.recveiver_sender.clone();
        let udp_recv_map_clone = self.udp_recv_map.clone();
        let remote_src = remote_src.clone();
        debug!("accept_uni for udp session: {}", context_id);
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = closer_clone.wait() => {
                        break;
                    }

                    res = async {
                        let mut lock = unistream.lock().await;

                        let mut len_buf = [0u8; 2];
                        lock.read_exact(&mut len_buf).await?;
                        let len = u16::from_be_bytes(len_buf);

                        let mut payload = vec![0u8; len as usize];
                        lock.read_exact(&mut payload).await?;

                        Ok::<Bytes, anyhow::Error>(Bytes::from(payload))
                    } => {
                        match res {
                            Ok(data) => {
                                if let Err(e) = sender_clone.send((remote_src.clone(), data)) {
                                    closer_clone.close();
                                    error!("unistream failed to send packet to sender: {}, id: {}", e, context_id);
                                    break;
                                }
                            }
                            Err(e) => {
                                debug!("unistream {} closed: {}", context_id, e);
                                break;
                            }
                        }
                    }
                }
            }

            debug!("unistream_worker {} closed", context_id);
            udp_recv_map_clone.remove(&context_id);
            closer_clone.close();
        });

        Ok(())
    }

    pub fn feed_datagram(&self, payload: Bytes, context_id: u16) -> anyhow::Result<()> {
        if let Some(target) = self.binded_coontext_id.get(&context_id) {
            match self.recveiver_sender.send((target.clone(), payload)) {
                Ok(_) => {}
                Err(e) => {
                    self.closer.close();
                    bail!("failed to feed datagram: {}", e);
                }
            };
        } else {
            bail!("can not feed_datagram to a unknow context_id");
        }

        Ok(())
    }

    pub fn bind_context_id(
        &self,
        target: TargetAddr,
        context_id: u16,
        myself: Arc<ShadowUdpReceiver>,
    ) {
        self.binded_coontext_id.insert(context_id, target.clone());
        self.udp_recv_map.insert(context_id, myself);
        self.udp_recv_map_notify.notify(&context_id.to_string());
        debug!("receive context_id {} with address {}", context_id, target);
    }

    pub fn clean(&self) {
        let keys: Vec<u16> = self
            .binded_coontext_id
            .iter()
            .map(|item| *item.key())
            .collect();

        for item in keys {
            self.udp_recv_map_notify.notify(&item.to_string());
            self.udp_recv_map.remove(&item);
            debug!("removing context_id {} from UdpRecvMap", item);
        }
    }
}

async fn read_addr_and_context_id(
    recv: &mut quinn::RecvStream,
) -> anyhow::Result<(u16, TargetAddr)> {
    let target = TargetAddr::read_from(recv).await?;
    let mut cid_buf = [0u8; 2];
    recv.read_exact(&mut cid_buf).await?;
    let id = u16::from_be_bytes(cid_buf);
    Ok((id, target))
}

pub fn run_bistream_recv_listener(mut recv: quinn::RecvStream, receiver: Arc<ShadowUdpReceiver>) {
    let receiver_for_spawn = receiver.clone();
    let closer_clone = receiver.closer.clone();

    let current_span = tracing::Span::current();

    tokio::spawn(
        async move {
            loop {
                tokio::select! {
                    _ = closer_clone.wait() => {
                        debug!("recv loop: received closer signal");
                        break;
                    }
                    res = read_addr_and_context_id(&mut recv) => {
                        match res {
                            Ok((id, source)) => {
                                receiver_for_spawn.bind_context_id(source, id, receiver_for_spawn.clone());
                            }
                            Err(e) => {
                                error!("recv read error: {}", e);
                                break;
                            }
                        }
                    }
                }
            }

            receiver_for_spawn.clean();
            debug!("control_bistream loop ended");
            closer_clone.close();
        }
        .instrument(current_span),
    );
}

pub fn start_udp_session_cleaner(
    udp_recv_map: UdpRecvMap,
    check_interval: Duration,
    timeout: Duration,
) {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(check_interval).await;

            let mut expired_ids = Vec::new();

            for entry in udp_recv_map.iter() {
                let receiver = entry.value();
                if receiver.binded_coontext_id.len() == 0
                    && now().duration_since(receiver.create_at) >= timeout
                {
                    expired_ids.push(*entry.key());
                }
            }

            for id in expired_ids {
                debug!("clean context_id {}", id);
                if let Some((_, receiver)) = udp_recv_map.remove(&id) {
                    receiver.closer.close();
                }
            }
        }
    });
}

async fn get_receiver(
    udp_recv_map: UdpRecvMap,
    context_id: u16,
    keyed_notify: Arc<KeyedNotify>,
) -> anyhow::Result<Arc<ShadowUdpReceiver>> {
    if let Some(entry) = udp_recv_map.get(&context_id) {
        return Ok(entry.value().clone());
    }

    let start_time = now();
    keyed_notify
        .wait(&context_id.to_string(), Duration::from_secs(10))
        .await?;

    if let Some(entry) = udp_recv_map.get(&context_id) {
        debug!(
            "get_receiver id {} cost: {}",
            context_id,
            format_duration(start_time.elapsed())
        );
        return Ok(entry.value().clone());
    }
    bail!("failed to get_receiver");
}

pub fn start_unistream_listener(
    conn: Arc<quinn::Connection>,
    udp_recv_map: UdpRecvMap,
    udp_recv_map_notify: Arc<KeyedNotify>,
    read_timeout: Duration,
) {
    tokio::spawn(async move {
        loop {
            match conn.accept_uni().await {
                Ok(mut recv) => {
                    let recv_map_clone = udp_recv_map.clone();
                    let recv_map_notify_clone = udp_recv_map_notify.clone();

                    tokio::spawn(async move {
                        let res: anyhow::Result<()> = async {
                            let recv_context_id =
                                try_get_recv_context_id(&mut recv, read_timeout).await?;
                            let item = get_receiver(
                                recv_map_clone,
                                recv_context_id,
                                recv_map_notify_clone,
                            )
                            .await?;

                            item.run_unistream_worker(Arc::new(Mutex::new(recv)), recv_context_id)?;

                            Ok(())
                        }
                        .await;

                        if let Err(e) = res {
                            error!("unistream worker error: {:#}", e);
                        }
                    });
                }
                Err(e) => {
                    debug!("accept_uni failed, connection closed: {}", e);
                    break;
                }
            }
        }
    });
}

async fn try_get_recv_context_id(
    recv: &mut quinn::RecvStream,
    read_timeout: Duration,
) -> anyhow::Result<u16> {
    let mut buf = [0u8; 2];
    timeout(read_timeout, recv.read_exact(&mut buf))
        .await
        .context("read recv_context_id timed out")?
        .context("read recv_context_id failed")?;
    Ok(u16::from_be_bytes(buf))
}

pub fn start_datagram_loop(
    conn: Arc<quinn::Connection>,
    udp_recv_map: UdpRecvMap,
    waiting_datagram_buffer: WaitingDatagramBuffer,
    udp_recv_map_notify: Arc<KeyedNotify>,
) {
    let conn = conn.clone();
    let udp_recv_map = udp_recv_map.clone();
    let waiting_datagram_buffer = waiting_datagram_buffer.clone();
    let udp_recv_map_notify = udp_recv_map_notify.clone();

    tokio::spawn(async move {
        loop {
            match conn.read_datagram().await {
                Ok(datagram) => {
                    if let Err(e) = handle_datagram(
                        udp_recv_map.clone(),
                        udp_recv_map_notify.clone(),
                        waiting_datagram_buffer.clone(),
                        datagram,
                    ) {
                        debug!("handle_datagram error: {}", e);
                    }
                }
                Err(e) => {
                    debug!("read_datagram failed, connection closed: {}", e);
                    break;
                }
            }
        }
    });
}

fn handle_datagram(
    udp_recv_map: UdpRecvMap,
    udp_recv_map_notify: Arc<KeyedNotify>,
    waiting_datagram_buffer: WaitingDatagramBuffer,
    datagram: Bytes,
) -> anyhow::Result<()> {
    if datagram.len() <= 2 {
        warn!("Received invalid shadowquic datagram, ignored");
        return Ok(());
    }

    let recv_context_id = u16::from_be_bytes(
        datagram[..2]
            .try_into()
            .map_err(|_| anyhow::anyhow!("Invalid datagram length for context_id"))?,
    );

    let payload = datagram.slice(2..);

    if let Some(item) = udp_recv_map.get(&recv_context_id) {
        return item.feed_datagram(payload, recv_context_id);
    }

    let mut is_new = false;

    let item = waiting_datagram_buffer
        .entry(recv_context_id)
        .or_insert_with(|| {
            is_new = true;
            Arc::new(ShadowUdpDatagramBuffer::new())
        })
        .clone();

    if let Err(e) = item.recveiver_sender.send(Bytes::from(payload)) {
        waiting_datagram_buffer.remove(&recv_context_id);
        bail!("datagram sender {} closed: {}", recv_context_id, e);
    }
    if !is_new {
        return Ok(());
    }

    let item_clone = item.clone();

    tokio::spawn(async move {
        let result: anyhow::Result<()> = async {
            let item = get_receiver(
                udp_recv_map.clone(),
                recv_context_id,
                udp_recv_map_notify.clone(),
            )
            .await?;

            let closer = item.closer.clone();
            let mut lock = item_clone.recveiver.lock().await;

            loop {
                tokio::select! {
                    _ = closer.wait() => {
                        break;
                    }
                    payload = lock.recv() => {
                        if let Some(payload) = payload {
                            if let Err(e) = item.feed_datagram(payload, recv_context_id) {
                                error!("feed_datagram: {}", e);
                                break;
                            }
                        }else{
                            break;
                        }
                    }
                }
            }

            Ok(())
        }
        .await;

        debug!("datagram {} handler loop closed", recv_context_id);
        waiting_datagram_buffer.remove(&recv_context_id);

        if let Err(e) = result {
            eprintln!("Task failed: {}", e);
        }
    });

    Ok(())
}

pub struct ShadowQuicUdpPacket {
    sender_map: DashMap<SourceAddr, SenderMapItem>,
    is_over_unistream: bool,
    is_client: bool,

    conn: Arc<quinn::Connection>,
    control_stream: Arc<Mutex<quinn::SendStream>>,
    next_context_id: Arc<AtomicU16>,

    receiver: Arc<ShadowUdpReceiver>,
}

impl ShadowQuicUdpPacket {
    pub fn new(
        is_over_unistream: bool,
        is_client: bool,
        receiver: Arc<ShadowUdpReceiver>,
        next_context_id: Arc<AtomicU16>,
        control_stream: Arc<Mutex<quinn::SendStream>>,
        conn: Arc<quinn::Connection>,
    ) -> Self {
        Self {
            sender_map: DashMap::new(),
            is_over_unistream,
            is_client,
            control_stream,
            next_context_id,
            receiver,
            conn,
        }
    }

    pub async fn build_sender(
        &self,
        send_context_id: u16,
        target: &SourceAddr,
    ) -> anyhow::Result<()> {
        let mut lock = self.control_stream.lock().await;

        let target_bytes = target.to_bytes();
        let mut packet = Vec::with_capacity(target_bytes.len() + 2);
        packet.extend_from_slice(&target_bytes);
        packet.extend_from_slice(&send_context_id.to_be_bytes());
        lock.write_all(&packet).await?;
        lock.flush().await?;

        if self.is_over_unistream {
            let uni_send = self.conn.open_uni().await?;

            let send_mutex = Arc::new(Mutex::new(uni_send));
            {
                let mut lock = send_mutex.lock().await;
                lock.write_all(&send_context_id.to_be_bytes()).await?;
                lock.flush().await?;
            }
            self.sender_map
                .insert(target.clone(), (send_context_id, Some(send_mutex)));
        } else {
            self.sender_map
                .insert(target.clone(), (send_context_id, None));
        }
        Ok(())
    }

    pub async fn get_send_context_id(&self, target: &SourceAddr) -> anyhow::Result<SenderMapItem> {
        if let Some(unistream) = self.sender_map.get(&target) {
            return Ok(unistream.clone());
        }

        let send_context_id = self.next_context_id.fetch_add(1, Ordering::SeqCst);
        self.build_sender(send_context_id, target).await?;

        if let Some(unistream) = self.sender_map.get(&target) {
            return Ok(unistream.clone());
        }
        bail!("failed to init sender.");
    }
}

#[async_trait]
impl AnyPacket for ShadowQuicUdpPacket {
    fn closer(&self) -> Arc<SessionCloser> {
        self.receiver.closer.clone()
    }

    async fn send_to(
        &self,
        buf: Bytes,
        from: &SourceAddr,
        target: &TargetAddr,
    ) -> anyhow::Result<usize> {
        let mut context_addr = from;
        if self.is_client {
            context_addr = target;
        }
        if self.is_over_unistream {
            let (_, lock) = self.get_send_context_id(context_addr).await?;
            let lock = lock.expect("should be unistream");
            let mut stream = lock.lock().await;
            let mut packet = Vec::with_capacity(2 + buf.len());
            packet.extend_from_slice(&(buf.len() as u16).to_be_bytes());
            packet.extend_from_slice(&buf);
            stream.write_all(&packet).await?;
            stream.flush().await?;
            return Ok(buf.len());
        }

        let (send_context_id, _) = self.get_send_context_id(context_addr).await?;
        let mut packet = Vec::with_capacity(2 + buf.len());
        packet.extend_from_slice(&send_context_id.to_be_bytes());
        packet.extend_from_slice(&buf);
        // self.conn.send_datagram_wait(Bytes::from(packet));
        if let Err(e) = self.conn.send_datagram(Bytes::from(packet)) {
            warn!("send_datagram: {}", e);
        }
        Ok(buf.len())
    }

    async fn recv_many(&self) -> anyhow::Result<Vec<PacketInfo>> {
        let mut rx = self.receiver.recveiver.lock().await;

        let mut buffer = Vec::new();
        let _left = rx.recv_many(&mut buffer, 10).await;
        let mut results = Vec::with_capacity(buffer.len());
        for item in buffer {
            if self.is_client {
                results.push((item.0, TargetAddr::dummy(), item.1));
            } else {
                results.push((TargetAddr::Ip(self.conn.remote_address()), item.0, item.1));
            }
        }
        Ok(results)
    }

    async fn recv_from(&self) -> anyhow::Result<PacketInfo> {
        let mut rx = self.receiver.recveiver.lock().await;

        match rx.recv().await {
            Some(item) => {
                if self.is_client {
                    Ok((item.0, TargetAddr::dummy(), item.1))
                } else {
                    Ok((TargetAddr::Ip(self.conn.remote_address()), item.0, item.1))
                }
            }
            None => bail!("recv_from closed."),
        }
    }
}

pub async fn read_context_id(
    bistream: &mut QuinnBistream,
    duration: Duration,
) -> std::io::Result<u16> {
    let mut buf = [0u8; 2];
    match timeout(duration, bistream.read_exact(&mut buf)).await {
        Ok(Ok(_)) => Ok(u16::from_be_bytes(buf)),
        Ok(Err(e)) => Err(e),
        Err(e) => Err(new_io_other_error(e)),
    }
}

pub static SUNNY_QUIC_AUTH_LEN: usize = 64;
pub type SunnyCredential = Arc<[u8; SUNNY_QUIC_AUTH_LEN]>;

pub fn gen_sunny_auth_hash(username: &str, password: &str) -> [u8; 64] {
    let hash_in = format!("{}:{}", username, password);

    let hash_out = Sha256::digest(hash_in.as_bytes());

    let mut arr = [0u8; SUNNY_QUIC_AUTH_LEN];
    let hash_bytes = hash_out.as_slice();

    let len = arr.len().min(hash_bytes.len());
    arr[..len].copy_from_slice(&hash_bytes[..len]);

    arr
}

pub async fn auth_sunnyquic(
    bistream: &mut QuinnBistream,
    expected_hash: [u8; 64],
    duration: Duration,
) -> anyhow::Result<()> {
    let handshake = async {
        let mut cmd_buf = [0u8; 1];
        bistream.read_exact(&mut cmd_buf).await?;
        let cmd = cmd_buf[0];
        if cmd != 0x5 {
            bail!("auth requires cmd == 0x05")
        }
        let mut received_hash = [0u8; 64];
        bistream.read_exact(&mut received_hash).await?;
        if received_hash != expected_hash {
            bail!("Invalid auth hash")
        }

        Ok(())
    };

    match timeout(duration, handshake).await {
        Ok(result) => result,
        Err(e) => bail!(e),
    }
}

pub async fn read_request_head(
    bistream: &mut QuinnBistream,
    duration: Duration,
) -> anyhow::Result<(u8, TargetAddr)> {
    let handshake = async {
        let mut cmd_buf = [0u8; 1];
        bistream.read_exact(&mut cmd_buf).await?;
        let cmd = cmd_buf[0];

        // Extension request: no target address follows
        if cmd == 0xFF {
            return Ok((cmd, TargetAddr::dummy()));
        }

        let mut target = TargetAddr::read_from(bistream).await?;

        // UDP 协议需要读取 dummy target
        if matches!(cmd, 0x03 | 0x04) {
            target = TargetAddr::read_from(bistream).await?;
        }

        Ok((cmd, target))
    };

    timeout(duration, handshake)
        .await
        .context("Handshake timeout")?
}

/// Decoded extension request from the shadowquic extension protocol.
#[derive(Debug)]
pub enum ExtensionRequest {
    /// `ExtOpcodeConn::GetConnStats` (tag 0x00)
    GetConnStats,
    /// `SQExtOpcode::User` (tag 0x02) — unsupported, respond with NotAvailable
    UserExtension,
    /// Unknown opcode — respond with NotAvailable
    Unknown,
}

/// Read an extension request from a bistream. The command byte `0xFF` has already
/// been consumed by `read_request_head`. This reads:
/// - `u64` BE: `SQExtOpcode` discriminant (1 = Conn, 2 = User)
/// - For Conn: `u8` `ExtOpcodeConn` discriminant (0 = GetConnStats)
pub async fn read_extension_request(
    bistream: &mut QuinnBistream,
    duration: Duration,
) -> anyhow::Result<ExtensionRequest> {
    timeout(duration, async {
        let opcode = bistream.read_u64().await?;
        match opcode {
            // SQExtOpcode::Conn
            1 => {
                let conn_opcode = bistream.read_u8().await?;
                match conn_opcode {
                    0x00 => Ok(ExtensionRequest::GetConnStats),
                    _ => Ok(ExtensionRequest::Unknown),
                }
            }
            // SQExtOpcode::User
            2 => Ok(ExtensionRequest::UserExtension),
            _ => Ok(ExtensionRequest::Unknown),
        }
    })
    .await
    .context("Extension request timeout")?
}

/// Write a `Result<ConnStats, SQExtError>` response.
///
/// Wire format:
/// - `0x00` (Ok) + ConnStats: `u32` BE size (26) + `u64` lost + `u64` sent + `f64` rtt_ms + `u16` mtu
/// - `0x01` (Err) + SQExtError tag (`u8`): 0 = NotAvailable, 1 = PermissionDenied, 2 = NotFound
pub async fn write_conn_stats_response(
    send: &mut quinn::SendStream,
    lost_packets: u64,
    sent_packets: u64,
    rtt_ms: f64,
    current_mtu: u16,
) -> anyhow::Result<()> {
    // Result::Ok tag
    send.write_u8(0x00).await?;
    // ConnStats size tag (#[size_tag]): 8 + 8 + 8 + 2 = 26 bytes
    send.write_u32(26).await?;
    send.write_u64(lost_packets).await?;
    send.write_u64(sent_packets).await?;
    send.write_f64(rtt_ms).await?;
    send.write_u16(current_mtu).await?;
    Ok(())
}

/// Write an error response: `Result::Err(SQExtError::NotAvailable)`.
/// Wire format: `0x01` (Err tag) + `0x00` (NotAvailable tag).
pub async fn write_ext_error_not_available(send: &mut quinn::SendStream) -> anyhow::Result<()> {
    send.write_u8(0x01).await?; // Result::Err tag
    send.write_u8(0x00).await?; // SQExtError::NotAvailable
    Ok(())
}
