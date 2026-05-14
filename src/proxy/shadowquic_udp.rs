use anyhow::Context;
use anyhow::bail;
use async_trait::async_trait;
use bytes::Bytes;
use dashmap::DashMap;
use sha2::{Digest, Sha256};
use std::sync::Arc;
use std::time::Duration;
use std::time::Instant;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Mutex;
use tokio::sync::mpsc;
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::time::timeout;
use tracing::Instrument;
use tracing::debug;
use tracing::error;
use tracing::warn;

use crate::proxy::outbound::AnyPacket;
use crate::proxy::{SessionCloser, TargetAddr};
use crate::utils::format_duration;
use crate::utils::keyed_notify::KeyedNotify;
use crate::utils::new_io_other_error;
use crate::utils::now;
use crate::utils::quic_wrap::quinn_wrap::QuinnBistream;

use super::SourceAddr;

pub type UdpRecvMap = Arc<DashMap<u16, Arc<ShadowUdpReceiver>>>;
pub type WaitingDatagramBuffer = Arc<DashMap<u16, Arc<ShadowUdpDatagramBuffer>>>;

pub struct ShadowUdpDatagramBuffer {
    recveiver_sender: Sender<Bytes>,
    recveiver: Mutex<Receiver<Bytes>>,
}

impl ShadowUdpDatagramBuffer {
    pub fn new() -> Self {
        let (sender, recver) = mpsc::channel(10);

        Self {
            recveiver_sender: sender,
            recveiver: Mutex::new(recver),
        }
    }
}

pub struct ShadowUdpReceiver {
    recveiver_sender: Sender<(SourceAddr, Bytes)>, // feed packet to recver
    recveiver: Mutex<Receiver<(SourceAddr, Bytes)>>,

    udp_recv_map: UdpRecvMap,
    closer: Arc<SessionCloser>,

    create_at: Instant, // check for bistream delay but packet(unistream or datagram) had arrived
    is_binded_bistream: std::sync::atomic::AtomicBool,
}

impl ShadowUdpReceiver {
    pub fn new(udp_recv_map: UdpRecvMap) -> Self {
        let (sender, recver) = mpsc::channel(10);
        let closer = Arc::new(SessionCloser::new());

        Self {
            recveiver_sender: sender,
            recveiver: Mutex::new(recver),
            create_at: now(),
            udp_recv_map,
            is_binded_bistream: std::sync::atomic::AtomicBool::new(false),
            closer,
        }
    }

    // for udp OverStream
    pub fn run_unistream_worker(
        &self,
        unistream: Arc<Mutex<quinn::RecvStream>>,
        remote_src: TargetAddr,
        recv_context_id: u16,
    ) {
        let closer_clone = self.closer.clone();
        let sender_clone = self.recveiver_sender.clone();
        let udp_recv_map_clone = self.udp_recv_map.clone();
        debug!("accept_uni for udp session: {}", recv_context_id);
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = closer_clone.wait() => {
                        debug!("unistream_worker: recv closer signal, id: {}", recv_context_id);
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
                                if let Err(e) = sender_clone.send((remote_src.clone(), data)).await{
                                    closer_clone.close();
                                    error!("unistream failed to send packet to sender: {}, id: {}", e, recv_context_id);
                                    break;
                                }
                            }
                            Err(e) => {
                                debug!("unistream {} closed: {}", recv_context_id, e);
                                break;
                            }
                        }
                    }
                }
            }

            udp_recv_map_clone.remove(&recv_context_id);
            closer_clone.close();
        });
    }

    pub async fn feed_datagram(&self, payload: Bytes, remote_src: TargetAddr) {
        match self
            .recveiver_sender
            .send((remote_src.clone(), payload))
            .await
        {
            Ok(_) => {}
            Err(e) => {
                error!("failed to feed datagram: {}", e);
                self.closer.close();
            }
        }
    }
}

async fn read_addr_and_context_id(
    bistream: &mut QuinnBistream,
) -> anyhow::Result<(u16, TargetAddr)> {
    let target = TargetAddr::read_from(bistream).await?;
    let mut cid_buf = [0u8; 2];
    bistream.read_exact(&mut cid_buf).await?;
    let id = u16::from_be_bytes(cid_buf);
    Ok((id, target))
}

pub fn run_bistream_recv_listener(
    mut bistream: Box<QuinnBistream>,
    udp_recv_map: UdpRecvMap,
    shadowquic_receiver: Arc<ShadowUdpReceiver>,
    udp_recv_map_notify: Arc<KeyedNotify>,
    recv_context_id: Option<u16>,
) {
    let receiver_for_spawn = shadowquic_receiver.clone();
    let closer_clone = shadowquic_receiver.closer.clone();
    let udp_recv_map_clone = udp_recv_map.clone();
    shadowquic_receiver
        .is_binded_bistream
        .store(true, std::sync::atomic::Ordering::SeqCst);

    let mut context_ids: Vec<u16> = Vec::new();
    if let Some(recv_context_id) = recv_context_id {
        context_ids.push(recv_context_id);
        udp_recv_map_clone.insert(recv_context_id, receiver_for_spawn.clone());
        udp_recv_map_notify.notify(&recv_context_id.to_string());
    }

    let current_span = tracing::Span::current();

    tokio::spawn(
        async move {
            loop {
                tokio::select! {
                    _ = closer_clone.wait() => {
                        debug!("bistream recv loop: received closer signal");
                        break;
                    }
                    res = read_addr_and_context_id(&mut bistream) => {
                        match res {
                            Ok((id, _target)) => {
                                debug!("received context_id from bistream: {}", id);
                                if !context_ids.contains(&id) {
                                    udp_recv_map_clone.insert(id, receiver_for_spawn.clone());
                                    context_ids.push(id);
                                    udp_recv_map_notify.notify(&id.to_string());
                                }
                            }
                            Err(e) => {
                                error!("bistream read error: {:?}", e);
                                break;
                            }
                        }
                    }
                }
            }

            for id in context_ids {
                debug!("removing {} from udp_recv_map", id);
                udp_recv_map_clone.remove(&id);
                let id_string = id.to_string();
                udp_recv_map_notify.notify(&id_string);
                udp_recv_map_notify.remove(&id_string);
            }
            debug!("bistream recv loop ended");
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
                if !receiver
                    .is_binded_bistream
                    .load(std::sync::atomic::Ordering::SeqCst)
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
            let remote_src = TargetAddr::Ip(conn.remote_address());
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

                            item.run_unistream_worker(
                                Arc::new(Mutex::new(recv)),
                                remote_src.clone(),
                                recv_context_id,
                            );

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
    datagram_sender_rx: flume::Receiver<Bytes>,
) {
    tokio::spawn(async move {
        let remote_src = TargetAddr::Ip(conn.remote_address());
        loop {
            tokio::select! {
                res = conn.read_datagram() => {
                    match res {
                        Ok(datagram) => {
                            if let Err(e) = handle_datagram(
                                udp_recv_map.clone(),
                                udp_recv_map_notify.clone(),
                                waiting_datagram_buffer.clone(),
                                datagram,
                                remote_src.clone(),
                            ).await {
                                debug!("handle_datagram error: {}", e);
                            }
                        }
                        Err(e) => {
                            debug!("read_datagram failed, connection closed: {}", e);
                            break;
                        }
                    }
                }
                payload = datagram_sender_rx.recv_async() => {
                    match payload {
                        Ok(datagram) => {
                            if let Err(e) = conn.send_datagram(datagram) {
                                warn!("send_datagram_wait failed: {}", e);
                            }
                        }
                        Err(e) => {
                            error!("datagram_sender_rx.recv_async error: {}", e);
                            break;
                        }
                    }
                }
            }
        }
    });
}

async fn handle_datagram(
    udp_recv_map: UdpRecvMap,
    udp_recv_map_notify: Arc<KeyedNotify>,
    waiting_datagram_buffer: WaitingDatagramBuffer,
    datagram: Bytes,
    remote_src: TargetAddr,
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

    let mut is_new = false;

    let item = waiting_datagram_buffer
        .entry(recv_context_id)
        .or_insert_with(|| {
            is_new = true;
            Arc::new(ShadowUdpDatagramBuffer::new())
        })
        .clone();

    let _ = item.recveiver_sender.send(Bytes::from(payload)).await;
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
            let addr_clone = remote_src.clone();

            loop {
                let addr_clone = addr_clone.clone();
                tokio::select! {
                    _ = closer.wait() => {
                        break;
                    }
                    payload = lock.recv() => {
                        if let Some(payload) = payload {
                            item.feed_datagram(payload, addr_clone).await;
                        }else{
                            break;
                        }
                    }
                }
            }

            Ok(())
        }
        .await;

        waiting_datagram_buffer.remove(&recv_context_id);

        // 处理错误
        if let Err(e) = result {
            eprintln!("Task failed: {}", e);
        }
    });

    Ok(())
}

pub struct ShadowQuicUdpPacket {
    send_unistream: Option<Arc<Mutex<quinn::SendStream>>>,
    datagram_sender_tx: Option<flume::Sender<Bytes>>,

    send_context_id: u16,
    target: TargetAddr,

    receiver: Arc<ShadowUdpReceiver>,
}

impl ShadowQuicUdpPacket {
    pub fn new(
        send_unistream: Option<Arc<Mutex<quinn::SendStream>>>,
        datagram_sender_tx: Option<flume::Sender<Bytes>>,
        send_context_id: u16,
        target: TargetAddr,

        receiver: Arc<ShadowUdpReceiver>,
    ) -> Self {
        Self {
            send_unistream,
            datagram_sender_tx,
            send_context_id,
            target,
            receiver,
        }
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
        _target: &TargetAddr,
        _from: &SourceAddr,
    ) -> anyhow::Result<usize> {
        if let Some(stream) = &self.send_unistream {
            let mut stream = stream.lock().await;
            let mut packet = Vec::with_capacity(2 + buf.len());
            packet.extend_from_slice(&(buf.len() as u16).to_be_bytes());
            packet.extend_from_slice(&buf);
            stream.write_all(&packet).await?;
            stream.flush().await?;
            return Ok(buf.len());
        }

        if let Some(sender) = &self.datagram_sender_tx {
            let mut packet = Vec::with_capacity(2 + buf.len());
            packet.extend_from_slice(&self.send_context_id.to_be_bytes());
            packet.extend_from_slice(&buf);
            if sender.send_async(Bytes::from(packet)).await.is_err() {
                warn!("datagram send queue closed");
            }
        }
        Ok(buf.len())
    }

    async fn recv_from(&self) -> anyhow::Result<(SourceAddr, TargetAddr, Bytes)> {
        let mut rx = self.receiver.recveiver.lock().await;

        match rx.recv().await {
            Some(packet) => {
                let dst = self.target.clone();
                Ok((packet.0, dst, packet.1))
            }
            None => Err(new_io_other_error("recv_from closed.").into()),
        }
    }
}

pub struct ShadowQuicUdpOverBistream {
    recv: Mutex<quinn::RecvStream>,
    send: Mutex<quinn::SendStream>,
    target: TargetAddr,
    closer: Arc<SessionCloser>,
}

impl ShadowQuicUdpOverBistream {
    pub fn new(
        recv: Mutex<quinn::RecvStream>,
        send: Mutex<quinn::SendStream>,
        target: TargetAddr,
        closer: Arc<SessionCloser>,
    ) -> Self {
        Self {
            recv,
            send,
            target,
            closer,
        }
    }
}

#[async_trait]
impl AnyPacket for ShadowQuicUdpOverBistream {
    fn closer(&self) -> Arc<SessionCloser> {
        self.closer.clone()
    }

    async fn send_to(
        &self,
        buf: Bytes,
        _target: &TargetAddr,
        _from: &SourceAddr,
    ) -> anyhow::Result<usize> {
        let mut stream = self.send.lock().await;

        let mut packet = Vec::with_capacity(2 + buf.len());
        packet.extend_from_slice(&(buf.len() as u16).to_be_bytes());
        packet.extend_from_slice(&buf);
        stream.write_all(&packet).await?;
        stream.flush().await?;
        Ok(buf.len())
    }

    async fn recv_from(&self) -> anyhow::Result<(TargetAddr, TargetAddr, Bytes)> {
        let mut stream = self.recv.lock().await;

        let mut len_buf = [0u8; 2];
        let l = match stream.read_exact(&mut len_buf).await {
            Ok(_) => u16::from_be_bytes(len_buf),
            Err(e) => return Err(new_io_other_error(e.to_string()).into()),
        };
        let mut payload = Vec::with_capacity(l as usize);

        stream
            .read_exact(&mut payload)
            .await
            .map_err(|e| new_io_other_error(e.to_string()))?;

        let dummy_target = TargetAddr::dummy();
        Ok((self.target.clone(), dummy_target, Bytes::from(payload)))
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
