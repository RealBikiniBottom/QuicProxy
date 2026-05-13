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
use tokio::sync::Notify;
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
use crate::utils::id::Id32;
use crate::utils::new_io_other_error;
use crate::utils::now;
use crate::utils::quic_wrap::quinn_wrap::QuinnBistream;

use super::SourceAddr;

pub type UdpRecvMap = Arc<DashMap<String, Arc<ShadowUdpReceiver>>>;

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
        recv_context_id: String,
    ) {
        let closer_clone = self.closer.clone();
        let sender_clone = self.recveiver_sender.clone();
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
    recv_context_id: String,
) {
    let receiver_for_spawn = shadowquic_receiver.clone();
    let closer_clone = shadowquic_receiver.closer.clone();
    let udp_recv_map_clone = udp_recv_map.clone();
    shadowquic_receiver
        .is_binded_bistream
        .store(true, std::sync::atomic::Ordering::SeqCst);

    let mut context_ids: Vec<String> = Vec::new();
    if !recv_context_id.is_empty() {
        context_ids.push(recv_context_id.clone());
        udp_recv_map_clone.insert(recv_context_id, receiver_for_spawn.clone());
    }

    let current_span = tracing::Span::current();

    tokio::spawn(
        async move {
            let mut buf = [0u8; 1];
            loop {
                tokio::select! {
                    _ = closer_clone.wait() => {
                        debug!("bistream recv loop: received closer signal");
                        break;
                    }
                    res = bistream.read_exact(&mut buf) => {
                        match res {
                            Ok(_) => {
                            }
                            Err(e) => {
                                error!("bistream read error: {:?}", e);
                                break;
                            }
                        }
                    }
                    // res = read_addr_and_context_id(&mut bistream) => {
                    //     match res {
                    //         Ok((id, _target)) => {
                    //             debug!("received context_id from bistream: {}", id);
                    //             if !context_ids.contains(&id) {
                    //                 udp_recv_map_clone.insert(id, receiver_for_spawn.clone());
                    //                 context_ids.push(id);
                    //             }
                    //         }
                    //         Err(e) => {
                    //             error!("bistream read error: {:?}", e);
                    //             break;
                    //         }
                    //     }
                    // }
                }
            }

            for id in context_ids {
                debug!("removing {} from udp_recv_map", id);
                udp_recv_map_clone.remove(&id);
            }
            debug!("bistream recv loop ended");
            closer_clone.close();
        }
        .instrument(current_span),
    );
}

pub fn start_unistream_listener(
    conn: Arc<quinn::Connection>,
    udp_recv_map: UdpRecvMap,
    read_timeout: Duration,
) {
    tokio::spawn(async move {
        loop {
            let remote_src = TargetAddr::Ip(conn.remote_address());
            match conn.accept_uni().await {
                Ok(mut recv) => {
                    let recv_map_clone = udp_recv_map.clone();

                    tokio::spawn(async move {
                        let res: anyhow::Result<()> = async {
                            let recv_context_id =
                                try_get_recv_context_id(&mut recv, read_timeout).await?;

                            let k = recv_context_id.to_string();
                            if let Some(item) = recv_map_clone.get(&k) {
                                item.run_unistream_worker(
                                    Arc::new(Mutex::new(recv)),
                                    remote_src.clone(),
                                    k,
                                );
                                return anyhow::Ok(());
                            }
                            bail!("can not find context_id");
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
) -> anyhow::Result<Id32> {
    let mut buf = [0u8; 32];
    timeout(read_timeout, recv.read_exact(&mut buf))
        .await
        .context("read recv_context_id timed out")?
        .context("read recv_context_id failed")?;
    Ok(Id32::from_bytes(buf))
}

pub fn start_datagram_loop(
    conn: Arc<quinn::Connection>,
    udp_recv_map: UdpRecvMap,
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
                                datagram,
                                remote_src.clone(),
                            ).await {
                                error!("handle_datagram error: {}", e);
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
    datagram: Bytes,
    remote_src: TargetAddr,
) -> anyhow::Result<()> {
    if datagram.len() <= 32 {
        warn!("Received invalid shadowquic datagram, ignored");
        return Ok(());
    }

    let recv_context_id = Id32::from_bytes(
        datagram[..32]
            .try_into()
            .map_err(|_| anyhow::anyhow!("Invalid datagram length for context_id"))?,
    );

    let payload = datagram.slice(32..);

    if let Some(entry) = udp_recv_map.get(&recv_context_id.to_string()) {
        entry.feed_datagram(payload, remote_src).await;
        return Ok(());
    }

    Ok(())
}

pub struct ShadowQuicUdpPacket {
    send_unistream: Option<Arc<Mutex<quinn::SendStream>>>,
    datagram_sender_tx: Option<flume::Sender<Bytes>>,

    send_context_id: Bytes,
    target: TargetAddr,

    receiver: Arc<ShadowUdpReceiver>,
}

impl ShadowQuicUdpPacket {
    pub fn new(
        send_unistream: Option<Arc<Mutex<quinn::SendStream>>>,
        datagram_sender_tx: Option<flume::Sender<Bytes>>,
        send_context_id: Bytes,
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
            let mut packet = Vec::with_capacity(self.send_context_id.len() + buf.len());
            packet.extend_from_slice(&self.send_context_id);
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
) -> std::io::Result<Id32> {
    let mut buf = [0u8; 32];
    match timeout(duration, bistream.read_exact(&mut buf)).await {
        Ok(Ok(_)) => Ok(Id32::from_bytes(buf)),
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
