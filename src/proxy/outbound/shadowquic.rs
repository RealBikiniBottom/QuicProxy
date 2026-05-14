use crate::proxy::shadowquic_udp::{
    ShadowUdpReceiver, UdpRecvMap, WaitingDatagramBuffer, gen_sunny_auth_hash,
    run_bistream_recv_listener, start_datagram_loop, start_udp_session_cleaner,
    start_unistream_listener,
};
use crate::utils::quic_wrap::quinn_wrap::QuinnBistream;
use crate::utils::quic_wrap::quinn_wrap::QuinnClient;
use anyhow::{Context, Result};
use async_trait::async_trait;
use bytes::Bytes;
use dashmap::DashMap;

use std::sync::Arc;
use std::sync::atomic::AtomicU16;
use std::sync::atomic::Ordering;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::sync::Mutex;
use tracing::debug;

use tracing::{info, warn};

use crate::config::OutboundConfig;
use crate::proxy::outbound::{AnyOutbound, AnyStream, UdpMode};
use crate::proxy::shadowquic_udp::ShadowQuicUdpPacket;
use crate::proxy::{QuicTlsConfig, TargetAddr};

use crate::utils::keyed_notify::KeyedNotify;
use crate::utils::{format_duration, new_io_other_error};

use super::AnyPacket;

pub struct ShadowQuicOutbound {
    tag: String,
    address: String,
    port: u16,

    auth_hash: Option<[u8; 64]>,
    tls: QuicTlsConfig,

    dns_server_name: Option<String>,
    bind_interface: Option<String>,

    congestion_controller: Option<String>,
    connect_timeout: Duration,
    idle_timeout: Duration,
    enable_gso: bool,

    udp_mod: UdpMode,

    waiting_datagram_buffer: WaitingDatagramBuffer,
    udp_recv_map_notify: Arc<KeyedNotify>,
    client: Mutex<Option<Arc<QuinnClient>>>,
    connection: Mutex<Option<Arc<quinn::Connection>>>,
    next_context_id: AtomicU16,

    datagram_sender_tx: flume::Sender<Bytes>,
    datagram_sender_rx: flume::Receiver<Bytes>,
    udp_recv_map: UdpRecvMap,
}

impl ShadowQuicOutbound {
    pub fn new(tag: String, cfg: &OutboundConfig) -> Result<Arc<dyn AnyOutbound>> {
        let connect_timeout = Duration::from_secs(cfg.connect_timeout.unwrap_or(30));
        let idle_timeout = Duration::from_secs(cfg.idle_timeout.unwrap_or(30));

        let tls = QuicTlsConfig::from_outbound(cfg)?;

        let mut udp_mod = UdpMode::OverStream;
        if cfg.udp_mod.clone().unwrap_or("stream".to_string()) == "datagram" {
            udp_mod = UdpMode::OverDatagram;
        }

        let (datagram_sender_tx, datagram_sender_rx) = flume::bounded(100);
        let udp_recv_map = Arc::new(DashMap::new());
        start_udp_session_cleaner(udp_recv_map.clone(), connect_timeout, connect_timeout);

        let mut auth_hash = None;
        if !tls.enable_jls {
            let username = cfg.username.clone().context(format!(
                "shadowquic outbound '{}' requires username",
                tag.clone()
            ))?;
            let password = cfg.password.clone().context(format!(
                "shadowquic outbound '{}' requires password",
                tag.clone()
            ))?;
            auth_hash = Some(gen_sunny_auth_hash(&username, &password));
        }

        let address = cfg.address.clone().context(format!(
            "shadowquic outbound '{}' requires address",
            tag.clone()
        ))?;
        let port = cfg.port.context(format!(
            "shadowquic outbound '{}' requires port",
            tag.clone()
        ))?;

        Ok(Arc::new(Self {
            tag,
            address,
            port,
            tls,
            connect_timeout,
            idle_timeout,
            auth_hash,
            udp_mod,
            waiting_datagram_buffer: Arc::new(DashMap::new()),
            udp_recv_map_notify: Arc::new(KeyedNotify::new()),
            client: Mutex::new(None),
            connection: Mutex::new(None),
            dns_server_name: cfg.dns.clone(),
            bind_interface: cfg.bind_interface.clone(),
            congestion_controller: cfg.congestion_controller.clone(),
            next_context_id: AtomicU16::new(1),
            datagram_sender_tx,
            datagram_sender_rx,
            enable_gso: cfg.gso,
            udp_recv_map,
        }))
    }

    pub fn connect_timeout(&self) -> Duration {
        self.connect_timeout
    }

    async fn clear_cached_connection(&self, conn: &Arc<quinn::Connection>) {
        let should_clear = {
            let lock = self.connection.lock().await;
            lock.as_ref()
                .is_some_and(|cached| Arc::ptr_eq(cached, conn))
        };

        if should_clear {
            let mut lock = self.connection.lock().await;
            *lock = None;
            let mut client = self.client.lock().await;
            *client = None;
        }
    }

    async fn ensure_connection(&self) -> anyhow::Result<Arc<quinn::Connection>> {
        let mut lock = self.connection.lock().await;

        if let Some(conn) = lock.as_ref() {
            match conn.close_reason() {
                Some(r) => {
                    info!("exists connection closed: {}", r);
                }
                None => {
                    info!("reuse quic connection {}", conn.stable_id());
                    return Ok(conn.clone());
                }
            }
        }

        let remote_addr = self.resolve_addr(&self.address, self.port).await?;

        let socket = self.new_udp_socket(remote_addr).await?;

        let client = Arc::new(
            QuinnClient::new(
                socket.into_std()?,
                self.idle_timeout,
                !self.tls.insecure,
                self.tls.zero_rtt,
                self.tls.cert.as_deref(),
                self.tls.sni.clone(),
                self.tls.alpns.clone(),
                self.congestion_controller.clone(),
                self.tls.jls_username.clone(),
                self.tls.jls_password.clone(),
                self.tls.enable_jls,
                self.enable_gso,
            )
            .with_context(|| {
                format!(
                    "Failed to create QuinnClient (addr={} sni={:?} jls={} cert={:?})",
                    remote_addr, self.tls.sni, self.tls.enable_jls, self.tls.cert,
                )
            })?,
        );

        let conn = tokio::time::timeout(self.connect_timeout, client.connect(remote_addr))
            .await
            .map_err(|_| {
                new_io_other_error(format!(
                    "ShadowQuic connect timeout after {:?} to {}",
                    self.connect_timeout, remote_addr
                ))
            })?
            .map_err(|e| {
                new_io_other_error(format!(
                    "ShadowQuic connect failed to {}: {:?}",
                    remote_addr, e
                ))
            })?;

        info!("new quic connection");
        *self.client.lock().await = Some(client);
        *lock = Some(conn.clone());

        if let Some(auth_hash) = self.auth_hash {
            match conn.open_bi().await {
                Ok((mut send, _recv)) => {
                    let mut auth_packet = Vec::with_capacity(1 + 64);
                    auth_packet.push(0x05);
                    auth_packet.extend_from_slice(&auth_hash);
                    if let Err(e) = send.write_all(&auth_packet).await {
                        warn!("send auth packet failed: {}", e);
                    }
                    let _ = send.flush().await;
                    let _ = send.finish();
                }
                Err(e) => {
                    warn!("open auth bistream failed: {}", e);
                }
            }
        }

        // one connection start once
        let conn_clone = conn.clone();
        match self.udp_mod {
            UdpMode::OverStream => start_unistream_listener(
                conn_clone,
                self.udp_recv_map.clone(),
                self.udp_recv_map_notify.clone(),
                self.connect_timeout(),
            ),
            UdpMode::OverDatagram => start_datagram_loop(
                conn_clone,
                self.udp_recv_map.clone(),
                self.waiting_datagram_buffer.clone(),
                self.udp_recv_map_notify.clone(),
                self.datagram_sender_rx.clone(),
            ),
        }
        Ok(conn)
    }

    async fn open_bistream_with_retry(
        &self,
    ) -> anyhow::Result<(Arc<quinn::Connection>, quinn::SendStream, quinn::RecvStream)> {
        let conn = self.ensure_connection().await?;

        match conn.open_bi().await {
            // 成功时直接解构元组
            Ok((send, recv)) => Ok((conn, send, recv)),

            Err(e) => {
                warn!(
                    "Cached ShadowQuic connection invalid (bi-stream error: {}), reconnecting",
                    e
                );

                // 1. 发现失效，清除缓存
                self.clear_cached_connection(&conn).await;

                // 2. 重新获取连接（通常内部会触发重新握手）
                let retry_conn = self.ensure_connection().await?;

                // 3. 再次尝试打开双向流
                let (send, recv) = retry_conn
                    .open_bi()
                    .await
                    .with_context(|| "failed to open bistream after reconnection")?;

                Ok((retry_conn, send, recv))
            }
        }
    }

    async fn open_unistream_with_retry(
        &self,
    ) -> anyhow::Result<(Arc<quinn::Connection>, quinn::SendStream)> {
        let conn = self.ensure_connection().await?;

        // 尝试第一次打开流
        match conn.open_uni().await {
            Ok(send) => Ok((conn, send)),
            Err(e) => {
                warn!(
                    "Cached ShadowQuic connection invalid (error: {}), retrying with new connection",
                    e
                );

                // 1. 清理旧连接
                self.clear_cached_connection(&conn).await;

                // 2. 获取新连接（ensure_connection 内部逻辑应包含重新拨号）
                let retry_conn = self.ensure_connection().await?;

                // 3. 再次尝试，直接使用 ? 抛出 anyhow 错误
                let send = retry_conn
                    .open_uni()
                    .await
                    .context("failed to open unistream after reconnection")?;

                Ok((retry_conn, send))
            }
        }
    }
}

#[async_trait]
impl AnyOutbound for ShadowQuicOutbound {
    fn tag(&self) -> &str {
        &self.tag
    }

    fn protocol(&self) -> &str {
        "shadowquic"
    }

    fn dns_server_name(&self) -> Option<&str> {
        self.dns_server_name.as_deref()
    }

    fn bind_interface(&self) -> Option<&str> {
        self.bind_interface.as_deref()
    }

    fn connect_timeout(&self) -> Duration {
        Duration::from_secs(10)
    }

    async fn connect_stream_base(&self) -> anyhow::Result<AnyStream> {
        let (conn, send, recv) = self.open_bistream_with_retry().await?;

        let stats = conn.stats();
        let packet_loss_rate =
            (stats.path.lost_packets as f32) / ((stats.path.sent_packets + 1) as f32) * 100.0;
        let rtt = conn.rtt();
        let mtu = stats.path.current_mtu;

        info!(
            "packet_loss_rate: {:.2}%, rtt: {:?}, mtu: {}",
            packet_loss_rate,
            Some(rtt).map(format_duration),
            mtu,
        );

        Ok(Box::new(QuinnBistream::new(send, recv)))
    }

    async fn connect_stream_with(
        &self,
        target: &TargetAddr,
        mut stream: AnyStream,
    ) -> anyhow::Result<AnyStream> {
        let target_bytes = target.to_bytes();
        let mut handshake = Vec::with_capacity(1 + target_bytes.len());
        handshake.push(0x01);
        handshake.extend_from_slice(&target_bytes);
        stream.write_all(&handshake).await?;
        stream.flush().await?;

        Ok(stream)
    }

    async fn connect_packet(&self, target: &TargetAddr) -> anyhow::Result<Arc<dyn AnyPacket>> {
        // open control bistream
        let (_conn, send, recv) = self.open_bistream_with_retry().await?;
        let mut bistream = Box::new(QuinnBistream::new(send, recv));

        let target_bytes = target.to_bytes();
        let target_bytes_dummy = TargetAddr::dummy().to_bytes();

        // send header with control_bistream
        let send_context_id = self.next_context_id.fetch_add(1, Ordering::SeqCst);
        let mut packet = Vec::with_capacity(1 + target_bytes.len() + 2 + target_bytes_dummy.len());
        match self.udp_mod {
            UdpMode::OverStream => {
                packet.push(0x04);
            }
            UdpMode::OverDatagram => {
                packet.push(0x03);
            }
        }
        packet.extend_from_slice(&target_bytes_dummy);
        packet.extend_from_slice(&target_bytes);
        packet.extend_from_slice(&send_context_id.to_be_bytes());
        bistream.write_all(&packet).await?;
        bistream.flush().await?;

        let receiver = Arc::new(ShadowUdpReceiver::new(self.udp_recv_map.clone()));
        run_bistream_recv_listener(
            bistream,
            self.udp_recv_map.clone(),
            receiver.clone(),
            self.udp_recv_map_notify.clone(),
            None,
        );

        // setup sender
        let out_packet: Arc<dyn AnyPacket>;
        match self.udp_mod {
            UdpMode::OverStream => {
                let (_conn, uni_send) = self.open_unistream_with_retry().await?;

                let send_mutex = Arc::new(Mutex::new(uni_send));

                {
                    let mut lock = send_mutex.lock().await;
                    lock.write_all(&send_context_id.to_be_bytes()).await?;
                    lock.flush().await?;
                }

                out_packet = Arc::new(ShadowQuicUdpPacket::new(
                    Some(send_mutex),
                    None,
                    send_context_id,
                    target.clone(),
                    receiver,
                ));
            }
            UdpMode::OverDatagram => {
                out_packet = Arc::new(ShadowQuicUdpPacket::new(
                    None,
                    Some(self.datagram_sender_tx.clone()),
                    send_context_id,
                    target.clone(),
                    receiver,
                ));
            }
        }

        debug!("created ShadowQuicUdpPacket");
        Ok(out_packet)
    }
}
