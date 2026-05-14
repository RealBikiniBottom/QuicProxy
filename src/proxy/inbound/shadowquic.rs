use anyhow::bail;
use async_trait::async_trait;
use bytes::Bytes;
use dashmap::DashMap;
use quinn::VarInt;
use std::sync::Arc;
use std::sync::atomic::AtomicU16;
use std::sync::atomic::Ordering;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::sync::Mutex;

use crate::config::InboundConfig;
use crate::proxy::inbound::AnyInbound;
use crate::proxy::outbound::AnyPacket;
use crate::proxy::outbound::UdpMode;
use crate::proxy::router::Router;
use crate::proxy::router::get_router;
use crate::proxy::shadowquic_udp::WaitingDatagramBuffer;
use crate::proxy::shadowquic_udp::{
    ShadowQuicUdpPacket, ShadowUdpReceiver, UdpRecvMap, auth_sunnyquic, gen_sunny_auth_hash,
    read_context_id, read_request_head, run_bistream_recv_listener, start_datagram_loop,
    start_udp_session_cleaner, start_unistream_listener,
};
use crate::proxy::{QuicTlsConfig, TargetAddr};
use anyhow::Context;

use crate::utils::keyed_notify::KeyedNotify;
use crate::utils::new_io_other_error;
use crate::utils::quic_wrap::quinn_wrap::QuinnBistream;
use crate::utils::quic_wrap::quinn_wrap::QuinnServer;

use tracing::{Instrument, debug, error, field, info, info_span};

pub struct ShadowQuicInbound {
    tag: String,
    address: String,
    port: u16,
    tls: QuicTlsConfig,
    auth_hash: Option<[u8; 64]>,
    enable_gso: bool,

    congestion_controller: Option<String>,
    idle_timeout: Duration,
    next_context_id: Arc<AtomicU16>,
    udp_recv_map: UdpRecvMap,
    udp_recv_map_notify: Arc<KeyedNotify>,
    waiting_datagram_buffer: WaitingDatagramBuffer,
    datagram_sender_tx: flume::Sender<Bytes>,
    datagram_sender_rx: flume::Receiver<Bytes>,
}

impl ShadowQuicInbound {
    pub fn new(tag: String, cfg: &InboundConfig) -> anyhow::Result<Self> {
        let tls = QuicTlsConfig::from_inbound(cfg)?;

        if !tls.enable && !tls.enable_jls {
            anyhow::bail!("ShadowQuic inbound requires TLS to be enabled");
        }

        let mut auth_hash = None;
        if !tls.enable_jls {
            let username = cfg.username.clone().context("requires username")?;
            let password = cfg.password.clone().context("requires password")?;
            auth_hash = Some(gen_sunny_auth_hash(&username, &password));
        }

        let idle_timeout = Duration::from_secs(cfg.idle_timeout.unwrap_or(30));

        let (datagram_sender_tx, datagram_sender_rx) = flume::bounded(100);
        let udp_recv_map = Arc::new(DashMap::new());
        start_udp_session_cleaner(udp_recv_map.clone(), idle_timeout, idle_timeout);

        Ok(Self {
            tag,
            auth_hash,
            congestion_controller: cfg.congestion_controller.clone(),
            tls,
            address: cfg.address.clone().context("require address")?,
            port: cfg.port.context("require port")?,
            idle_timeout,
            next_context_id: Arc::new(AtomicU16::new(1)),
            udp_recv_map_notify: Arc::new(KeyedNotify::new()),
            waiting_datagram_buffer: Arc::new(DashMap::new()),
            udp_recv_map,
            datagram_sender_tx,
            datagram_sender_rx,
            enable_gso: cfg.gso,
        })
    }

    async fn handle_udp(
        udp_mod: UdpMode,
        mut bistream: Box<QuinnBistream>,
        target: TargetAddr,
        router: Arc<Router>,
        inbound_tag: &str,
        udp_recv_map: UdpRecvMap,
        datagram_sender_tx: flume::Sender<Bytes>,
        conn: Arc<quinn::Connection>,
        send_context_id: u16,
        idle_timeout: Duration,
        udp_recv_map_notify: Arc<KeyedNotify>,
    ) -> anyhow::Result<()> {
        let recv_context_id = read_context_id(&mut bistream, idle_timeout).await?;
        debug!("receive context_id {}", recv_context_id);

        let receiver = udp_recv_map
            .entry(recv_context_id)
            .or_insert_with(|| Arc::new(ShadowUdpReceiver::new(udp_recv_map.clone())))
            .clone();

        {
            let mut buf = target.to_bytes();
            buf.extend_from_slice(&send_context_id.to_be_bytes());
            bistream.write_all(&buf).await?;
            bistream.flush().await?;
        }

        run_bistream_recv_listener(
            bistream,
            udp_recv_map,
            receiver.clone(),
            udp_recv_map_notify,
            Some(recv_context_id),
        );

        let target_clone = target.clone();

        // build tracked_packet
        let out_packet: Arc<dyn AnyPacket>;
        match udp_mod {
            UdpMode::OverStream => {
                let uni_send = conn.open_uni().await?;

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
                    target,
                    receiver.clone(),
                ));
            }
            UdpMode::OverDatagram => {
                out_packet = Arc::new(ShadowQuicUdpPacket::new(
                    None,
                    Some(datagram_sender_tx.clone()),
                    send_context_id,
                    target,
                    receiver.clone(),
                ));
            }
        }

        router
            .dispatch_packet(
                out_packet,
                &target_clone,
                &TargetAddr::Ip(conn.remote_address()),
                inbound_tag,
                None,
                idle_timeout,
                None,
            )
            .await
    }
}

#[async_trait]
impl AnyInbound for ShadowQuicInbound {
    fn protocol(&self) -> &str {
        "shadowquic"
    }

    fn idle_timeout(&self) -> Duration {
        self.idle_timeout
    }

    async fn listen(&self) -> anyhow::Result<()> {
        let listen_addr = format!("{}:{}", self.address, self.port);
        let mut listener = QuinnServer::new(
            &listen_addr,
            self.idle_timeout,
            self.tls.cert.as_deref(),
            self.tls.key.as_deref(),
            self.congestion_controller.clone(),
            self.tls.sni.clone(),
            self.tls.alpns.clone(),
            self.tls.zero_rtt,
            self.tls.jls_username.clone(),
            self.tls.jls_password.clone(),
            self.tls.enable_jls,
            self.enable_gso,
        )
        .await
        .map_err(|e| new_io_other_error(format!("QUIC server error: {}", e)))?;

        let auth_hash = self.auth_hash;
        let udp_recv_map = self.udp_recv_map.clone();
        let udp_recv_map_notify = self.udp_recv_map_notify.clone();
        let waiting_datagram_buffer = self.waiting_datagram_buffer.clone();
        let datagram_sender_tx = self.datagram_sender_tx.clone();
        let datagram_sender_rx = self.datagram_sender_rx.clone();
        let session_timeout = self.idle_timeout();
        let tag = self.tag.clone();
        let router = get_router();

        info!("ShadowQuic inbound listening on {}", listen_addr);

        loop {
            match listener.accept().await {
                Ok(conn) => {
                    let router_clone = router.clone();
                    let next_context_id = self.next_context_id.clone();
                    info!("Accepted QUIC connection from {}", conn.remote_address());

                    let conn_clone = conn.clone();
                    let udp_recv_map_clone = udp_recv_map.clone();
                    let udp_recv_map_notify_clone = udp_recv_map_notify.clone();
                    let waiting_datagram_buffer_clone = waiting_datagram_buffer.clone();
                    let datagram_sender_tx = datagram_sender_tx.clone();
                    let datagram_sender_rx = datagram_sender_rx.clone();
                    let session_timeout_val = session_timeout;
                    let tag_clone = tag.clone();

                    tokio::spawn(async move {
                        let res: anyhow::Result<()> = async {
                            let mut is_authed = !auth_hash.is_some();
                            let mut services_started = false;

                            let start_services = || {
                                start_unistream_listener(
                                    conn_clone.clone(),
                                    udp_recv_map_clone.clone(),
                                    udp_recv_map_notify_clone.clone(),
                                    session_timeout_val,
                                );
                                start_datagram_loop(
                                    conn_clone.clone(),
                                    udp_recv_map_clone.clone(),
                                    waiting_datagram_buffer_clone.clone(),
                                    udp_recv_map_notify_clone.clone(),
                                    datagram_sender_rx.clone(),
                                );
                            };

                            while conn.close_reason().is_none() {
                                let conn_clone2 = conn.clone();
                                let (send, recv) = conn_clone2
                                    .accept_bi()
                                    .await
                                    .context("QUIC accept_bi error")?;

                                let mut bistream = Box::new(QuinnBistream::new(send, recv));
                                if !is_authed {
                                    if let Some(auth_hash) = auth_hash {
                                        auth_sunnyquic(
                                            &mut bistream,
                                            auth_hash,
                                            session_timeout_val,
                                        )
                                        .await
                                        .context("auth failed")?;

                                        is_authed = true;
                                        info!("Sunnyquic auth ok");
                                        continue;
                                    }
                                }

                                if !services_started {
                                    start_services();
                                    services_started = true;
                                }

                                let tag = tag_clone.clone();
                                let router = router_clone.clone();
                                let udp_recv_map_clone = udp_recv_map_clone.clone();
                                let udp_recv_map_notify_clone = udp_recv_map_notify_clone.clone();
                                let datagram_sender_tx = datagram_sender_tx.clone();
                                let send_context_id = next_context_id.clone();
                                let remote_addr = conn_clone2.remote_address().to_string();

                                info!("Accepted proxy request from bistream");
                                tokio::spawn(async move {
                                    let res: anyhow::Result<()> = async {
                                        let (cmd, target) =
                                            read_request_head(&mut bistream, session_timeout_val)
                                                .await?;

                                        match cmd {
                                            0x01 => {
                                                let span = info_span!(
                                                    "tcp",
                                                    i = %tag,
                                                    s = %remote_addr,
                                                    d = field::Empty,
                                                    r = field::Empty,
                                                    o = field::Empty
                                                );
                                                router
                                                    .dispatch_stream(bistream, &target, &tag)
                                                    .instrument(span)
                                                    .await?;
                                            }
                                            0x03 | 0x04 => {
                                                let span = info_span!(
                                                    "udp",
                                                    i = %tag,
                                                    s = %remote_addr,
                                                    d = field::Empty,
                                                    r = field::Empty,
                                                    o = field::Empty
                                                );
                                                let context_id =
                                                    send_context_id.fetch_add(1, Ordering::SeqCst);
                                                Self::handle_udp(
                                                    if cmd == 0x03 {
                                                        UdpMode::OverDatagram
                                                    } else {
                                                        UdpMode::OverStream
                                                    },
                                                    bistream,
                                                    target,
                                                    router,
                                                    tag.as_str(),
                                                    udp_recv_map_clone,
                                                    datagram_sender_tx,
                                                    conn_clone2.clone(),
                                                    context_id,
                                                    session_timeout_val,
                                                    udp_recv_map_notify_clone,
                                                )
                                                .instrument(span)
                                                .await?;
                                            }
                                            _ => {
                                                bail!("wrong bistream cmd.");
                                            }
                                        }
                                        Ok(())
                                    }
                                    .await;

                                    if let Err(e) = res {
                                        error!("proxy request error: {:#}", e);
                                    }
                                });
                            }
                            Ok(())
                        }
                        .await;

                        if let Err(e) = res {
                            error!("QUIC conn error: {:#}", e);
                        }

                        conn.close(VarInt::from_u64(263).unwrap(), &[]);
                        debug!("QUIC conn closed",);
                    });
                }
                Err(e) => {
                    error!("Failed to accept ShadowQuic connection: {}", e);
                    break;
                }
            }
        }

        Ok(())
    }
}
