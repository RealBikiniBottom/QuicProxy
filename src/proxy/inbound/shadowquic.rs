use anyhow::bail;
use async_trait::async_trait;
use quinn::{ConnectionError, VarInt};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::sync::Mutex;

use crate::config::InboundConfig;
use crate::proxy::inbound::AnyInbound;
use crate::proxy::outbound::UdpMode;
use crate::proxy::router::Router;
use crate::proxy::router::get_router;
use crate::proxy::shadowquic_udp::{
    ExtensionRequest, PerConnectionState, ShadowQuicUdpPacket, ShadowUdpReceiver,
    UDP_CONTEXT_ID_RECONNECT_MARGIN, auth_sunnyquic, gen_sunny_auth_hash, read_context_id,
    read_extension_request, read_request_head, run_bistream_recv_listener, start_datagram_loop,
    start_unistream_listener, write_conn_stats_response, write_ext_error_not_available,
};
use crate::proxy::{TargetAddr, TlsConfig};
use anyhow::Context;

use crate::utils::quic_wrap::quinn_wrap::QuinnBistream;
use crate::utils::quic_wrap::quinn_wrap::QuinnServer;

use tracing::{Instrument, debug, error, field, info, info_span};

/// Application close code sent to the peer when the connection handler exits.
const SHADOWQUIC_CLOSE_CODE: u32 = 263;

pub struct ShadowQuicInbound {
    tag: String,
    address: String,
    port: u16,
    tls: TlsConfig,
    auth_hash: Option<[u8; 64]>,
    enable_gso: bool,
    enable_mtudis: bool,
    min_mtu: u16,
    initial_mtu: u16,

    congestion_controller: Option<String>,
    idle_timeout: Duration,
}

impl ShadowQuicInbound {
    pub fn new(tag: String, cfg: &InboundConfig) -> anyhow::Result<Self> {
        let tls = TlsConfig::from_inbound(cfg)?;

        if !tls.enable && !tls.enable_jls {
            anyhow::bail!("ShadowQuic inbound requires TLS to be enabled");
        }

        let mut auth_hash = None;
        if !tls.enable_jls {
            let (username, password) = cfg.credentials(&tag)?;
            auth_hash = Some(gen_sunny_auth_hash(username, password));
        }

        let (address, port) = cfg.endpoint()?;

        Ok(Self {
            tag,
            auth_hash,
            congestion_controller: cfg.congestion_controller.clone(),
            tls,
            address: address.to_string(),
            port,
            idle_timeout: cfg.idle_timeout(),
            enable_gso: cfg.gso,
            enable_mtudis: cfg.mtu_discoveriy,
            min_mtu: cfg.min_mtu,
            initial_mtu: cfg.initial_mtu,
        })
    }

    async fn handle_udp(
        udp_mod: UdpMode,
        mut bistream: Box<QuinnBistream>,
        target: TargetAddr,
        router: Arc<Router>,
        inbound_tag: &str,
        per_conn: Arc<PerConnectionState>,
        conn: Arc<quinn::Connection>,
        idle_timeout: Duration,
    ) -> anyhow::Result<()> {
        let recv_context_id = read_context_id(&mut bistream, idle_timeout).await?;

        // The server is the acceptor, so it cannot force a fresh connection the
        // way the client does. Refuse this session instead: letting the shared
        // per-connection counter run out would trip get_send_context_id's
        // u16::try_from failure and close the whole QUIC connection, killing
        // every TCP and UDP session riding on it.
        let used = per_conn.next_context_id.load(Ordering::Relaxed);
        if used >= u16::MAX as u32 - UDP_CONTEXT_ID_RECONNECT_MARGIN {
            bail!(
                "UDP context-id space nearly exhausted on this connection ({} used), refusing new UDP session",
                used
            );
        }

        let receiver = Arc::new(ShadowUdpReceiver::new(
            per_conn.udp_recv_map.clone(),
            per_conn.udp_recv_map_notify.clone(),
        ));
        receiver.bind_context_id(target.clone(), recv_context_id)?;
        run_bistream_recv_listener(bistream.recv, receiver.clone());

        debug!(?udp_mod);
        let source_addr = TargetAddr::Ip(conn.remote_address());
        let out_packet = Arc::new(ShadowQuicUdpPacket::new(
            matches!(udp_mod, UdpMode::OverStream),
            false,
            receiver,
            per_conn.next_context_id.clone(),
            Arc::new(Mutex::new(bistream.send)),
            conn,
        ));
        out_packet.get_send_context_id(&target).await?; // init

        router
            .dispatch_packet(
                out_packet,
                &target,
                &source_addr,
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
        let listen_addr = SocketAddr::new(self.address.parse::<IpAddr>()?, self.port);
        let mut listener = QuinnServer::new(
            listen_addr,
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
            self.enable_mtudis,
            self.initial_mtu,
            self.min_mtu,
        )
        .with_context(|| format!("QUIC server failed to listen on {}", listen_addr))?;

        let auth_hash = self.auth_hash;
        let session_timeout = self.idle_timeout();
        let tag = self.tag.clone();
        let router = get_router()?;

        info!("ShadowQuic inbound listening on {}", listen_addr);

        loop {
            match listener.accept().await {
                Ok(conn) => {
                    info!("Accepted QUIC connection from {}", conn.remote_address());

                    let per_conn = Arc::new(PerConnectionState::new());
                    let router = router.clone();
                    let tag = tag.clone();

                    tokio::spawn(async move {
                        let res: anyhow::Result<()> = async {
                            let mut is_authed = auth_hash.is_none();
                            let mut services_started = false;

                            loop {
                                let (send, recv) = match conn.accept_bi().await {
                                    Ok(stream) => stream,
                                    Err(
                                        e @ (ConnectionError::ApplicationClosed(_)
                                        | ConnectionError::ConnectionClosed(_)
                                        | ConnectionError::TimedOut
                                        | ConnectionError::LocallyClosed
                                        | ConnectionError::Reset),
                                    ) => {
                                        debug!("QUIC connection ended: {}", e);
                                        return Ok(());
                                    }
                                    Err(e) => return Err(e).context("QUIC accept_bi error"),
                                };

                                let mut bistream = Box::new(QuinnBistream::new(send, recv));
                                if !is_authed {
                                    if let Some(auth_hash) = auth_hash {
                                        auth_sunnyquic(&mut bistream, auth_hash, session_timeout)
                                            .await
                                            .context("auth failed")?;

                                        is_authed = true;
                                        info!("Sunnyquic auth ok");
                                        continue;
                                    }
                                }

                                if !services_started {
                                    start_unistream_listener(
                                        conn.clone(),
                                        per_conn.udp_recv_map.clone(),
                                        per_conn.udp_recv_map_notify.clone(),
                                        session_timeout,
                                    );
                                    start_datagram_loop(
                                        conn.clone(),
                                        per_conn.udp_recv_map.clone(),
                                        per_conn.waiting_datagram_buffer.clone(),
                                        per_conn.udp_recv_map_notify.clone(),
                                    );
                                    services_started = true;
                                }

                                let tag = tag.clone();
                                let router = router.clone();
                                let per_conn = per_conn.clone();
                                let conn = conn.clone();
                                let remote_addr = conn.remote_address().to_string();

                                info!("Accepted proxy request from bistream");
                                tokio::spawn(async move {
                                    let res: anyhow::Result<()> = async {
                                        let (cmd, target) =
                                            read_request_head(&mut bistream, session_timeout)
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
                                                    per_conn,
                                                    conn,
                                                    session_timeout,
                                                )
                                                .instrument(span)
                                                .await?;
                                            }
                                            0xFF => {
                                                // Shadowquic extension protocol
                                                let ext_req = read_extension_request(
                                                    &mut bistream,
                                                    session_timeout,
                                                )
                                                .await
                                                .context("read extension request")?;

                                                let mut send = bistream.send;
                                                match ext_req {
                                                    ExtensionRequest::GetConnStats => {
                                                        let stats = conn.stats();
                                                        let rtt_ms =
                                                            conn.rtt().as_secs_f64() * 1000.0;
                                                        if let Err(e) = write_conn_stats_response(
                                                            &mut send,
                                                            stats.path.lost_packets,
                                                            stats.path.sent_packets,
                                                            rtt_ms,
                                                            stats.path.current_mtu,
                                                        )
                                                        .await
                                                        {
                                                            debug!(
                                                                "write conn stats response: {}",
                                                                e
                                                            );
                                                        }
                                                    }
                                                    ExtensionRequest::UserExtension
                                                    | ExtensionRequest::Unknown => {
                                                        if let Err(e) =
                                                            write_ext_error_not_available(&mut send)
                                                                .await
                                                        {
                                                            debug!(
                                                                "write ext error response: {}",
                                                                e
                                                            );
                                                        }
                                                    }
                                                }
                                                let _ = send.flush().await;
                                                let _ = send.finish();
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
                        }
                        .await;

                        if let Err(e) = res {
                            error!("QUIC conn error: {:#}", e);
                        }

                        conn.close(VarInt::from_u32(SHADOWQUIC_CLOSE_CODE), b"");
                        info!("QUIC conn {} closed", conn.remote_address());
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
