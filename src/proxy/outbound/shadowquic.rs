use crate::proxy::shadowquic_udp::{
    PerConnectionState, ShadowQuicUdpPacket, ShadowUdpReceiver, gen_sunny_auth_hash,
    run_bistream_recv_listener, start_datagram_loop, start_udp_session_cleaner,
    start_unistream_listener,
};
use crate::utils::interface::InterfaceManager;
use crate::utils::quic_wrap::quinn_wrap::QuinnBistream;
use crate::utils::quic_wrap::quinn_wrap::QuinnClient;
use anyhow::{Context, Result};
use async_trait::async_trait;

use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Mutex;

use tracing::{debug, info, warn};

use crate::config::OutboundConfig;
use crate::proxy::outbound::{AnyOutbound, AnyStream, UdpMode};
use crate::proxy::{QuicTlsConfig, TargetAddr};

use crate::utils::{format_duration, new_io_other_error};

use super::AnyPacket;

pub struct ShadowQuicOutbound {
    tag: String,
    address: TargetAddr,

    auth_hash: Option<[u8; 64]>,
    tls: QuicTlsConfig,

    dns_server_name: Option<String>,
    bind_interface: Option<String>,

    congestion_controller: Option<String>,
    connect_timeout: Duration,
    idle_timeout: Duration,
    enable_gso: bool,
    enable_mtudis: bool,
    min_mtu: u16,
    initial_mtu: u16,

    udp_mod: UdpMode,

    cached_client: Arc<
        Mutex<
            Option<(
                Arc<quinn::Connection>,
                Arc<QuinnClient>,
                Arc<PerConnectionState>,
            )>,
        >,
    >,
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
        let address = TargetAddr::from_str2(&address, port)?;

        let cached_client = Arc::new(Mutex::new(None));
        if let Some(mut rx) = InterfaceManager::subscribe() {
            let cached_client_cloen = cached_client.clone();
            tokio::spawn(async move {
                while let Ok(_) = rx.recv().await {
                    let mut lock = cached_client_cloen.lock().await;
                    *lock = None;
                    info!("reset shadowquic outbound because iface changed");
                }
            });
        }

        Ok(Arc::new(Self {
            tag,
            address,
            tls,
            connect_timeout,
            idle_timeout,
            auth_hash,
            udp_mod,
            cached_client,
            dns_server_name: cfg.dns.clone(),
            bind_interface: cfg.bind_interface.clone(),
            congestion_controller: cfg.congestion_controller.clone(),
            enable_gso: cfg.gso,
            enable_mtudis: cfg.mtu_discoveriy,
            min_mtu: cfg.min_mtu,
            initial_mtu: cfg.initial_mtu,
        }))
    }

    pub fn connect_timeout(&self) -> Duration {
        self.connect_timeout
    }

    async fn clear_cache(&self) {
        let mut lock = self.cached_client.lock().await;
        *lock = None;
    }

    async fn ensure_connection(
        &self,
    ) -> anyhow::Result<(Arc<quinn::Connection>, Arc<PerConnectionState>)> {
        {
            let lock = self.cached_client.lock().await;
            if let Some((ref conn, _, ref state)) = *lock {
                if conn.close_reason().is_none() {
                    debug!(
                        "[{}] reuse quic connection {}",
                        self.tag(),
                        conn.stable_id()
                    );
                    return Ok((conn.clone(), state.clone()));
                }
                info!(
                    "[{}] exists connection closed: {:?}",
                    self.tag(),
                    conn.close_reason()
                );
            }
        }

        let remote_addr = self.resolve_addr(&self.address).await?;

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
                self.enable_mtudis,
                self.initial_mtu,
                self.min_mtu,
            )
            .with_context(|| {
                format!(
                    "[{}] Failed to create QuinnClient (addr={} sni={:?} jls={} cert={:?})",
                    self.tag(),
                    remote_addr,
                    self.tls.sni,
                    self.tls.enable_jls,
                    self.tls.cert,
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

        let state = Arc::new(PerConnectionState::new());
        start_udp_session_cleaner(
            state.udp_recv_map.clone(),
            self.idle_timeout,
            self.idle_timeout,
        );

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

        let conn_clone = conn.clone();
        match self.udp_mod {
            UdpMode::OverStream => start_unistream_listener(
                conn_clone,
                state.udp_recv_map.clone(),
                state.udp_recv_map_notify.clone(),
                self.connect_timeout(),
            ),
            UdpMode::OverDatagram => start_datagram_loop(
                conn_clone,
                state.udp_recv_map.clone(),
                state.waiting_datagram_buffer.clone(),
                state.udp_recv_map_notify.clone(),
            ),
        }

        {
            let mut lock = self.cached_client.lock().await;
            *lock = Some((conn.clone(), client, state.clone()));
        }

        info!("[{}] new quic connection", self.tag());

        Ok((conn, state))
    }

    async fn open_bistream_with_retry(
        &self,
    ) -> anyhow::Result<(
        Arc<quinn::Connection>,
        quinn::SendStream,
        quinn::RecvStream,
        Arc<PerConnectionState>,
    )> {
        let (conn, state) = self.ensure_connection().await?;

        match conn.open_bi().await {
            Ok((send, recv)) => Ok((conn, send, recv, state)),

            Err(e) => {
                warn!(
                    "Cached ShadowQuic connection invalid (bi-stream error: {}), reconnecting",
                    e
                );

                self.clear_cache().await;

                let (retry_conn, state) = self.ensure_connection().await?;

                let (send, recv) = retry_conn
                    .open_bi()
                    .await
                    .with_context(|| "failed to open bistream after reconnection")?;

                Ok((retry_conn, send, recv, state))
            }
        }
    }

    pub async fn open_unistream_with_retry(
        &self,
    ) -> anyhow::Result<(
        Arc<quinn::Connection>,
        quinn::SendStream,
        Arc<PerConnectionState>,
    )> {
        let (conn, state) = self.ensure_connection().await?;

        match conn.open_uni().await {
            Ok(send) => Ok((conn, send, state)),
            Err(e) => {
                warn!(
                    "Cached ShadowQuic connection invalid (error: {}), retrying with new connection",
                    e
                );

                self.clear_cache().await;

                let (retry_conn, state) = self.ensure_connection().await?;

                let send = retry_conn
                    .open_uni()
                    .await
                    .context("failed to open unistream after reconnection")?;

                Ok((retry_conn, send, state))
            }
        }
    }

    async fn get_uplink_stats(&self) -> Option<super::PathState> {
        let (conn, _state) = self.ensure_connection().await.ok()?;

        let stats = conn.stats();
        let lost_packets = stats.path.lost_packets;
        let sent_packets = stats.path.sent_packets;
        let rtt = conn.rtt().as_secs_f32() * 1000.0;
        let mtu = stats.path.current_mtu;
        Some(super::PathState {
            lost_packets,
            sent_packets,
            mtu,
            rtt,
        })
    }

    /// Query remote server for its path stats via the shadowquic extension protocol.
    /// Opens a bistream, sends `SQReq::SQExtension(Conn(GetConnStats))`, and decodes
    /// the `Result<ConnStats, SQExtError>` response. Returns `None` if the query
    /// times out or any step fails.
    async fn get_downlink_stats(&self) -> Option<super::PathState> {
        let (conn, _state) = self.ensure_connection().await.ok()?;

        const DOWNLINK_STATS_TIMEOUT: Duration = Duration::from_secs(3);

        let result = tokio::time::timeout(DOWNLINK_STATS_TIMEOUT, async {
            let (mut send, mut recv) = conn.open_bi().await?;

            // SQReq::SQExtension tag (u8)
            // SQExtOpcode::Conn tag (u64 BE, value = 1)
            // ExtOpcodeConn::GetConnStats tag (u8)
            let mut req = [0u8; 10];
            req[0] = 0xFF;
            req[1..9].copy_from_slice(&1u64.to_be_bytes());
            req[9] = 0x00;
            send.write_all(&req).await?;
            send.flush().await?;
            let _ = send.finish();

            // Decode Result<ConnStats, SQExtError>
            let tag = recv.read_u8().await?;
            if tag != 0 {
                anyhow::bail!("server returned error tag: {}", tag);
            }

            // ConnStats is #[size_tag]: u32 BE length prefix followed by fields
            let _size = recv.read_u32().await?;
            let lost_packets = recv.read_u64().await?;
            let sent_packets = recv.read_u64().await?;
            let rtt_ms = recv.read_f64().await?;
            let mtu = recv.read_u16().await?;

            anyhow::Ok((lost_packets, sent_packets, rtt_ms, mtu))
        })
        .await;

        match result {
            Ok(Ok((lost_packets, sent_packets, rtt_ms, mtu))) => Some(super::PathState {
                lost_packets,
                sent_packets,
                mtu,
                rtt: rtt_ms as f32,
            }),
            Ok(Err(e)) => {
                debug!("downlink stats query failed: {}", e);
                None
            }
            Err(_) => {
                debug!("downlink stats query timed out after {DOWNLINK_STATS_TIMEOUT:?}");
                None
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
        let (conn, send, recv, _state) = self.open_bistream_with_retry().await?;

        let stats = conn.stats();
        let lost_packets = stats.path.lost_packets;
        let sent_packets = stats.path.sent_packets;
        let rtt = conn.rtt();
        let mtu = stats.path.current_mtu;

        debug!(
            "[{}] lost_packets: {}, sent_packets: {}, rtt: {:?}, mtu: {}",
            self.tag(),
            lost_packets,
            sent_packets,
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
        let (conn, mut send, recv, state) = self.open_bistream_with_retry().await?;

        let target_bytes_dummy = TargetAddr::dummy().to_bytes();
        let mut packet = Vec::with_capacity(1 + target_bytes_dummy.len());

        let mut is_over_unistream = false;
        match self.udp_mod {
            UdpMode::OverStream => {
                packet.push(0x04);
                is_over_unistream = true;
            }
            UdpMode::OverDatagram => {
                packet.push(0x03);
            }
        }
        packet.extend_from_slice(&target_bytes_dummy);
        send.write_all(&packet).await?;
        send.flush().await?;

        let receiver = Arc::new(ShadowUdpReceiver::new(
            state.udp_recv_map.clone(),
            state.udp_recv_map_notify.clone(),
        ));
        run_bistream_recv_listener(recv, receiver.clone());

        let out_packet = Arc::new(ShadowQuicUdpPacket::new(
            is_over_unistream,
            true,
            receiver,
            state.next_context_id.clone(),
            Arc::new(Mutex::new(send)),
            conn.clone(),
        ));
        out_packet.get_send_context_id(target).await?; // init

        Ok(out_packet)
    }

    async fn get_uplink_state(&self) -> Option<super::PathState> {
        self.get_uplink_stats().await
    }

    async fn get_downlink_state(&self) -> Option<super::PathState> {
        self.get_downlink_stats().await
    }
}
