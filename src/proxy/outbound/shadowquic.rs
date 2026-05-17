use crate::proxy::shadowquic_udp::{
    PerConnectionState, ShadowQuicUdpPacket, ShadowUdpReceiver, gen_sunny_auth_hash,
    run_bistream_recv_listener, start_datagram_loop, start_udp_session_cleaner,
    start_unistream_listener,
};
use crate::utils::quic_wrap::quinn_wrap::QuinnBistream;
use crate::utils::quic_wrap::quinn_wrap::QuinnClient;
use anyhow::{Context, Result};
use async_trait::async_trait;

use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::sync::Mutex;

use tracing::{info, warn};

use crate::config::OutboundConfig;
use crate::proxy::outbound::{AnyOutbound, AnyStream, UdpMode};
use crate::proxy::{QuicTlsConfig, TargetAddr};

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
    enable_mtudis: bool,
    min_mtu: u16,
    initial_mtu: u16,

    udp_mod: UdpMode,

    cached: Mutex<
        Option<(
            Arc<quinn::Connection>,
            Arc<QuinnClient>,
            Arc<PerConnectionState>,
        )>,
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

        Ok(Arc::new(Self {
            tag,
            address,
            port,
            tls,
            connect_timeout,
            idle_timeout,
            auth_hash,
            udp_mod,
            cached: Mutex::new(None),
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
        let mut lock = self.cached.lock().await;
        *lock = None;
    }

    async fn ensure_connection(
        &self,
    ) -> anyhow::Result<(Arc<quinn::Connection>, Arc<PerConnectionState>)> {
        {
            let lock = self.cached.lock().await;
            if let Some((ref conn, _, ref state)) = *lock {
                if conn.close_reason().is_none() {
                    info!("reuse quic connection {}", conn.stable_id());
                    return Ok((conn.clone(), state.clone()));
                }
                info!("exists connection closed: {:?}", conn.close_reason());
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
                self.enable_mtudis,
                self.initial_mtu,
                self.min_mtu,
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
            let mut lock = self.cached.lock().await;
            *lock = Some((conn.clone(), client, state.clone()));
        }

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
        let (conn, mut send, recv, state) = self.open_bistream_with_retry().await?;

        let target_bytes_dummy = TargetAddr::dummy().to_bytes();
        let mut packet = Vec::with_capacity(1 + target_bytes_dummy.len());

        let mut is_over_unistream = true;
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
            receiver,
            state.next_context_id.clone(),
            Arc::new(Mutex::new(send)),
            conn.clone(),
        ));
        out_packet.get_send_context_id(target).await?; // init

        Ok(out_packet)
    }
}
