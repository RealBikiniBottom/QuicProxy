use crate::proxy::shadowquic_udp::{
    PerConnectionState, SUNNY_QUIC_AUTH_LEN, ShadowQuicUdpPacket, ShadowUdpReceiver,
    UDP_CONTEXT_ID_RECONNECT_MARGIN, gen_sunny_auth_hash, run_bistream_recv_listener,
    start_datagram_loop, start_unistream_listener,
};
use crate::utils::interface::InterfaceManager;
use crate::utils::quic_wrap::quinn_wrap::QuinnBistream;
use crate::utils::quic_wrap::quinn_wrap::QuinnClient;
use anyhow::{Context, Result};
use async_trait::async_trait;

use std::sync::Arc;
use std::sync::LazyLock;
use std::sync::atomic::Ordering;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Mutex;
use tokio::sync::broadcast::error::RecvError;
use tokio::task::JoinHandle;

use tracing::{debug, info, warn};

use crate::config::OutboundConfig;
use crate::proxy::outbound::{AnyOutbound, AnyStream, LazyHandshakeStream, UdpMode};
use crate::proxy::{TargetAddr, TlsConfig};

use crate::utils::{format_duration, new_io_other_error};

use super::AnyPacket;

const DOWNLINK_STATS_TIMEOUT: Duration = Duration::from_secs(3);

/// Serialized `TargetAddr::dummy()`, sent as the placeholder target in the UDP
/// session handshake (cmd 0x03/0x04).
static DUMMY_TARGET_BYTES: LazyLock<Vec<u8>> = LazyLock::new(|| TargetAddr::dummy().to_bytes());

pub struct ShadowQuicOutbound {
    tag: String,
    address: TargetAddr,

    auth_hash: Option<[u8; 64]>,

    dns_server_name: Option<String>,
    bind_interface: Option<String>,

    connect_timeout: Duration,

    udp_mod: UdpMode,

    /// Prebuilt QUIC client configuration (crypto + transport). Building it
    /// involves loading certificates and rustls setup but the result never
    /// changes between reconnects, so it is created once and reused; only the
    /// UDP socket/endpoint is fresh per connection attempt.
    client_config: Arc<quinn::ClientConfig>,
    sni: String,
    zero_rtt: bool,
    enable_jls: bool,

    cached_client: Arc<
        Mutex<
            Option<(
                Arc<quinn::Connection>,
                Arc<QuinnClient>,
                Arc<PerConnectionState>,
            )>,
        >,
    >,

    /// Background task clearing `cached_client` whenever the network
    /// interface changes. Aborted on drop so it cannot keep the cached QUIC
    /// connection (and its endpoint/socket) alive after this outbound goes
    /// away.
    iface_reset_task: Option<JoinHandle<()>>,
}

impl ShadowQuicOutbound {
    pub fn new(tag: String, cfg: &OutboundConfig) -> Result<Arc<dyn AnyOutbound>> {
        let connect_timeout = cfg.connect_timeout();

        let tls = TlsConfig::from_outbound(cfg)?;

        let udp_mod = match cfg.udp_mode_or("stream") {
            "datagram" => UdpMode::OverDatagram,
            _ => UdpMode::OverStream,
        };

        let mut auth_hash = None;
        if !tls.enable_jls {
            let (username, password) = cfg.credentials(&tag)?;
            auth_hash = Some(gen_sunny_auth_hash(username, password));
        }

        let address = cfg.endpoint(&tag)?;

        let (client_config, sni) = QuinnClient::build_client_config(
            cfg.idle_timeout(),
            !tls.insecure,
            tls.zero_rtt,
            tls.cert.as_deref(),
            tls.sni.clone(),
            tls.alpns.clone(),
            cfg.congestion_controller.clone(),
            tls.jls_username.clone(),
            tls.jls_password.clone(),
            tls.enable_jls,
            cfg.gso,
            cfg.mtu_discoveriy,
            cfg.initial_mtu,
            cfg.min_mtu,
        )
        .with_context(|| {
            format!(
                "[{}] Failed to build ShadowQuic client config (sni={:?} jls={} cert={:?})",
                tag, tls.sni, tls.enable_jls, tls.cert
            )
        })?;

        let zero_rtt = tls.zero_rtt;
        let enable_jls = tls.enable_jls;

        let cached_client = Arc::new(Mutex::new(None));
        let iface_reset_task = InterfaceManager::subscribe().map(|mut rx| {
            let cache = cached_client.clone();
            let tag = tag.clone();
            tokio::spawn(async move {
                loop {
                    match rx.recv().await {
                        Ok(()) => {
                            let mut lock = cache.lock().await;
                            if lock.take().is_some() {
                                info!(
                                    "[{}] reset shadowquic outbound because iface changed",
                                    tag
                                );
                            }
                        }
                        // Lagged means we missed change events, not that the
                        // channel died: reset on the next one instead of
                        // silently exiting the loop.
                        Err(RecvError::Lagged(n)) => {
                            debug!("[{}] iface change watcher lagged by {} events", tag, n);
                        }
                        Err(RecvError::Closed) => break,
                    }
                }
            })
        });

        Ok(Arc::new(Self {
            tag,
            address,
            auth_hash,
            udp_mod,
            client_config,
            sni,
            zero_rtt,
            enable_jls,
            cached_client,
            iface_reset_task,
            dns_server_name: cfg.dns.clone(),
            bind_interface: cfg.bind_interface.clone(),
            connect_timeout,
        }))
    }

    /// Clear the cached connection, but only if it is still the one that
    /// failed: a concurrent caller may have already replaced it with a fresh
    /// connection, which must not be evicted.
    async fn clear_cached_conn(&self, failed: &quinn::Connection) {
        let mut lock = self.cached_client.lock().await;
        let is_failed = matches!(
            &*lock,
            Some((conn, _, _)) if conn.stable_id() == failed.stable_id()
        );
        if is_failed {
            *lock = None;
        }
    }

    async fn ensure_connection(
        &self,
    ) -> anyhow::Result<(Arc<quinn::Connection>, Arc<PerConnectionState>)> {
        // The lock is held across the whole establishment: concurrent callers
        // wait for one shared handshake instead of racing. If they raced, the
        // last writer would overwrite the cache and drop the loser's
        // QuinnClient — dropping it closes the endpoint and tears down
        // connections that were already handed out to other callers.
        let mut lock = self.cached_client.lock().await;

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

        match self.establish_connection().await {
            Ok((conn, client, state)) => {
                info!(
                    "[{}] new quic connection {} to {}",
                    self.tag(),
                    conn.stable_id(),
                    conn.remote_address()
                );
                let result = (conn.clone(), state.clone());
                *lock = Some((conn, client, state));
                Ok(result)
            }
            Err(e) => {
                *lock = None;
                Err(e)
            }
        }
    }

    async fn establish_connection(
        &self,
    ) -> anyhow::Result<(
        Arc<quinn::Connection>,
        Arc<QuinnClient>,
        Arc<PerConnectionState>,
    )> {
        let remote_addr = self.resolve_addr(&self.address).await?;

        let socket = self.new_udp_socket(remote_addr).await?;

        let client = Arc::new(
            QuinnClient::from_config(
                socket.into_std()?,
                self.client_config.clone(),
                self.sni.clone(),
                self.zero_rtt,
                self.enable_jls,
            )
            .with_context(|| {
                format!(
                    "[{}] Failed to create QuinnClient (addr={} sni={})",
                    self.tag(),
                    remote_addr,
                    self.sni
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

        if let Some(auth_hash) = self.auth_hash {
            self.send_auth(&conn, auth_hash).await?;
        }

        let state = Arc::new(PerConnectionState::new());

        match self.udp_mod {
            UdpMode::OverStream => start_unistream_listener(
                conn.clone(),
                state.udp_recv_map.clone(),
                state.udp_recv_map_notify.clone(),
                self.connect_timeout,
            ),
            UdpMode::OverDatagram => start_datagram_loop(
                conn.clone(),
                state.udp_recv_map.clone(),
                state.waiting_datagram_buffer.clone(),
                state.udp_recv_map_notify.clone(),
            ),
        }

        Ok((conn, client, state))
    }

    /// Send credentials on the first bistream. The server requires auth before
    /// serving any request and closes the connection when it fails, so any
    /// error here must abort establishment instead of caching an unusable
    /// connection.
    async fn send_auth(
        &self,
        conn: &quinn::Connection,
        auth_hash: [u8; SUNNY_QUIC_AUTH_LEN],
    ) -> anyhow::Result<()> {
        let (mut send, _recv) = tokio::time::timeout(self.connect_timeout, conn.open_bi())
            .await
            .map_err(|_| {
                new_io_other_error(format!(
                    "[{}] open auth bistream timed out after {:?}",
                    self.tag(),
                    self.connect_timeout
                ))
            })?
            .with_context(|| format!("[{}] failed to open auth bistream", self.tag()))?;

        let mut auth_packet = Vec::with_capacity(1 + SUNNY_QUIC_AUTH_LEN);
        auth_packet.push(0x05);
        auth_packet.extend_from_slice(&auth_hash);

        send.write_all(&auth_packet)
            .await
            .context("failed to send auth packet")?;
        send.flush().await.context("failed to flush auth packet")?;
        let _ = send.finish();

        Ok(())
    }

    /// Open a stream on the cached connection, retrying once on a fresh
    /// connection if the cached one turns out to be dead.
    async fn open_stream_with_retry<T, F, Fut>(
        &self,
        kind: &str,
        open: F,
    ) -> anyhow::Result<(Arc<quinn::Connection>, T, Arc<PerConnectionState>)>
    where
        F: Fn(Arc<quinn::Connection>) -> Fut,
        Fut: std::future::Future<Output = Result<T, quinn::ConnectionError>>,
    {
        let (conn, state) = self.ensure_connection().await?;

        match open(conn.clone()).await {
            Ok(stream) => Ok((conn, stream, state)),

            Err(e) => {
                warn!(
                    "[{}] cached ShadowQuic connection invalid ({} stream error: {}), reconnecting",
                    self.tag(),
                    kind,
                    e
                );

                self.clear_cached_conn(&conn).await;

                let (retry_conn, retry_state) = self.ensure_connection().await?;

                let stream = open(retry_conn.clone()).await.with_context(|| {
                    format!("failed to open {} stream after reconnection", kind)
                })?;

                Ok((retry_conn, stream, retry_state))
            }
        }
    }

    async fn open_bistream_with_retry(
        &self,
    ) -> anyhow::Result<(
        Arc<quinn::Connection>,
        quinn::SendStream,
        quinn::RecvStream,
        Arc<PerConnectionState>,
    )> {
        let (conn, (send, recv), state) = self
            .open_stream_with_retry("bi", |conn| async move { conn.open_bi().await })
            .await?;
        Ok((conn, send, recv, state))
    }

    /// open_bistream_with_retry, but refuses a connection whose shared UDP
    /// context-id space is (nearly) exhausted and forces a fresh connection.
    ///
    /// PerConnectionState::next_context_id is shared by all UDP sessions on
    /// one QUIC connection and is never recycled, so a long-lived connection
    /// eventually runs out of u16 ids. Handing it out to another session at
    /// that point would make that session trip the u16::try_from failure in
    /// get_send_context_id, which closes the whole connection and kills
    /// every session on it. Instead the cache is cleared so the next attempt
    /// establishes a brand-new connection with a fresh counter (starts at 1),
    /// which ensure_connection always creates.
    async fn open_udp_bistream_with_capacity(
        &self,
    ) -> anyhow::Result<(
        Arc<quinn::Connection>,
        quinn::SendStream,
        quinn::RecvStream,
        Arc<PerConnectionState>,
    )> {
        for _ in 0..2 {
            let (conn, send, recv, state) = self.open_bistream_with_retry().await?;
            let used = state.next_context_id.load(Ordering::Relaxed);
            if used < (u16::MAX as u32) - UDP_CONTEXT_ID_RECONNECT_MARGIN {
                return Ok((conn, send, recv, state));
            }

            warn!(
                "[{}] UDP context-id space nearly exhausted ({} used), forcing a new connection",
                self.tag(),
                used
            );
            self.clear_cached_conn(&conn).await;
        }

        anyhow::bail!(
            "[{}] could not obtain a connection with available UDP context ids",
            self.tag()
        )
    }

    pub async fn open_unistream_with_retry(
        &self,
    ) -> anyhow::Result<(
        Arc<quinn::Connection>,
        quinn::SendStream,
        Arc<PerConnectionState>,
    )> {
        let (conn, send, state) = self
            .open_stream_with_retry("uni", |conn| async move { conn.open_uni().await })
            .await?;
        Ok((conn, send, state))
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
        self.connect_timeout
    }

    async fn connect_stream_base(&self) -> anyhow::Result<AnyStream> {
        let (conn, send, recv, _state) = self.open_bistream_with_retry().await?;

        if tracing::enabled!(tracing::Level::DEBUG) {
            let stats = conn.stats();
            debug!(
                "[{}] lost_packets: {}, sent_packets: {}, rtt: {}, mtu: {}",
                self.tag(),
                stats.path.lost_packets,
                stats.path.sent_packets,
                format_duration(conn.rtt()),
                stats.path.current_mtu,
            );
        }

        Ok(Box::new(QuinnBistream::new(send, recv)))
    }

    async fn connect_stream_with(
        &self,
        target: &TargetAddr,
        stream: AnyStream,
    ) -> anyhow::Result<AnyStream> {
        let target_bytes = target.to_bytes();
        let mut handshake = Vec::with_capacity(1 + target_bytes.len());
        handshake.push(0x01);
        handshake.extend_from_slice(&target_bytes);

        // Defer the handshake to the first payload write so it can go out
        // together with the first request bytes instead of a separate
        // write+flush round.
        Ok(Box::new(LazyHandshakeStream::new(stream, handshake)))
    }

    async fn connect_packet(&self, target: &TargetAddr) -> anyhow::Result<Arc<dyn AnyPacket>> {
        let (conn, mut send, recv, state) = self.open_udp_bistream_with_capacity().await?;

        let is_over_unistream = matches!(self.udp_mod, UdpMode::OverStream);
        let mut packet = Vec::with_capacity(1 + DUMMY_TARGET_BYTES.len());
        packet.push(if is_over_unistream { 0x04 } else { 0x03 });
        packet.extend_from_slice(&DUMMY_TARGET_BYTES);
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

impl Drop for ShadowQuicOutbound {
    fn drop(&mut self) {
        if let Some(handle) = self.iface_reset_task.take() {
            handle.abort();
        }
    }
}
