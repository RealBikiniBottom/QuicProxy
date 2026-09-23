use anyhow::bail;
use arc_swap::ArcSwap;
use async_trait::async_trait;
use dashmap::DashMap;
use quinn::{ConnectionError, VarInt};
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, OnceLock};
use std::sync::atomic::Ordering;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::sync::Mutex;

use crate::config::{AuthUser, InboundConfig};
use crate::proxy::inbound::AnyInbound;
use crate::proxy::observe::{UserAccount, get_observer};
use crate::proxy::outbound::UdpMode;
use crate::proxy::router::Router;
use crate::proxy::router::get_router;
use crate::proxy::shadowquic_udp::{
    ExtensionRequest, PerConnectionState, ShadowQuicUdpPacket, ShadowUdpReceiver,
    UDP_CONTEXT_ID_RECONNECT_MARGIN, gen_sunny_auth_hash, read_context_id,
    read_extension_request, read_request_head, read_sunny_auth, run_bistream_recv_listener,
    start_datagram_loop, start_unistream_listener, write_conn_stats_response,
    write_ext_error_not_available,
};
use crate::proxy::{TargetAddr, TlsConfig};
use anyhow::Context;

use crate::utils::quic_wrap::quinn_wrap::QuinnBistream;
use crate::utils::quic_wrap::quinn_wrap::QuinnServer;
use crate::utils::quic_wrap::quinn_wrap::ServerConfigUpdater;

use tracing::{Instrument, debug, error, field, info, info_span};

/// Application close code sent to the peer when the connection handler exits.
const SHADOWQUIC_CLOSE_CODE: u32 = 263;

pub struct ShadowQuicInbound {
    tag: String,
    address: String,
    port: u16,
    tls: TlsConfig,
    users: Arc<ArcSwap<Vec<AuthUser>>>,
    jls_updater: OnceLock<Arc<ServerConfigUpdater>>,
    /// Live QUIC connections keyed by remote address, paired with the user
    /// (JLS iv / sunnyquic username) that authentication resolved to. Used to
    /// terminate a user's sessions when it is removed at runtime.
    conns: Arc<DashMap<SocketAddr, (Arc<quinn::Connection>, Option<Arc<str>>)>>,
    enable_gso: bool,
    enable_mtudis: bool,
    min_mtu: u16,
    initial_mtu: u16,

    congestion_controller: Option<String>,
    idle_timeout: Duration,
}

impl ShadowQuicInbound {
    pub fn new(tag: String, cfg: &InboundConfig, users: Vec<AuthUser>) -> anyhow::Result<Self> {
        let tls = TlsConfig::from_inbound(cfg)?;

        if !tls.enable && !tls.enable_jls {
            anyhow::bail!("ShadowQuic inbound requires TLS to be enabled");
        }

        if !tls.enable_jls && users.is_empty() {
            anyhow::bail!("ShadowQuic inbound '{}' requires username and password", tag);
        }

        let users = Arc::new(ArcSwap::from_pointee(users));

        let (address, port) = cfg.endpoint()?;

        Ok(Self {
            tag,
            users,
            jls_updater: OnceLock::new(),
            conns: Arc::new(DashMap::new()),
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
        user: Option<UserAccount>,
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
                user,
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
        let initial_users = self.users.load().as_ref().clone();
        let mut listener = QuinnServer::new(
            listen_addr,
            self.idle_timeout,
            self.tls.cert.as_deref(),
            self.tls.key.as_deref(),
            self.congestion_controller.clone(),
            self.tls.sni.clone(),
            self.tls.alpns.clone(),
            self.tls.zero_rtt,
            &initial_users,
            self.tls.enable_jls,
            self.enable_gso,
            self.enable_mtudis,
            self.initial_mtu,
            self.min_mtu,
        )
        .with_context(|| format!("QUIC server failed to listen on {}", listen_addr))?;

        if self.tls.enable_jls {
            let _ = self.jls_updater.set(listener.updater());
        }

        let is_jls = self.tls.enable_jls;
        let users_store = self.users.clone();
        let session_timeout = self.idle_timeout();
        let tag = self.tag.clone();
        let router = get_router()?;
        let conns = self.conns.clone();

        info!("ShadowQuic inbound listening on {}", listen_addr);

        loop {
            match listener.accept().await {
                Ok(conn) => {
                    info!("Accepted QUIC connection from {}", conn.remote_address());

                    let per_conn = Arc::new(PerConnectionState::new());
                    let router = router.clone();
                    let tag = tag.clone();
                    let users_store = users_store.clone();
                    let conns = conns.clone();
                    let remote_addr = conn.remote_address();

                    tokio::spawn(async move {
                        // Register the connection so a runtime remove_user can
                        // close it. `authed` starts as the JLS identity (known
                        // at handshake time) and is filled in after sunnyquic
                        // auth for non-JLS connections.
                        conns.insert(remote_addr, (conn.clone(), None));

                        let res: anyhow::Result<()> = async {
                            let observer = get_observer();
                            let mut authed_user: Option<UserAccount> = if is_jls {
                                conn.jls_chosen_user().and_then(|name| {
                                    observer.as_ref().and_then(|o| o.user_account(&name))
                                })
                            } else {
                                None
                            };
                            if let Some(user) = &authed_user
                                && let Some(mut entry) = conns.get_mut(&remote_addr)
                            {
                                entry.1 = Some(user.username.clone());
                            }
                            let has_users = users_store.load().iter().next().is_some();
                            let mut is_authed = is_jls || !has_users;
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
                                    let received =
                                        read_sunny_auth(&mut bistream, session_timeout)
                                            .await
                                            .context("auth failed")?;
                                    authed_user = observer
                                        .as_ref()
                                        .and_then(|o| o.authenticate(&tag, &received))
                                        .map(|(username, stats)| UserAccount {
                                            username: Arc::from(username.as_str()),
                                            stats,
                                        });
                                    let local_ok = users_store.load().iter().any(|u| {
                                        gen_sunny_auth_hash(&u.username, &u.password) == received
                                    });
                                    if authed_user.is_none() && !local_ok {
                                        bail!("Invalid auth hash");
                                    }
                                    if let Some(mut entry) = conns.get_mut(&remote_addr) {
                                        entry.1 = authed_user
                                            .as_ref()
                                            .map(|u| u.username.clone());
                                    }

                                    is_authed = true;
                                    info!("Sunnyquic auth ok");
                                    continue;
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
                                let user = authed_user.clone();
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
                                                    .dispatch_stream(
                                                        bistream, &target, &tag, user,
                                                    )
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
                                                    user,
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

                        conns.remove(&remote_addr);
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

    fn supports_users(&self) -> bool {
        true
    }

    async fn add_user(&self, user: &AuthUser) -> anyhow::Result<()> {
        let mut users = self.users.load().as_ref().clone();
        match users.iter_mut().find(|u| u.username == user.username) {
            Some(existing) => existing.password = user.password.clone(),
            None => users.push(user.clone()),
        }
        self.users.store(Arc::new(users.clone()));
        if let Some(updater) = self.jls_updater.get() {
            updater.update_jls_users(&users)?;
        }
        Ok(())
    }

    async fn remove_user(&self, username: &str) -> anyhow::Result<()> {
        let users: Vec<AuthUser> = self
            .users
            .load()
            .iter()
            .filter(|u| u.username != username)
            .cloned()
            .collect();
        self.users.store(Arc::new(users.clone()));
        if let Some(updater) = self.jls_updater.get() {
            updater.update_jls_users(&users)?;
        }
        // Terminate the removed user's live sessions: set_server_config only
        // affects new handshakes, so existing connections would otherwise keep
        // proxying with the now-revoked credential.
        let stale: Vec<SocketAddr> = self
            .conns
            .iter()
            .filter(|e| e.value().1.as_deref() == Some(username))
            .map(|e| *e.key())
            .collect();
        for addr in stale {
            if let Some((_, (conn, _))) = self.conns.remove(&addr) {
                conn.close(VarInt::from_u32(SHADOWQUIC_CLOSE_CODE), b"user removed");
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_inbound(users: Vec<AuthUser>) -> ShadowQuicInbound {
        let cfg: InboundConfig = serde_json5::from_str(
            r#"{ type: "shadowquic", address: "127.0.0.1", port: 0, username: "seed", password: "pw", tls: { enable: true } }"#,
        )
        .unwrap();
        ShadowQuicInbound::new("sq_in".to_string(), &cfg, users).unwrap()
    }

    fn usernames(inbound: &ShadowQuicInbound) -> Vec<String> {
        inbound
            .users
            .load()
            .iter()
            .map(|u| u.username.clone())
            .collect()
    }

    #[tokio::test]
    async fn add_user_appends_and_updates() {
        let inbound = test_inbound(vec![AuthUser {
            username: "seed".to_string(),
            password: "pw".to_string(),
        }]);

        inbound
            .add_user(&AuthUser {
                username: "alice".to_string(),
                password: "a1".to_string(),
            })
            .await
            .unwrap();
        assert_eq!(usernames(&inbound), vec!["seed", "alice"]);

        // Same username updates the password in place.
        inbound
            .add_user(&AuthUser {
                username: "alice".to_string(),
                password: "a2".to_string(),
            })
            .await
            .unwrap();
        let users = inbound.users.load();
        assert_eq!(users.len(), 2);
        assert_eq!(
            users.iter().find(|u| u.username == "alice").unwrap().password,
            "a2"
        );
    }

    #[tokio::test]
    async fn remove_user_drops_only_the_target() {
        let inbound = test_inbound(vec![
            AuthUser {
                username: "seed".to_string(),
                password: "pw".to_string(),
            },
            AuthUser {
                username: "alice".to_string(),
                password: "a1".to_string(),
            },
        ]);

        inbound.remove_user("alice").await.unwrap();

        assert_eq!(usernames(&inbound), vec!["seed"]);
    }
}
