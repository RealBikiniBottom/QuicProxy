use crate::config::InboundConfig;
use crate::proxy::inbound::AnyInbound;
use crate::proxy::inbound::http::{self, StreamHandler};
use crate::proxy::inbound::socks5::{self, Socks5Handler};
use crate::proxy::router::get_router;
use crate::utils::{format_duration, now};
use anyhow::{Context, bail};
use async_trait::async_trait;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::time;
use tracing::{Instrument, error, field, info, info_span};

use super::{create_tcp_listener, setup_system_proxy};

pub struct MixInbound {
    tag: String,
    idle_timeout: Duration,
    addr: SocketAddr,
    set_system_proxy: bool,
    users: Option<Vec<socks5::User>>,
}

impl MixInbound {
    pub fn new(tag: String, cfg: &InboundConfig) -> anyhow::Result<Self> {
        let users = match (&cfg.username, &cfg.password) {
            (Some(u), Some(p)) => Some(vec![socks5::User {
                username: u.clone(),
                password: p.clone(),
            }]),
            _ => None,
        };

        let addr = cfg.socket_addr(&tag)?;

        Ok(Self {
            tag,
            idle_timeout: cfg.idle_timeout(),
            addr,
            set_system_proxy: cfg.set_system_proxy,
            users,
        })
    }
}

#[async_trait]
impl AnyInbound for MixInbound {
    fn protocol(&self) -> &str {
        "mix"
    }

    fn idle_timeout(&self) -> Duration {
        self.idle_timeout
    }

    async fn listen(&self) -> anyhow::Result<()> {
        let listener = create_tcp_listener(self.addr).await?;
        info!("Mix Inbound listening on {}", self.addr);

        let _proxy_guard = setup_system_proxy(
            self.set_system_proxy,
            &self.addr.ip().to_string(),
            self.addr.port(),
        )?;

        let http_users = self.users.as_ref().map(|users| {
            Arc::new(
                users
                    .iter()
                    .map(|u| http::User {
                        username: u.username.clone(),
                        password: u.password.clone(),
                    })
                    .collect(),
            )
        });
        let tag = self.tag.clone();

        loop {
            let (socket, peer_addr) = listener.accept().await?;
            let local_addr = socket.local_addr().ok();
            let tag_clone = tag.clone();
            let start_time = now();
            let router = get_router();
            let socks5_users = self.users.clone();
            let http_users = http_users.clone();
            info!("Accepted proxy request from: {}", peer_addr.to_string());

            let timeout_duration = self.idle_timeout();
            tokio::spawn(async move {
                let result: anyhow::Result<()> = async {
                    let mut buf = [0u8; 1];

                    match time::timeout(timeout_duration, socket.peek(&mut buf)).await {
                        Ok(Ok(_)) => {}
                        Ok(Err(e)) => return Err(e.into()),
                        Err(_) => bail!("Mix peek timeout after {:?}", timeout_duration),
                    }

                    if buf[0] == 0x05 {
                        let result = time::timeout(
                            timeout_duration,
                            socks5::handle_client(socket, peer_addr, local_addr, socks5_users),
                        )
                        .await
                        .context("Mix (SOCKS5) handshake timeout")?
                        .context("Mix (SOCKS5) error")?;

                        match result {
                            Some(Socks5Handler::Stream(stream, target)) => {
                                let span = info_span!(
                                    "tcp",
                                    i = tag_clone,
                                    s = peer_addr.to_string(),
                                    d = field::Empty,
                                    r = field::Empty,
                                    o = field::Empty
                                );
                                info!(
                                    "Mix (SOCKS5) parsed dst: {} cost {}",
                                    target,
                                    format_duration(start_time.elapsed())
                                );

                                router
                                    .dispatch_stream(Box::new(stream), &target, &tag_clone)
                                    .instrument(span)
                                    .await
                                    .context("Routing stream error")?;
                            }
                            Some(Socks5Handler::Packet(udp_socket, client_addr, tcp_socket)) => {
                                info!(
                                    "Mix (SOCKS5) UDP ASSOCIATE from {}. Routing packets...",
                                    peer_addr
                                );

                                socks5::start_udp_worker(
                                    router.clone(),
                                    udp_socket,
                                    client_addr,
                                    tcp_socket,
                                    timeout_duration,
                                    tag_clone.clone(),
                                )
                                .await;
                            }
                            None => {}
                        }
                    } else {
                        let result = time::timeout(
                            timeout_duration,
                            http::handle_client(socket, http_users),
                        )
                        .await
                        .context("Mix (HTTP) handshake timeout")?
                        .context("Mix (HTTP) error")?;

                        if let Some(StreamHandler { stream, target }) = result {
                            info!(
                                "Mix (HTTP) parsed dst: {} cost: {}",
                                target,
                                format_duration(start_time.elapsed())
                            );

                            router
                                .dispatch_stream(Box::new(stream), &target, &tag_clone)
                                .await
                                .context("Routing error")?;
                        }
                    }

                    Ok(())
                }
                .await;

                if let Err(e) = result {
                    error!("Mix handler error: {:?}", e);
                }
            });
        }
    }
}
