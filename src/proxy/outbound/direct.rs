use crate::config::OutboundConfig;
use crate::dns::resolve_target;
use crate::proxy::outbound::{AnyOutbound, AnyPacket, AnyStream, PacketInfo};
use crate::proxy::{SessionCloser, SourceAddr, TargetAddr};
use crate::utils::socket::udp_recv;
use anyhow::{Result, bail};
use crate::utils::error::Context;
use async_trait::async_trait;
use bytes::Bytes;
use dashmap::DashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::net::UdpSocket;

pub struct DirectOutbound {
    tag: String,
    connect_timeout: Duration,
    bind_interface: Option<String>,
    dns: Option<String>,
}

struct DirectUdpOutbound {
    socket: UdpSocket,
    dns: Option<String>,
    /// Domain targets this session sent to, and the address each one resolved to.
    resolved: DashMap<TargetAddr, SocketAddr>,
    /// Reverse of `resolved`, so replies are reported as coming from the domain.
    reverse: DashMap<SocketAddr, TargetAddr>,
    closer: Arc<SessionCloser>,
}

impl DirectUdpOutbound {
    pub fn reverse(&self, ip: SocketAddr) -> anyhow::Result<TargetAddr> {
        Ok(match self.reverse.get(&ip) {
            Some(target) => target.clone(),
            None => TargetAddr::Ip(ip),
        })
    }
}

#[async_trait]
impl AnyPacket for DirectUdpOutbound {
    fn closer(&self) -> Option<Arc<SessionCloser>> {
        Some(self.closer.clone())
    }

    async fn send_to(&self, buf: Bytes, _from: &SourceAddr, target: &TargetAddr) -> Result<usize> {
        let ip = match target {
            TargetAddr::Ip(socket_addr) => *socket_addr,
            TargetAddr::Domain(_, _) => {
                let cached = self.resolved.get(target).map(|addr| *addr);
                match cached {
                    Some(addr) => addr,
                    None => {
                        let addr = resolve_target(target, self.dns.as_deref()).await?;
                        self.resolved.insert(target.clone(), addr);
                        self.reverse.insert(addr, target.clone());
                        addr
                    }
                }
            }
        };

        self.socket
            .send_to(&buf, ip)
            .await
            .context("send_to failed")
    }

    async fn recv_from(&self) -> Result<PacketInfo> {
        let (data, addr) = udp_recv::recv_from(&self.socket).await?;
        Ok((self.reverse(addr)?, TargetAddr::dummy(), data))
    }

    async fn recv_many(&self, packets: &mut Vec<PacketInfo>) -> anyhow::Result<()> {
        let first = self.recv_from().await?;
        packets.clear();
        packets.push(first);
        while let Ok((data, addr)) = udp_recv::try_recv_from(&self.socket) {
            packets.push((self.reverse(addr)?, TargetAddr::dummy(), data));
        }
        Ok(())
    }
}

impl DirectOutbound {
    pub fn new(tag: String, cfg: &OutboundConfig) -> Result<Arc<dyn AnyOutbound>> {
        Ok(Arc::new(Self {
            tag,
            connect_timeout: cfg.connect_timeout(),
            bind_interface: cfg.bind_interface.clone(),
            dns: cfg.dns.clone(),
        }))
    }
}

#[async_trait]
impl AnyOutbound for DirectOutbound {
    fn tag(&self) -> &str {
        &self.tag
    }

    fn protocol(&self) -> &str {
        "direct"
    }

    fn dns_server_name(&self) -> Option<&str> {
        self.dns.as_deref()
    }

    fn bind_interface(&self) -> Option<&str> {
        self.bind_interface.as_deref()
    }

    fn connect_timeout(&self) -> Duration {
        self.connect_timeout
    }

    async fn connect_stream(&self, target: &TargetAddr) -> Result<AnyStream> {
        let addr = resolve_target(target, self.dns_server_name()).await?;
        let stream = self.new_tcp_stream(addr).await?;

        Ok(Box::new(stream))
    }

    async fn connect_stream_base(&self) -> Result<AnyStream> {
        bail!("not implemented")
    }

    async fn connect_stream_with(
        &self,
        _target: &TargetAddr,
        _stream: AnyStream,
    ) -> Result<AnyStream> {
        bail!("not implemented")
    }

    async fn connect_packet(&self, target: &TargetAddr) -> Result<Arc<dyn AnyPacket>> {
        let addr = resolve_target(target, self.dns_server_name()).await?;
        let socket = self.new_udp_socket(addr).await?;

        let inner = Arc::new(DirectUdpOutbound {
            socket,
            dns: self.dns.clone(),
            resolved: DashMap::new(),
            reverse: DashMap::new(),
            closer: Arc::new(SessionCloser::new()),
        });
        Ok(inner)
    }
}
