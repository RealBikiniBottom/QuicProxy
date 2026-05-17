use crate::config::OutboundConfig;
use crate::dns::resolve_target;
use crate::proxy::outbound::{AnyOutbound, AnyPacket, AnyStream};
use crate::proxy::{SessionCloser, SourceAddr, TargetAddr};
use anyhow::{Context, Result, bail};
use async_trait::async_trait;
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
    ip_map: DashMap<TargetAddr, SocketAddr>,
    closer: Arc<SessionCloser>,
}

use bytes::{Bytes, BytesMut};

#[async_trait]
impl AnyPacket for DirectUdpOutbound {
    fn closer(&self) -> Arc<SessionCloser> {
        self.closer.clone()
    }

    async fn send_to(&self, buf: Bytes, target: &TargetAddr, _from: &SourceAddr) -> Result<usize> {
        let ip = match self.ip_map.get(target) {
            Some(res) => res.clone(),
            None => {
                let addr = resolve_target(target, self.dns.as_deref()).await?;
                self.ip_map.insert(target.clone(), addr);
                addr
            }
        };

        self.socket
            .send_to(&buf, ip)
            .await
            .context("send_to failed")
    }

    async fn recv_from(&self) -> Result<(SourceAddr, TargetAddr, Bytes)> {
        let mut buf = BytesMut::with_capacity(1024 * 2);
        let (n, addr) = self.socket.recv_buf_from(&mut buf).await?;
        buf.truncate(n);
        Ok((TargetAddr::Ip(addr), TargetAddr::dummy(), buf.freeze()))
    }

    async fn recv_many(&self) -> anyhow::Result<Vec<(TargetAddr, TargetAddr, Bytes)>> {
        let first = self.recv_from().await?;
        let mut results = vec![first];
        loop {
            let mut buf = BytesMut::with_capacity(1024 * 2);
            if let Result::Ok((n, addr)) = self.socket.try_recv_buf_from(&mut buf) {
                buf.truncate(n);
                results.push((TargetAddr::Ip(addr), TargetAddr::dummy(), buf.freeze()));
            } else {
                break;
            }
        }
        Ok(results)
    }
}

impl DirectOutbound {
    pub fn new(tag: String, cfg: &OutboundConfig) -> Result<Arc<dyn AnyOutbound>> {
        Ok(Arc::new(Self {
            tag,
            connect_timeout: Duration::from_secs(cfg.connect_timeout.unwrap_or(30)),
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
            ip_map: DashMap::new(),
            closer: Arc::new(SessionCloser::new()),
        });
        Ok(inner)
    }
}
