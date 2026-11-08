//! Server side of the built-in speed test.
//!
//! Route the reserved domain to this outbound on a quicproxy server:
//!
//! ```json5
//! "outbounds": { "servers": { "speedtest": { "type": "speedtest" } } },
//! "router": { "rules": [ { "domain": ["speedtest.quicproxy.internal"], "outbound": "speedtest" } ] }
//! ```
//!
//! TCP streams are answered in-process by [`proto::serve`] and UDP datagrams
//! are echoed, so nothing is sent beyond the server. Only users who passed the
//! inbound's authentication reach the router, and their speed test traffic is
//! counted like any other traffic.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Result, bail};
use async_trait::async_trait;
use bytes::Bytes;
use tokio::sync::{Mutex, mpsc};
use tracing::debug;

use crate::config::OutboundConfig;
use crate::proxy::outbound::{AnyOutbound, AnyPacket, AnyStream, PacketInfo};
use crate::proxy::{SessionCloser, SourceAddr, TargetAddr};
use crate::utils::speedtest::proto;

const DUPLEX_BUFFER: usize = 512 * 1024;
const UDP_QUEUE: usize = 1024;

pub struct SpeedtestOutbound {
    tag: String,
    connect_timeout: Duration,
}

impl SpeedtestOutbound {
    pub fn new(tag: String, cfg: &OutboundConfig) -> Result<Arc<dyn AnyOutbound>> {
        Ok(Arc::new(Self {
            tag,
            connect_timeout: cfg.connect_timeout(),
        }))
    }
}

fn check_target(target: &TargetAddr, port: u16) -> Result<()> {
    match target {
        TargetAddr::Domain(domain, p)
            if *p == port && domain.eq_ignore_ascii_case(proto::SPEEDTEST_DOMAIN) =>
        {
            Ok(())
        }
        _ => bail!(
            "speedtest outbound only serves {}:{}, got {}",
            proto::SPEEDTEST_DOMAIN,
            port,
            target
        ),
    }
}

#[async_trait]
impl AnyOutbound for SpeedtestOutbound {
    fn tag(&self) -> &str {
        &self.tag
    }

    fn protocol(&self) -> &str {
        "speedtest"
    }

    fn dns_server_name(&self) -> Option<&str> {
        None
    }

    fn connect_timeout(&self) -> Duration {
        self.connect_timeout
    }

    async fn connect_stream(&self, target: &TargetAddr) -> Result<AnyStream> {
        check_target(target, proto::TCP_PORT)?;
        let (client, server) = tokio::io::duplex(DUPLEX_BUFFER);
        tokio::spawn(async move {
            if let Err(e) = proto::serve(server).await {
                debug!("speedtest stream ended: {e}");
            }
        });
        Ok(Box::new(client))
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
        check_target(target, proto::UDP_PORT)?;
        let (tx, rx) = mpsc::channel(UDP_QUEUE);
        Ok(Arc::new(EchoPacket {
            tx,
            rx: Mutex::new(rx),
            closer: Arc::new(SessionCloser::new()),
        }))
    }
}

/// Echoes every datagram back as if the speed test domain had answered it.
struct EchoPacket {
    tx: mpsc::Sender<(TargetAddr, Bytes)>,
    rx: Mutex<mpsc::Receiver<(TargetAddr, Bytes)>>,
    closer: Arc<SessionCloser>,
}

#[async_trait]
impl AnyPacket for EchoPacket {
    fn closer(&self) -> Option<Arc<SessionCloser>> {
        Some(self.closer.clone())
    }

    async fn send_to(&self, buf: Bytes, _from: &SourceAddr, target: &TargetAddr) -> Result<usize> {
        check_target(target, proto::UDP_PORT)?;
        let len = buf.len();
        if len > proto::MAX_UDP_PAYLOAD {
            // Treat oversized datagrams like a too-small path MTU: drop them.
            return Ok(len);
        }
        // A full queue drops the datagram, which the client counts as loss.
        let _ = self.tx.try_send((target.clone(), buf));
        Ok(len)
    }

    async fn recv_from(&self) -> Result<PacketInfo> {
        let mut rx = self.rx.lock().await;
        tokio::select! {
            item = rx.recv() => match item {
                Some((from, buf)) => Ok((from, TargetAddr::dummy(), buf)),
                None => bail!("speedtest echo closed"),
            },
            _ = self.closer.wait() => bail!("speedtest echo closed"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn outbound() -> SpeedtestOutbound {
        SpeedtestOutbound {
            tag: "speedtest".into(),
            connect_timeout: Duration::from_secs(5),
        }
    }

    #[tokio::test]
    async fn rejects_other_targets() {
        let out = outbound();
        let other = TargetAddr::Domain("example.com".into(), 80);
        assert!(out.connect_stream(&other).await.is_err());
        assert!(out.connect_packet(&other).await.is_err());
        let wrong_port = TargetAddr::Domain(proto::SPEEDTEST_DOMAIN.into(), 80);
        assert!(out.connect_stream(&wrong_port).await.is_err());
    }

    #[tokio::test]
    async fn serves_tcp_commands() {
        let out = outbound();
        let target = TargetAddr::Domain(proto::SPEEDTEST_DOMAIN.into(), proto::TCP_PORT);
        let mut s = out.connect_stream(&target).await.unwrap();
        proto::client_handshake(&mut s).await.unwrap();
        s.write_u8(proto::CMD_PING).await.unwrap();
        s.write_u64(7).await.unwrap();
        assert_eq!(s.read_u8().await.unwrap(), proto::CMD_PING);
        assert_eq!(s.read_u64().await.unwrap(), 7);
    }

    #[tokio::test]
    async fn echoes_udp() {
        let out = outbound();
        let target = TargetAddr::Domain(proto::SPEEDTEST_DOMAIN.into(), proto::UDP_PORT);
        let p = out.connect_packet(&target).await.unwrap();
        p.send_to(Bytes::from_static(b"hello"), &TargetAddr::dummy(), &target)
            .await
            .unwrap();
        let (from, _, buf) = p.recv_from().await.unwrap();
        assert_eq!(from, target);
        assert_eq!(&buf[..], b"hello");
    }
}
