pub mod vmess_impl;

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use async_trait::async_trait;
use tokio::sync::Mutex;
use tokio::time::timeout;

use crate::config::OutboundConfig;
use crate::proxy::outbound::{AnyOutbound, AnyPacket, AnyStream, PacketInfo};
use crate::proxy::{SourceAddr, TargetAddr};
use crate::utils::new_io_other_error;

use bytes::Bytes;
use futures::{SinkExt, StreamExt};

use self::vmess_impl::{Builder, OutboundDatagramVmess, VmessOption};

pub struct VmessOutbound {
    tag: String,
    server: TargetAddr,
    uuid: String,
    alter_id: u16,
    security: String,
    #[allow(dead_code)]
    udp: bool,
    connect_timeout: Duration,
    dns_server_name: Option<String>,
    bind_interface: Option<String>,
}

impl VmessOutbound {
    pub fn new(tag: String, cfg: &OutboundConfig) -> Result<Arc<dyn AnyOutbound>> {
        let address = cfg
            .address
            .clone()
            .context(format!("vmess outbound '{}' requires address", tag))?;
        let port = cfg
            .port
            .context(format!("vmess outbound '{}' requires port", tag))?;
        let server = TargetAddr::from_str2(&address, port)?;

        let uuid = cfg
            .uuid
            .clone()
            .context(format!("vmess outbound '{}' requires uuid", tag))?;

        let alter_id = cfg
            .username
            .clone()
            .and_then(|u| u.parse::<u16>().ok())
            .unwrap_or(0);

        let security = cfg.udp_mod.clone().unwrap_or_else(|| "auto".to_string());

        let udp = true;

        Ok(Arc::new(Self {
            tag,
            server,
            uuid,
            alter_id,
            security,
            udp,
            connect_timeout: Duration::from_secs(cfg.connect_timeout.unwrap_or(30)),
            dns_server_name: cfg.dns.clone(),
            bind_interface: cfg.bind_interface.clone(),
        }))
    }

    fn build_vmess_option(&self, target: &TargetAddr, udp: bool) -> Result<VmessOption> {
        Ok(VmessOption {
            uuid: self.uuid.clone(),
            alter_id: self.alter_id,
            security: self.security.clone(),
            udp,
            dst: target.clone(),
        })
    }
}

#[async_trait]
impl AnyOutbound for VmessOutbound {
    fn tag(&self) -> &str {
        &self.tag
    }

    fn protocol(&self) -> &str {
        "vmess"
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
        let proxy_addr = self.resolve_addr(&self.server).await?;
        let stream = self.new_tcp_stream(proxy_addr).await?;
        Ok(Box::new(stream))
    }

    async fn connect_stream_with(
        &self,
        target: &TargetAddr,
        stream: AnyStream,
    ) -> anyhow::Result<AnyStream> {
        let opt = self.build_vmess_option(target, false)?;
        let builder =
            Builder::new(&opt).map_err(|e| new_io_other_error(format!("vmess builder: {}", e)))?;

        let vmess_stream = timeout(self.connect_timeout(), builder.proxy_stream(stream))
            .await
            .with_context(|| format!("vmess connect timeout after {:?}", self.connect_timeout()))?
            .map_err(|e| new_io_other_error(format!("vmess connect: {}", e)))?;

        Ok(Box::new(vmess_stream))
    }

    async fn connect_packet(&self, target: &TargetAddr) -> anyhow::Result<Arc<dyn AnyPacket>> {
        let stream = self.connect_stream(target).await?;
        Ok(Arc::new(VmessUdpSocket::new(stream, target.clone())))
    }
}

struct VmessUdpSocket {
    sink: Mutex<futures::stream::SplitSink<OutboundDatagramVmess, (TargetAddr, Bytes)>>,
    stream: Mutex<futures::stream::SplitStream<OutboundDatagramVmess>>,
    target: TargetAddr,
}

impl VmessUdpSocket {
    fn new(inner: AnyStream, target: TargetAddr) -> Self {
        let datagram = OutboundDatagramVmess::new(inner, target.clone());
        let (sink, stream) = datagram.split();
        Self {
            sink: Mutex::new(sink),
            stream: Mutex::new(stream),
            target,
        }
    }
}

#[async_trait]
impl AnyPacket for VmessUdpSocket {
    async fn send_to(&self, buf: Bytes, _from: &SourceAddr, _target: &TargetAddr) -> Result<usize> {
        let len = buf.len();
        let mut sink = self.sink.lock().await;

        sink.send((self.target.clone(), buf))
            .await
            .map_err(|e| new_io_other_error(format!("vmess udp send: {}", e)))?;

        Ok(len)
    }

    async fn recv_from(&self) -> Result<PacketInfo> {
        let mut stream = self.stream.lock().await;

        match stream.next().await {
            Some((src, dst, data)) => Ok((src, dst, data)),
            None => anyhow::bail!("vmess udp stream closed"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::OutboundConfig;
    use crate::proxy::TargetAddr;

    fn make_config() -> OutboundConfig {
        serde_json::from_value(serde_json::json!({
            "type": "vmess",
            "address": "127.0.0.1",
            "port": 10086,
            "uuid": "b831381d-6324-4d53-ad4f-8cda48b30811",
            "username": "0",
            "udp_mod": "auto",
            "connect_timeout": 5,
            "mtu_discoveriy": false,
            "gso": false,
            "min_mtu": 1200,
            "initial_mtu": 1200,
        }))
        .unwrap()
    }

    #[test]
    fn test_vmess_outbound_construction() {
        let cfg = make_config();
        let result = VmessOutbound::new("test-vmess".to_string(), &cfg);
        assert!(result.is_ok());
        let outbound = result.unwrap();
        assert_eq!(outbound.tag(), "test-vmess");
        assert_eq!(outbound.protocol(), "vmess");
    }

    #[test]
    fn test_vmess_outbound_missing_uuid() {
        let mut cfg = make_config();
        cfg.uuid = None;
        let result = VmessOutbound::new("test-vmess".to_string(), &cfg);
        assert!(result.is_err());
    }

    #[test]
    fn test_vmess_outbound_missing_address() {
        let mut cfg = make_config();
        cfg.address = None;
        let result = VmessOutbound::new("test-vmess".to_string(), &cfg);
        assert!(result.is_err());
    }

    #[test]
    fn test_vmess_build_option() {
        let cfg = make_config();
        let outbound = VmessOutbound::new("test-vmess".to_string(), &cfg).unwrap();
        // Downcast to concrete type
        let handler = &*outbound as *const dyn AnyOutbound as *const VmessOutbound;
        let handler = unsafe { &*handler };
        let target = TargetAddr::from_str2("example.com", 443).unwrap();
        let opt = handler.build_vmess_option(&target, false);
        assert!(opt.is_ok());
        let opt = opt.unwrap();
        assert_eq!(opt.uuid, "b831381d-6324-4d53-ad4f-8cda48b30811");
        assert_eq!(opt.alter_id, 0);
        assert_eq!(opt.udp, false);
    }

    #[test]
    fn test_vmess_build_option_udp() {
        let cfg = make_config();
        let outbound = VmessOutbound::new("test-vmess".to_string(), &cfg).unwrap();
        let handler = &*outbound as *const dyn AnyOutbound as *const VmessOutbound;
        let handler = unsafe { &*handler };
        let target = TargetAddr::from_str2("example.com", 443).unwrap();
        let opt = handler.build_vmess_option(&target, true);
        assert!(opt.is_ok());
        assert!(opt.unwrap().udp);
    }

    #[test]
    fn test_vmess_outbound_connect_timeout() {
        let cfg = make_config();
        let outbound = VmessOutbound::new("test-vmess".to_string(), &cfg).unwrap();
        assert_eq!(outbound.connect_timeout(), Duration::from_secs(5));
    }

    #[test]
    fn test_vmess_outbound_default_connect_timeout() {
        let mut cfg = make_config();
        cfg.connect_timeout = None;
        let outbound = VmessOutbound::new("test-vmess".to_string(), &cfg).unwrap();
        assert_eq!(outbound.connect_timeout(), Duration::from_secs(30));
    }
}
