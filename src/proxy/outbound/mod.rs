pub mod anytls;
pub mod direct;
pub mod dns;
pub mod http;
pub mod pool;
pub mod selector;
pub mod shadowquic;
pub mod shadowsocks;
pub mod socks5;
pub mod trojan;
pub mod vmess;

use anyhow::{Context, bail};
use anytls::AnytlsOutbound;
use async_trait::async_trait;
use dashmap::DashMap;
use direct::DirectOutbound;
use dns::DnsOutbound;
use selector::SelectorOutbound;
use serde::Serialize;
use shadowquic::ShadowQuicOutbound;
use shadowsocks::ShadowsocksOutbound;
use socks5::Socks5Outbound;
use std::io;
use std::io::IoSlice;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, LazyLock};
use std::task::Poll;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::Mutex;
use tokio::sync::mpsc::{Receiver, Sender};
use trojan::TrojanOutbound;
use vmess::VmessOutbound;

use crate::config::Config;
use crate::dns::resolve_target;
use crate::proxy::observe::get_observer;
use crate::proxy::{SessionCloser, TargetAddr};
use crate::utils::interface::{InterfaceInfo, InterfaceManager, resolve_iface};
use crate::utils::new_io_timeout_error;
use crate::utils::socket::socket_helpers::{new_tcp_stream, new_udp_socket};

use bytes::{Bytes, BytesMut};

use super::SourceAddr;

pub static OUTBOUNDS_MAP: LazyLock<DashMap<String, Arc<dyn AnyOutbound>>> =
    LazyLock::new(DashMap::new);

pub fn init_outbounds(cfg: &Config) -> anyhow::Result<()> {
    let servers = &cfg.outbounds.servers;

    fn get_priority(protocol: &str) -> u8 {
        match protocol {
            "selector" => 2,
            "urltest" => 1,
            _ => 0,
        }
    }

    let mut sorted_servers: Vec<_> = servers.iter().collect();
    sorted_servers.sort_by_key(|(_, cfg)| get_priority(cfg.protocol_type.as_str()));

    for (name, item) in sorted_servers {
        let protocol = item.protocol_type.clone().to_lowercase();
        let name_str = name.clone();

        let out_result: Arc<dyn AnyOutbound> = match protocol.as_str() {
            "direct" => DirectOutbound::new(name_str, item)?,
            "shadowquic" => ShadowQuicOutbound::new(name_str, item)?,
            "trojan" => TrojanOutbound::new(name_str, item)?,
            "anytls" => AnytlsOutbound::new(name_str, item)?,
            "socks5" => Socks5Outbound::new(name_str, item)?,
            "shadowsocks" => ShadowsocksOutbound::new(name_str, item)?,
            "vmess" => VmessOutbound::new(name_str, item)?,
            "dns" => DnsOutbound::new(name_str, item)?,
            "selector" => SelectorOutbound::new(name_str, item)?,
            "urltest" => SelectorOutbound::new(name_str, item)?,
            _ => bail!("Unknown outbound type: {}", protocol),
        };

        OUTBOUNDS_MAP.insert(name.clone(), out_result.clone());

        if let Some(observer) = get_observer() {
            observer.register_outbound(name, out_result.protocol());
        }
    }

    let final_tag: String = match &cfg.outbounds.final_outbound {
        Some(tag) => tag.clone(),
        None => OUTBOUNDS_MAP
            .iter()
            .next()
            .map(|entry| entry.key().clone())
            .with_context(
                || "at least one outbound must be registered before setting default_server",
            )?,
    };

    // 先 clone 再 drop Ref（释放 DashMap 读锁），避免 insert 时获取写锁死锁
    let default_outbound = match OUTBOUNDS_MAP.get(&final_tag) {
        Some(o) => o.clone(),
        None => {
            bail!(
                "Final outbound tag '{}' not found in servers config",
                final_tag
            );
        }
    };
    OUTBOUNDS_MAP.insert("default_server".to_string(), default_outbound);
    Ok(())
}

pub fn try_get_outbound_by_tag(tag: &str) -> Arc<dyn AnyOutbound> {
    match OUTBOUNDS_MAP.get(tag) {
        Some(r) => return r.clone(),
        None => get_default_outbound(),
    }
}

pub fn get_outbound_by_tag(tag: &str) -> Arc<dyn AnyOutbound> {
    match OUTBOUNDS_MAP.get(tag) {
        Some(r) => return r.clone(),
        None => {
            panic!("can not find outbound: {}", tag);
        }
    };
}

pub fn get_default_outbound() -> Arc<dyn AnyOutbound> {
    get_outbound_by_tag("default_server".as_ref())
}

fn select_outbound_interface(
    bind_interface: Option<&str>,
    connect_to: Option<SocketAddr>,
) -> Option<Arc<InterfaceInfo>> {
    let mut used_interface = bind_interface.and_then(|name| resolve_iface(name, None).ok());

    let is_loopback = connect_to.map(|a| a.ip().is_loopback()).unwrap_or(false);

    if used_interface.is_none() && !is_loopback {
        used_interface = InterfaceManager::selected_iface();
    }

    used_interface
}

/// Statistics for a packet session
#[derive(Debug, Default)]
pub struct PacketStats {
    sent_bytes: AtomicU64,
    recv_bytes: AtomicU64,
}

impl PacketStats {
    pub fn add_sent(&self, bytes: u64) {
        self.sent_bytes.fetch_add(bytes, Ordering::Relaxed);
    }

    pub fn add_recv(&self, bytes: u64) {
        self.recv_bytes.fetch_add(bytes, Ordering::Relaxed);
    }

    pub fn get_sent(&self) -> u64 {
        self.sent_bytes.load(Ordering::Relaxed)
    }

    pub fn get_recv(&self) -> u64 {
        self.recv_bytes.load(Ordering::Relaxed)
    }
}

/// A trait alias for streams that implement AsyncRead, AsyncWrite, Unpin, Send.
pub trait ReadWrite: AsyncRead + AsyncWrite + Unpin + Send {}

impl<T: AsyncRead + AsyncWrite + Unpin + Send + ?Sized> ReadWrite for T {}

/// A boxed trait object for any stream that implements ReadWrite.
pub type AnyStream = Box<dyn ReadWrite>;
pub type PacketInfo = (SourceAddr, TargetAddr, Bytes);

pub struct LazyHandshakeStream {
    stream: AnyStream,
    handshake: Option<Vec<u8>>,
}

impl LazyHandshakeStream {
    pub fn new(stream: AnyStream, handshake: Vec<u8>) -> Self {
        Self {
            stream,
            handshake: Some(handshake),
        }
    }
}

impl AsyncRead for LazyHandshakeStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_read(cx, buf)
    }
}

impl AsyncWrite for LazyHandshakeStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();

        if let Some(handshake_data) = &mut this.handshake {
            let slices = [IoSlice::new(handshake_data), IoSlice::new(buf)];

            match Pin::new(&mut this.stream).poll_write_vectored(cx, &slices) {
                Poll::Ready(Ok(n)) => {
                    if n == 0 {
                        return Poll::Ready(Ok(0));
                    }

                    let handshake_len = handshake_data.len();
                    if n >= handshake_len {
                        this.handshake = None;

                        let written_user = n - handshake_len;
                        if written_user == 0 && !buf.is_empty() {
                            return Pin::new(&mut this.stream).poll_write(cx, buf);
                        }
                        Poll::Ready(Ok(written_user))
                    } else {
                        handshake_data.drain(0..n);
                        cx.waker().wake_by_ref();
                        Poll::Pending
                    }
                }
                Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
                Poll::Pending => Poll::Pending,
            }
        } else {
            Pin::new(&mut this.stream).poll_write(cx, buf)
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_flush(cx)
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_shutdown(cx)
    }
}

#[async_trait]
pub trait AnyPacket: Send + Sync {
    async fn send_to(
        &self,
        _buf: Bytes,
        _from: &SourceAddr,
        _target: &TargetAddr,
    ) -> anyhow::Result<usize> {
        bail!("Not supported")
    }

    async fn recv_from(&self) -> anyhow::Result<PacketInfo> {
        bail!("Not supported")
    }

    async fn send_many(&self, items: &[PacketInfo]) -> anyhow::Result<usize> {
        let mut r = 0;
        for (from, target, buf) in items {
            r += self.send_to(buf.clone(), from, target).await?;
        }
        Ok(r)
    }

    async fn recv_many(&self) -> anyhow::Result<Vec<PacketInfo>> {
        Ok(vec![self.recv_from().await?])
    }

    fn closer(&self) -> Arc<SessionCloser> {
        Arc::new(SessionCloser::new())
    }

    fn get_udp_stats(&self) -> Option<(u64, u64, u64)> {
        None
    }
}

#[async_trait]
impl AnyPacket for tokio::net::UdpSocket {
    async fn send_to(
        &self,
        buf: Bytes,
        _from: &SourceAddr,
        target: &TargetAddr,
    ) -> anyhow::Result<usize> {
        match target {
            TargetAddr::Ip(addr) => self.send_to(&buf, *addr).await.context("send_to failed"),
            _ => bail!("Domain address not supported for direct UDP"),
        }
    }

    async fn recv_from(&self) -> anyhow::Result<PacketInfo> {
        let mut buf = BytesMut::with_capacity(1024 * 2);
        let (n, addr) = self.recv_buf_from(&mut buf).await?;
        buf.truncate(n);
        let target = TargetAddr::Ip(std::net::SocketAddr::new(
            std::net::IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0)),
            0,
        ));
        Ok((TargetAddr::Ip(addr), target, buf.freeze()))
    }
}

#[async_trait]
pub trait AnyOutbound: Send + Sync {
    fn tag(&self) -> &str;
    fn protocol(&self) -> &str;
    fn dns_server_name(&self) -> Option<&str>;

    fn as_selector(&self) -> Option<&SelectorOutbound> {
        None
    }

    fn bind_interface(&self) -> Option<&str> {
        None
    }

    async fn connect_packet(&self, final_target: &TargetAddr)
    -> anyhow::Result<Arc<dyn AnyPacket>>;

    fn connect_timeout(&self) -> Duration;

    async fn connect_stream_base(&self) -> anyhow::Result<AnyStream>;

    async fn connect_stream_with(
        &self,
        _target: &TargetAddr,
        _stream: AnyStream,
    ) -> anyhow::Result<AnyStream>;

    async fn connect_stream(&self, target: &TargetAddr) -> anyhow::Result<AnyStream> {
        let s = self.connect_stream_base().await?;
        self.connect_stream_with(target, s).await
    }

    async fn retry_connect_stream(&self, _target: &TargetAddr) -> anyhow::Result<AnyStream> {
        bail!("not implemented")
    }

    fn is_pool(&self) -> bool {
        false
    }

    async fn resolve(&self, _domain: &str) -> anyhow::Result<Option<IpAddr>> {
        Ok(None)
    }

    async fn resolve_addr(&self, address: &TargetAddr) -> anyhow::Result<SocketAddr> {
        resolve_target(address, self.dns_server_name()).await
    }

    async fn new_tcp_stream(&self, connect_to: SocketAddr) -> io::Result<TcpStream> {
        let used_interface = select_outbound_interface(self.bind_interface(), Some(connect_to));

        tokio::time::timeout(
            self.connect_timeout(),
            new_tcp_stream(connect_to, used_interface, None),
        )
        .await
        .map_err(|_| new_io_timeout_error("connect timeout"))?
    }

    async fn new_udp_socket(&self, connect_to: SocketAddr) -> io::Result<UdpSocket> {
        let used_interface = select_outbound_interface(self.bind_interface(), Some(connect_to));

        new_udp_socket(None, used_interface, Some(connect_to), None).await
    }
    async fn get_uplink_state(&self) -> Option<PathState> {
        None
    }
    async fn get_downlink_state(&self) -> Option<PathState> {
        None
    }
}
#[derive(Debug, Clone, Serialize)]
pub struct PathState {
    pub lost_packets: u64,
    pub sent_packets: u64,
    pub mtu: u16,
    pub rtt: f32,
}

#[derive(Clone, Copy, Debug)]
pub enum UdpMode {
    OverStream,
    OverDatagram,
}

pub type SessionKey = (SourceAddr, TargetAddr);
pub type SessionMap = Arc<DashMap<SessionKey, Sender<Bytes>>>;

pub struct UdpHandler {
    udp_tx: Arc<dyn AnyPacket>,
    udp_rx: Mutex<Receiver<Bytes>>,
    src_addr: SourceAddr,
    dst_addr: TargetAddr,
}

impl UdpHandler {
    pub fn new(
        udp_tx: Arc<dyn AnyPacket>,
        udp_rx: Receiver<Bytes>,
        src_addr: SourceAddr,
        dst_addr: TargetAddr,
    ) -> Self {
        UdpHandler {
            udp_tx,
            udp_rx: Mutex::new(udp_rx),
            src_addr,
            dst_addr,
        }
    }
}

#[async_trait]
impl AnyPacket for UdpHandler {
    async fn send_to(
        &self,
        buf: Bytes,
        from: &SourceAddr,
        target: &TargetAddr,
    ) -> anyhow::Result<usize> {
        self.udp_tx.send_to(buf, from, target).await
    }

    async fn recv_from(&self) -> anyhow::Result<PacketInfo> {
        let mut rx = self.udp_rx.lock().await;
        match rx.recv().await {
            Some(data) => Ok((self.src_addr.clone(), self.dst_addr.clone(), data)),
            None => bail!("UDP session channel closed"),
        }
    }

    async fn recv_many(&self) -> anyhow::Result<Vec<PacketInfo>> {
        let mut rx = self.udp_rx.lock().await;
        let first = match rx.recv().await {
            Some(data) => data,
            None => bail!("recv channel closed"),
        };
        let mut results = vec![(self.src_addr.clone(), self.dst_addr.clone(), first)];
        while let Result::Ok(data) = rx.try_recv() {
            results.push((self.src_addr.clone(), self.dst_addr.clone(), data));
        }
        Ok(results)
    }
}
