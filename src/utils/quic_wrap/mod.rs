pub mod quinn_wrap;

use std::io;
use std::net::{IpAddr, SocketAddr};

use async_trait::async_trait;
use bytes::Bytes;
use std::time::Duration;
use tokio::io::AsyncWrite;

use crate::proxy::outbound::ReadWrite;

#[async_trait]
pub trait QuicUnistream: AsyncWrite + Send + Sync + Unpin {}

#[async_trait]
pub trait QuicBistream: ReadWrite {}

#[async_trait]
pub trait QuicConnection: Send + Sync {
    fn peer_addr(&self) -> SocketAddr;
    fn local_ip(&self) -> Option<IpAddr>;

    async fn packet_loss_rate(&self) -> f32;
    async fn rtt(&self) -> Option<Duration>;
    async fn mtu(&self) -> u16;

    async fn shutdown(&self) -> io::Result<()>;
    async fn is_closed(&self) -> io::Result<bool>;

    async fn accept_unistream(&self) -> io::Result<Box<dyn QuicUnistream>>;
    async fn open_unistream(&self) -> io::Result<Box<dyn QuicUnistream>>;

    async fn accept_bistream(&self) -> io::Result<Box<dyn QuicBistream>>;
    async fn open_bistream(&self) -> io::Result<Box<dyn QuicBistream>>;

    async fn read_datagram(&self) -> io::Result<Bytes>;
    async fn send_datagram(&self, data: Bytes) -> io::Result<bool>;
}
