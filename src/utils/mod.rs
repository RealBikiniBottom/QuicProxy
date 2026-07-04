use bytes::{Buf, BytesMut};
use rand::Rng;
use sha2::Digest;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

pub mod cache;
pub mod count_traffic;
pub mod elevate;
pub mod http_outbound;
pub mod interface;
pub mod keyed_notify;
pub mod logging;
pub mod net_monitor;
pub mod quic_wrap;
pub mod redb_store;
pub mod shutdown;
pub mod socket;
pub mod system;
pub mod system_proxy;
pub mod time;

pub fn format_duration(duration: Duration) -> String {
    return format!("{:.2?}", duration);
}

pub fn format_ms(ms: u64) -> String {
    let duration = std::time::Duration::from_millis(ms);
    return format_duration(duration);
}

pub fn format_us(us: u64) -> String {
    let duration = std::time::Duration::from_micros(us);
    return format_duration(duration);
}

pub fn now() -> Instant {
    return std::time::Instant::now();
}

pub fn now_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or_else(|e| {
            tracing::error!("Time went backwards: {}", e);
            0
        })
}

pub struct PrefixedReadStream<S> {
    stream: S,
    prefix: BytesMut,
}

impl<S> PrefixedReadStream<S> {
    pub fn new(stream: S, prefix: BytesMut) -> Self {
        Self { stream, prefix }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for PrefixedReadStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.prefix.has_remaining() {
            let len = std::cmp::min(self.prefix.len(), buf.remaining());
            buf.put_slice(&self.prefix[..len]);
            self.prefix.advance(len);
            Poll::Ready(Ok(()))
        } else {
            Pin::new(&mut self.stream).poll_read(cx, buf)
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for PrefixedReadStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.stream).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

pub fn new_io_other_error<T>(msg: T) -> io::Error
where
    T: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    io::Error::other(msg.into())
}

pub fn new_io_timeout_error<T>(msg: T) -> io::Error
where
    T: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    io::Error::new(io::ErrorKind::TimedOut, msg.into())
}

// Use 1KB buffer size for mobile, 4KB for desktop
#[cfg(any(target_os = "android", target_os = "ios"))]
const BUFFER_SIZE: usize = 1024 * 1;
#[cfg(not(any(target_os = "android", target_os = "ios")))]
const BUFFER_SIZE: usize = 1024 * 1;

/// Copies data in both directions between `a` and `b`.
///
/// This function uses `tokio::io::copy_bidirectional_with_sizes` with a custom buffer size
/// (1KB for mobile, 4KB for desktop) to optimize memory usage per connection.
pub async fn copy_bidirectional<A, B>(a: &mut A, b: &mut B) -> Result<(u64, u64), std::io::Error>
where
    A: AsyncRead + AsyncWrite + Unpin + ?Sized,
    B: AsyncRead + AsyncWrite + Unpin + ?Sized,
{
    tokio::io::copy_bidirectional_with_sizes(a, b, BUFFER_SIZE, BUFFER_SIZE).await
}

pub fn rand_range<T>(range: std::ops::Range<T>) -> T
where
    T: rand::distributions::uniform::SampleUniform + std::cmp::PartialOrd,
{
    let mut rng = rand::thread_rng();
    rng.gen_range(range)
}

pub fn rand_fill<T>(buf: &mut T)
where
    T: rand::Fill + ?Sized,
{
    let mut rng = rand::thread_rng();
    buf.try_fill(&mut rng).unwrap_or(());
}

pub fn sha256(bytes: &[u8]) -> Vec<u8> {
    let mut hasher = sha2::Sha256::new();
    hasher.update(bytes);
    hasher.finalize().to_vec()
}

pub fn md5(bytes: &[u8]) -> Vec<u8> {
    let mut hasher = md5::Context::new();
    hasher.consume(bytes);
    hasher.finalize().to_vec()
}
