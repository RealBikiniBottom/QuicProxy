use std::fmt::Debug;
use std::pin::Pin;

use shadowsocks::ProxyClientStream;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::proxy::outbound::AnyStream;

/// The first write carries the target address in the same AEAD chunk, and
/// `ProxyClientStream` assumes that chunk is written whole: a payload larger
/// than one chunk trips a debug assertion and, in release builds, silently
/// drops the tail. Keep the first write well below the smallest chunk limit
/// (0x3FFF minus the address); later writes report partial progress correctly.
const FIRST_WRITE_LIMIT: usize = 4096;

pub struct ShadowSocksStream {
    inner: ProxyClientStream<AnyStream>,
    first_write_done: bool,
}

impl ShadowSocksStream {
    pub fn new(inner: ProxyClientStream<AnyStream>) -> Self {
        Self {
            inner,
            first_write_done: false,
        }
    }
}

impl Debug for ShadowSocksStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("ShadowSocksStream").finish()
    }
}

impl AsyncRead for ShadowSocksStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for ShadowSocksStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<Result<usize, std::io::Error>> {
        let this = self.get_mut();
        let buf = if this.first_write_done {
            buf
        } else {
            &buf[..buf.len().min(FIRST_WRITE_LIMIT)]
        };
        let result = Pin::new(&mut this.inner).poll_write(cx, buf);
        if matches!(result, std::task::Poll::Ready(Ok(_))) {
            this.first_write_done = true;
        }
        result
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}
