use crate::proxy::outbound::{AnyOutbound, AnyPacket, AnyStream, PacketInfo};
use crate::proxy::{SourceAddr, TargetAddr};
use crate::utils::new_io_other_error;
use anyhow::Result;
use async_trait::async_trait;
use bytes::Bytes;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::{Mutex, mpsc};
use tracing::{debug, info};

pub const POOL_SHOULD_RETRY: &str = "POOL_SHOULD_RETRY";

pub struct PoolOutbound {
    inner: Arc<dyn AnyOutbound>,
    max_size: usize,
    tx: mpsc::Sender<AnyStream>,
    rx: Arc<Mutex<mpsc::Receiver<AnyStream>>>,
    is_filling: Arc<AtomicBool>,
}

struct _PoolUdpOutbound {
    inner: Arc<dyn AnyPacket>,
}

#[async_trait]
impl AnyPacket for _PoolUdpOutbound {
    async fn send_to(&self, buf: Bytes, from: &SourceAddr, target: &TargetAddr) -> Result<usize> {
        self.inner.send_to(buf, from, target).await
    }

    async fn recv_from(&self) -> Result<PacketInfo> {
        self.inner.recv_from().await
    }

    fn closer(&self) -> Option<Arc<crate::proxy::SessionCloser>> {
        self.inner.closer()
    }
}

impl PoolOutbound {
    pub fn new(max_size: usize, inner: Arc<dyn AnyOutbound>) -> Result<Arc<dyn AnyOutbound>> {
        let (tx, rx) = mpsc::channel::<AnyStream>(max_size);
        Ok(Arc::new(Self {
            inner,
            max_size,
            tx,
            is_filling: Arc::new(AtomicBool::new(false)),
            rx: Arc::new(Mutex::new(rx)),
        }))
    }

    fn fill(&self) {
        if self
            .is_filling
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            return;
        }

        let inner = self.inner.clone();
        let tx = self.tx.clone();
        let rx_mutex = self.rx.clone();
        let max_size = self.max_size;
        let filling_flag = self.is_filling.clone();

        tokio::spawn(async move {
            struct FillingGuard(Arc<AtomicBool>);
            impl Drop for FillingGuard {
                fn drop(&mut self) {
                    self.0.store(false, Ordering::Release);
                }
            }
            let _guard = FillingGuard(filling_flag);

            let mut try_times = {
                let lock = rx_mutex.lock().await;
                max_size.saturating_sub(lock.len())
            };

            debug!("try filling {} stream into pool", try_times);

            while try_times > 0 {
                if let Ok(s) = inner.connect_stream_base().await {
                    if tx.send(s).await.is_err() {
                        break;
                    }
                } else {
                    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                }
                try_times -= 1;
            }
        });
    }
}

#[async_trait]
impl AnyOutbound for PoolOutbound {
    fn tag(&self) -> &str {
        self.inner.tag()
    }

    fn protocol(&self) -> &str {
        self.inner.protocol()
    }

    fn dns_server_name(&self) -> Option<&str> {
        self.inner.dns_server_name()
    }

    fn bind_interface(&self) -> Option<&str> {
        self.inner.bind_interface()
    }

    fn is_pool(&self) -> bool {
        true
    }

    async fn retry_connect_stream(&self, target: &TargetAddr) -> anyhow::Result<AnyStream> {
        self.inner.connect_stream(target).await
    }

    async fn resolve(&self, domain: &str) -> anyhow::Result<Option<IpAddr>> {
        self.inner.resolve(domain).await
    }

    fn connect_timeout(&self) -> Duration {
        self.inner.connect_timeout()
    }

    async fn connect_stream_base(&self) -> Result<AnyStream> {
        let maybe_stream = {
            let mut rx_lock = self.rx.lock().await;
            rx_lock.try_recv().ok()
        };

        if let Some(stream) = maybe_stream {
            info!("using stream from pool");
            return Ok(stream);
        }

        self.fill();
        self.inner.connect_stream_base().await
    }

    async fn connect_stream_with(
        &self,
        target: &TargetAddr,
        stream: AnyStream,
    ) -> Result<AnyStream> {
        self.inner.connect_stream_with(target, stream).await
    }

    async fn connect_packet(&self, target: &TargetAddr) -> Result<Arc<dyn AnyPacket>> {
        self.inner.connect_packet(target).await
    }
}

pub struct PoolStream {
    is_try_once: bool,
    stream: AnyStream,
}

impl PoolStream {
    pub fn new(stream: AnyStream) -> Self {
        Self {
            is_try_once: false,
            stream,
        }
    }
}

impl AsyncRead for PoolStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_read(cx, buf)
    }
}

impl AsyncWrite for PoolStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.get_mut().stream).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();

        match Pin::new(&mut this.stream).poll_flush(cx) {
            Poll::Ready(Err(e)) => {
                if !this.is_try_once {
                    this.is_try_once = true;
                    return Poll::Ready(Err(new_io_other_error(POOL_SHOULD_RETRY)));
                }
                Poll::Ready(Err(e))
            }
            other => {
                this.is_try_once = true;
                other
            }
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_shutdown(cx)
    }
}
