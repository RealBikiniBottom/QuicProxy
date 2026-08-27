use crate::proxy::observe::{ConnectionHandle, Observer, Stats};
use crate::proxy::outbound::{AnyPacket, PacketInfo};
use crate::proxy::{SessionCloser, SourceAddr, TargetAddr};
use async_trait::async_trait;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite};

pub struct ObservedPacket {
    pub inner: Arc<dyn AnyPacket>,
    pub observer: Arc<Observer>,
    pub tracker: ConnectionHandle,
    pub outbound_tag: Arc<str>,
    pub extra_outbound_tag: Option<Arc<str>>,
}

#[async_trait]
impl AnyPacket for ObservedPacket {
    async fn send_to(
        &self,
        buf: bytes::Bytes,
        from: &SourceAddr,
        target: &TargetAddr,
    ) -> anyhow::Result<usize> {
        let n = self.inner.send_to(buf, from, target).await?;
        self.observer
            .update_outbound_node_traffic(&self.outbound_tag, n as u64, 0);
        self.observer
            .update_inbound_traffic(&self.tracker.inbound_tag, n as u64, 0);
        if let Some(ref tag) = self.extra_outbound_tag {
            self.observer.update_outbound_node_traffic(tag, n as u64, 0);
        }
        self.observer.update_global_traffic(n as u64, 0);
        self.tracker.inc_upload(n as u64);
        Ok(n)
    }

    async fn recv_from(&self) -> anyhow::Result<PacketInfo> {
        let (src, dst, data) = self.inner.recv_from().await?;
        let n = data.len();
        self.observer
            .update_outbound_node_traffic(&self.outbound_tag, 0, n as u64);
        self.observer
            .update_inbound_traffic(&self.tracker.inbound_tag, 0, n as u64);
        if let Some(ref tag) = self.extra_outbound_tag {
            self.observer.update_outbound_node_traffic(tag, 0, n as u64);
        }
        self.observer.update_global_traffic(0, n as u64);
        self.tracker.inc_download(n as u64);
        Ok((src, dst, data))
    }

    async fn recv_many(&self, packets: &mut Vec<PacketInfo>) -> anyhow::Result<()> {
        self.inner.recv_many(packets).await?;
        let n = packets.iter().map(|(_, _, data)| data.len() as u64).sum();
        self.observer
            .update_outbound_node_traffic(&self.outbound_tag, 0, n);
        self.observer
            .update_inbound_traffic(&self.tracker.inbound_tag, 0, n);
        if let Some(ref tag) = self.extra_outbound_tag {
            self.observer.update_outbound_node_traffic(tag, 0, n);
        }
        self.observer.update_global_traffic(0, n);
        self.tracker.inc_download(n);
        Ok(())
    }

    fn closer(&self) -> Option<Arc<SessionCloser>> {
        self.inner.closer()
    }

    fn get_udp_stats(&self) -> Option<(u64, u64, u64)> {
        let upload = self
            .tracker
            .upload
            .load(std::sync::atomic::Ordering::Relaxed);
        let download = self
            .tracker
            .download
            .load(std::sync::atomic::Ordering::Relaxed);
        Some((upload, download, self.tracker.start_time))
    }
}

impl Drop for ObservedPacket {
    fn drop(&mut self) {
        self.observer.on_outbound_close_udp(&self.outbound_tag);
        self.observer
            .on_inbound_close_udp(&self.tracker.inbound_tag);
        if let Some(ref tag) = self.extra_outbound_tag {
            self.observer.on_outbound_close_udp(tag);
        }
    }
}

pub struct ObservedStream<S> {
    pub inner: S,
    pub stats: Arc<Stats>,
    pub extra_stats: Option<Arc<Stats>>,
    pub tracker: ConnectionHandle,
    pub observer: Arc<Observer>,
    pub is_inbound: bool,
}

impl<S> ObservedStream<S> {
    pub fn new(
        inner: S,
        stats: Arc<Stats>,
        extra_stats: Option<Arc<Stats>>,
        tracker: ConnectionHandle,
        observer: Arc<Observer>,
        is_inbound: bool,
    ) -> Self {
        stats.inc_active_tcp();
        if let Some(ref s) = extra_stats {
            s.inc_active_tcp();
        }
        Self {
            inner,
            stats,
            extra_stats,
            tracker,
            observer,
            is_inbound,
        }
    }
}

impl<S> Drop for ObservedStream<S> {
    fn drop(&mut self) {
        self.stats.dec_active_tcp();
        if let Some(ref s) = self.extra_stats {
            s.dec_active_tcp();
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for ObservedStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let before = buf.filled().len();
        match Pin::new(&mut self.inner).poll_read(cx, buf) {
            Poll::Ready(Ok(())) => {
                let after = buf.filled().len();
                let n = (after - before) as u64;
                if n > 0 {
                    if self.is_inbound {
                        self.stats.inc_upload(n);
                        self.tracker.inc_upload(n);
                        self.observer.update_global_traffic(n, 0);
                    } else {
                        self.stats.inc_download(n);
                    }
                    if let Some(ref s) = self.extra_stats {
                        if self.is_inbound {
                            s.inc_upload(n);
                        } else {
                            s.inc_download(n);
                        }
                    }
                }
                Poll::Ready(Ok(()))
            }
            other => other,
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for ObservedStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match Pin::new(&mut self.inner).poll_write(cx, buf) {
            Poll::Ready(Ok(n)) => {
                let n_u64 = n as u64;
                if n_u64 > 0 {
                    if self.is_inbound {
                        self.stats.inc_download(n_u64);
                        self.tracker.inc_download(n_u64);
                        self.observer.update_global_traffic(0, n_u64);
                    } else {
                        self.stats.inc_upload(n_u64);
                    }
                    if let Some(ref s) = self.extra_stats {
                        if self.is_inbound {
                            s.inc_download(n_u64);
                        } else {
                            s.inc_upload(n_u64);
                        }
                    }
                }
                Poll::Ready(Ok(n))
            }
            other => other,
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proxy::observe::ConnectionTracker;
    use std::sync::atomic::Ordering;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn tcp_tracker_counts_each_direction_once_across_both_wrappers() {
        let observer = Observer::new_for_test();
        let tracker = observer.add_connection(
            ConnectionTracker::new(
                Arc::from("mixed"),
                vec!["direct".to_string()],
                None,
                TargetAddr::Domain("example.org".to_string(), 443),
                TargetAddr::Domain("example.org".to_string(), 443),
                false,
                false,
            ),
            None,
        );
        let inbound_stats = Arc::new(Stats::default());
        let outbound_stats = Arc::new(Stats::default());
        let (inbound_inner, mut inbound_peer) = tokio::io::duplex(64);
        let (outbound_inner, mut outbound_peer) = tokio::io::duplex(64);
        let mut inbound = ObservedStream::new(
            inbound_inner,
            inbound_stats.clone(),
            None,
            tracker.clone(),
            observer.clone(),
            true,
        );
        let mut outbound = ObservedStream::new(
            outbound_inner,
            outbound_stats.clone(),
            None,
            tracker.clone(),
            observer.clone(),
            false,
        );

        inbound_peer.write_all(b"up").await.unwrap();
        let mut upload = [0; 2];
        inbound.read_exact(&mut upload).await.unwrap();
        outbound.write_all(&upload).await.unwrap();
        let mut forwarded_upload = [0; 2];
        outbound_peer
            .read_exact(&mut forwarded_upload)
            .await
            .unwrap();

        outbound_peer.write_all(b"dn").await.unwrap();
        let mut download = [0; 2];
        outbound.read_exact(&mut download).await.unwrap();
        inbound.write_all(&download).await.unwrap();
        let mut forwarded_download = [0; 2];
        inbound_peer
            .read_exact(&mut forwarded_download)
            .await
            .unwrap();

        assert_eq!(tracker.upload.load(Ordering::Relaxed), 2);
        assert_eq!(tracker.download.load(Ordering::Relaxed), 2);
        assert_eq!(inbound_stats.get_upload_bytes(), 2);
        assert_eq!(inbound_stats.get_download_bytes(), 2);
        assert_eq!(outbound_stats.get_upload_bytes(), 2);
        assert_eq!(outbound_stats.get_download_bytes(), 2);

        let global = observer.get_global_stats();
        assert_eq!(global.get_upload_bytes(), 2);
        assert_eq!(global.get_download_bytes(), 2);

        assert_eq!(observer.get_all_connections().len(), 1);
        drop(tracker);
        drop(outbound);
        assert_eq!(observer.get_all_connections().len(), 1);
        drop(inbound);
        assert!(observer.get_all_connections().is_empty());

        let traffic = observer.drain_dst_traffic();
        assert_eq!(traffic.len(), 1);
        assert_eq!(traffic[0].upload, 2);
        assert_eq!(traffic[0].download, 2);
    }
}
