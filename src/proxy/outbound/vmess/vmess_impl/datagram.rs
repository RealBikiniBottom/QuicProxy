use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use futures::ready;
use tokio::io::{AsyncRead, AsyncWrite};
use tracing::debug;

use crate::proxy::TargetAddr;
use crate::proxy::outbound::{AnyStream, PacketInfo};

pub struct OutboundDatagramVmess {
    inner: AnyStream,
    remote_addr: TargetAddr,

    written: Option<usize>,
    flushed: bool,
    pkt: Option<(TargetAddr, bytes::Bytes)>,
    buf: Vec<u8>,
}

impl OutboundDatagramVmess {
    pub fn new(inner: AnyStream, remote_addr: TargetAddr) -> Self {
        Self {
            inner,
            remote_addr,
            written: None,
            flushed: true,
            pkt: None,
            buf: vec![0u8; 65535],
        }
    }
}

impl futures::Sink<(TargetAddr, bytes::Bytes)> for OutboundDatagramVmess {
    type Error = io::Error;

    fn poll_ready(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        if !self.flushed {
            match self.poll_flush(cx)? {
                Poll::Ready(()) => {}
                Poll::Pending => return Poll::Pending,
            }
        }

        Poll::Ready(Ok(()))
    }

    fn start_send(
        self: Pin<&mut Self>,
        item: (TargetAddr, bytes::Bytes),
    ) -> Result<(), Self::Error> {
        let pin = self.get_mut();
        pin.pkt = Some(item);
        pin.flushed = false;
        Ok(())
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        if self.flushed {
            return Poll::Ready(Ok(()));
        }

        let Self {
            ref mut inner,
            ref mut pkt,
            ref remote_addr,
            ref mut flushed,
            ref mut written,
            ..
        } = *self;

        let mut inner = Pin::new(inner);

        let pkt_container = pkt;

        if let &mut Some((.., ref data)) = pkt_container {
            // For vmess UDP, the target address is encoded in the data since
            // the connection is already established with a specific target
            if written.is_none() {
                let n = ready!(inner.as_mut().poll_write(cx, data.as_ref()))?;
                debug!(
                    "send udp packet to remote vmess server, len: {}, remote_addr: {}",
                    n, remote_addr
                );
                *written = Some(n);
            }
            if !*flushed {
                let r = inner.as_mut().poll_flush(cx)?;
                if r.is_pending() {
                    return Poll::Pending;
                }
                *flushed = true;
            }
            let total_len = data.len();

            *pkt_container = None;

            let res = if written.unwrap() == total_len {
                Ok(())
            } else {
                Err(io::Error::other(format!(
                    "failed to write entire datagram, written: {}",
                    written.unwrap()
                )))
            };
            *written = None;
            Poll::Ready(res)
        } else {
            debug!("no udp packet to send");
            Poll::Ready(Err(io::Error::other("no packet to send")))
        }
    }

    fn poll_close(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        ready!(self.poll_flush(cx))?;
        Poll::Ready(Ok(()))
    }
}

impl futures::Stream for OutboundDatagramVmess {
    type Item = PacketInfo;

    fn poll_next(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        let Self {
            ref mut buf,
            ref mut inner,
            ref remote_addr,
            ..
        } = *self;

        let mut read_buf = tokio::io::ReadBuf::new(buf);
        let rv = ready!(Pin::new(inner).poll_read(cx, &mut read_buf));

        match rv {
            Ok(()) if read_buf.filled().is_empty() => Poll::Ready(None),
            Ok(()) => {
                let n = read_buf.filled().len();
                let data = bytes::Bytes::copy_from_slice(&buf[..n]);
                Poll::Ready(Some((
                    remote_addr.clone(),
                    TargetAddr::dummy(),
                    data,
                )))
            }
            Err(_) => Poll::Ready(None),
        }
    }
}
