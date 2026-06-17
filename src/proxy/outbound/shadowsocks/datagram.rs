use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};

use futures::{Sink, Stream, ready};
use shadowsocks::{
    ProxySocket,
    relay::udprelay::{DatagramReceive, DatagramSend, options::UdpSocketControlData},
};
use tokio::io::ReadBuf;
use tracing::debug;

use crate::proxy::{TargetAddr, outbound::PacketInfo};

pub struct OutboundDatagramShadowsocks<S> {
    inner: ProxySocket<S>,
    remote_addr: SocketAddr,

    flushed: bool,
    pkt: Option<(TargetAddr, bytes::Bytes)>,
    buf: Vec<u8>,
    ss_control: UdpSocketControlData,
}

impl<S> OutboundDatagramShadowsocks<S> {
    pub fn new(inner: ProxySocket<S>, remote_addr: SocketAddr) -> Self {
        let mut ss_control = UdpSocketControlData::default();
        ss_control.client_session_id = rand::random::<u64>();

        Self {
            inner,
            flushed: true,
            pkt: None,
            remote_addr,
            buf: vec![0u8; 65535],
            ss_control,
        }
    }
}

impl<S> Sink<(TargetAddr, bytes::Bytes)> for OutboundDatagramShadowsocks<S>
where
    S: DatagramSend + Unpin,
{
    type Error = io::Error;

    fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
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

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        if self.flushed {
            return Poll::Ready(Ok(()));
        }

        let Self {
            ref mut inner,
            ref mut pkt,
            ref remote_addr,
            ref mut flushed,
            ref mut ss_control,
            ..
        } = *self;

        let pkt_container = pkt;

        if let &mut Some((ref dst_addr, ref data)) = pkt_container {
            let data: &bytes::Bytes = data;
            let data_len = data.len();
            let addr: shadowsocks::relay::Address =
                (dst_addr.host().to_string(), dst_addr.port()).into();

            let n =
                ready!(inner.poll_send_to_with_ctrl(*remote_addr, &addr, ss_control, data, cx))?;

            debug!(
                "send udp packet to remote ss server, len: {}, remote_addr: {}, dst_addr: {}",
                n, remote_addr, addr
            );

            *pkt_container = None;
            *flushed = true;

            let wrote_all = n == data_len;
            let res = if wrote_all {
                Ok(())
            } else {
                Err(io::Error::other(format!(
                    "failed to write entire datagram, written: {n}"
                )))
            };
            Poll::Ready(res)
        } else {
            debug!("no udp packet to send");
            Poll::Ready(Err(io::Error::other("no packet to send")))
        }
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        ready!(self.poll_flush(cx))?;
        Poll::Ready(Ok(()))
    }
}

impl<S> Stream for OutboundDatagramShadowsocks<S>
where
    S: DatagramReceive + Unpin,
{
    type Item = PacketInfo;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let &mut Self {
            ref mut buf,
            ref inner,
            ..
        } = self.get_mut();

        let mut buf = ReadBuf::new(buf);
        let rv = ready!(inner.poll_recv(cx, &mut buf));
        debug!("recv udp packet from remote ss server: {:?}", rv);

        match rv {
            Ok((n, src, ..)) => {
                let src_addr = match src {
                    shadowsocks::relay::Address::SocketAddress(a) => TargetAddr::Ip(a),
                    _ => TargetAddr::dummy(),
                };
                Poll::Ready(Some((
                    src_addr,
                    TargetAddr::dummy(),
                    bytes::Bytes::copy_from_slice(&buf.filled()[..n]),
                )))
            }
            Err(_) => Poll::Ready(None),
        }
    }
}
