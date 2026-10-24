use bytes::Bytes;
use std::cell::RefCell;
use std::io;
use std::net::SocketAddr;
use tokio::net::UdpSocket;

/// Largest UDP payload (IPv6 without jumbograms); IPv4 tops out slightly lower.
pub const MAX_UDP_DATAGRAM: usize = 64 * 1024;

thread_local! {
    // One full-size buffer per worker thread instead of one per UDP session: a
    // smaller buffer silently truncates datagrams that arrive IP-fragmented or
    // over loopback, and each packet is copied out at its real size anyway.
    static RECV_BUF: RefCell<Box<[u8]>> =
        RefCell::new(vec![0u8; MAX_UDP_DATAGRAM].into_boxed_slice());
}

fn recv_into_shared_buf<T>(
    recv: impl FnOnce(&mut [u8]) -> io::Result<(usize, T)>,
) -> io::Result<(Bytes, T)> {
    RECV_BUF.with_borrow_mut(|buf| {
        let (n, meta) = recv(buf)?;
        Ok((Bytes::copy_from_slice(&buf[..n]), meta))
    })
}

pub fn try_recv_from(socket: &UdpSocket) -> io::Result<(Bytes, SocketAddr)> {
    recv_into_shared_buf(|buf| socket.try_recv_from(buf))
}

pub async fn recv_from(socket: &UdpSocket) -> io::Result<(Bytes, SocketAddr)> {
    loop {
        socket.readable().await?;
        match try_recv_from(socket) {
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
            result => return result,
        }
    }
}

pub async fn recv(socket: &UdpSocket) -> io::Result<Bytes> {
    loop {
        socket.readable().await?;
        match recv_into_shared_buf(|buf| socket.try_recv(buf).map(|n| (n, ()))) {
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
            result => return result.map(|(data, ())| data),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn datagrams_larger_than_mtu_arrive_whole() {
        let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        // macOS caps outgoing datagrams at the send buffer size (net.inet.udp.maxdgram, 9216).
        socket2::SockRef::from(&sender)
            .set_send_buffer_size(MAX_UDP_DATAGRAM)
            .unwrap();
        let payload: Vec<u8> = (0..16_000u32).map(|i| i as u8).collect();

        sender
            .send_to(&payload, receiver.local_addr().unwrap())
            .await
            .unwrap();
        let (data, from) = recv_from(&receiver).await.unwrap();

        assert_eq!(&data[..], &payload[..]);
        assert_eq!(from, sender.local_addr().unwrap());
    }

    #[tokio::test]
    async fn small_datagrams_keep_their_own_size() {
        let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        sender
            .connect(receiver.local_addr().unwrap())
            .await
            .unwrap();
        receiver
            .connect(sender.local_addr().unwrap())
            .await
            .unwrap();

        sender.send(b"first").await.unwrap();
        sender.send(b"second").await.unwrap();

        assert_eq!(&recv(&receiver).await.unwrap()[..], b"first");
        assert_eq!(&recv(&receiver).await.unwrap()[..], b"second");
        assert!(matches!(
            try_recv_from(&receiver),
            Err(e) if e.kind() == io::ErrorKind::WouldBlock
        ));
    }
}
