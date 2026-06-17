use crate::config::InboundConfig;
use crate::proxy::inbound::{AnyInbound, create_tcp_listener, setup_system_proxy};
use crate::proxy::outbound::{AnyPacket, PacketInfo};
use crate::proxy::router::{Router, get_router, start_udp_loop};
use crate::proxy::{SourceAddr, TargetAddr};
use crate::utils::new_io_timeout_error;
use crate::utils::{format_duration, new_io_other_error, now};
use anyhow::Context;
use async_trait::async_trait;
use bytes::{Bytes, BytesMut};
use serde::Deserialize;
use std::io::Result;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::net::UdpSocket;
use tokio::sync::{Mutex, Notify};
use tokio::time::{self, Duration};
use tracing::{Instrument, error, info, info_span};
use tracing::{debug, field};

#[derive(Clone, Debug, Deserialize)]
pub struct User {
    pub username: String,
    pub password: String,
}

pub struct Socks5Inbound {
    tag: String,
    idle_timeout: Duration,
    addr: SocketAddr,
    set_system_proxy: bool,
    users: Option<Vec<User>>,
}

impl Socks5Inbound {
    pub fn new(tag: String, cfg: &InboundConfig) -> anyhow::Result<Self> {
        let addr: SocketAddr = format!(
            "{}:{}",
            cfg.address.clone().context("Required address")?,
            cfg.port.context("Required port")?
        )
        .parse()
        .context("failed to parse SocketAddr")?;

        let users = match (&cfg.username, &cfg.password) {
            (Some(u), Some(p)) => Some(vec![User {
                username: u.clone(),
                password: p.clone(),
            }]),
            _ => None,
        };

        Ok(Self {
            tag,
            idle_timeout: Duration::from_secs(cfg.idle_timeout.unwrap_or(30)),
            addr,
            set_system_proxy: cfg.set_system_proxy,
            users,
        })
    }
}

#[async_trait]
impl AnyInbound for Socks5Inbound {
    fn protocol(&self) -> &str {
        "socks5"
    }

    fn idle_timeout(&self) -> Duration {
        self.idle_timeout
    }

    async fn listen(&self) -> anyhow::Result<()> {
        let listener = create_tcp_listener(self.addr).await?;
        info!("Socks5 Inbound listening on {}", self.addr);

        let _proxy_guard = setup_system_proxy(
            self.set_system_proxy,
            &self.addr.ip().to_string(),
            self.addr.port(),
        )?;

        let tag = self.tag.clone();

        loop {
            let (socket, peer_addr) = listener.accept().await?;
            let start_time = now();
            let tag_clone = tag.clone();
            let local_addr = socket.local_addr().ok();

            let router = get_router();
            let users = self.users.clone();
            let idle_timeout = self.idle_timeout;

            tokio::spawn(async move {
                let result = time::timeout(
                    Duration::from_secs(10),
                    handle_client(socket, peer_addr, local_addr, users),
                )
                .await
                .map_err(|_| new_io_timeout_error("Handshake timeout"))
                .and_then(|res| res);
                match result {
                    Ok(Some(Socks5Handler::Stream(stream, target))) => {
                        let span = info_span!(
                            "tcp",
                            i = tag_clone,
                            s = peer_addr.to_string(),
                            d = field::Empty,
                            r = field::Empty,
                            o = field::Empty
                        );
                        info!(
                            "Parsed dst: {} cost {}",
                            target,
                            format_duration(start_time.elapsed())
                        );
                        if let Err(e) = router
                            .dispatch_stream(Box::new(stream), &target, &tag_clone)
                            .instrument(span)
                            .await
                        {
                            error!("Routing stream error: {:?}", e);
                        }
                    }
                    Ok(Some(Socks5Handler::Packet(udp_socket, client_addr, tcp_socket))) => {
                        info!(
                            "SOCKS5 UDP ASSOCIATE from {}. Routing packets...",
                            peer_addr
                        );

                        start_udp_worker(
                            router.clone(),
                            udp_socket,
                            client_addr,
                            tcp_socket,
                            idle_timeout,
                            tag_clone,
                        )
                        .await;
                    }
                    Ok(None) => {}
                    Err(e) => {
                        error!("Inbound error: {}", e);
                    }
                }
            });
            info!("Accepted connection from {}", peer_addr);
        }
    }
}

pub enum Socks5Handler<S> {
    Stream(S, TargetAddr),
    Packet(Arc<UdpSocket>, SocketAddr, S),
}

pub struct UdpWorkerConfig {
    pub session_timeout: Duration,
    pub cleanup_interval: Duration,
}

impl Default for UdpWorkerConfig {
    fn default() -> Self {
        Self {
            session_timeout: Duration::from_secs(100),
            cleanup_interval: Duration::from_secs(60),
        }
    }
}

struct Socks5InboundPacket {
    socket: Arc<UdpSocket>,
    client_tcp_addr: SocketAddr,
    client_udp_addr: Mutex<Option<SocketAddr>>,
}

#[async_trait]
impl AnyPacket for Socks5InboundPacket {
    async fn send_to(
        &self,
        buf: Bytes,
        _target: &TargetAddr,
        from: &SourceAddr,
    ) -> anyhow::Result<usize> {
        let guard = self.client_udp_addr.lock().await;
        let client_addr = match *guard {
            Some(addr) => addr,
            None => {
                return Err(anyhow::anyhow!("No client UDP address known yet",));
            }
        };
        drop(guard);

        let mut header = vec![0x00, 0x00, 0x00];
        header.extend_from_slice(&from.to_bytes());

        let mut data = Vec::with_capacity(header.len() + buf.len());
        data.extend_from_slice(&header);
        data.extend_from_slice(&buf);
        self.socket
            .send_to(&data, client_addr)
            .await
            .map_err(Into::into)
    }

    async fn recv_from(&self) -> anyhow::Result<PacketInfo> {
        let mut buf = BytesMut::with_capacity(1024 * 2);
        loop {
            buf.clear();
            let (n, src) = self.socket.recv_buf_from(&mut buf).await?;

            if src.ip() != self.client_tcp_addr.ip() {
                continue;
            }

            if n < 4 {
                continue;
            }

            // Save client UDP address for sending responses back
            let mut client_udp_addr = self.client_udp_addr.lock().await;
            *client_udp_addr = Some(src);
            drop(client_udp_addr);

            // SOCKS5 UDP header format:
            // +----+------+------+----------+----------+----------+
            // |RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
            // +----+------+------+----------+----------+----------+
            // | 2  |  1   |  1   | Variable |    2     | Variable |
            // +----+------+------+----------+----------+----------+
            let mut cursor = std::io::Cursor::new(&buf[3..n]);
            match TargetAddr::read_from(&mut cursor).await {
                Ok(target) => {
                    let header_len = cursor.position() as usize;
                    let payload_start = 3 + header_len;
                    if payload_start > n {
                        continue;
                    }
                    let _ = buf.split_to(payload_start);
                    return Ok((TargetAddr::Ip(src), target, buf.freeze()));
                }
                Err(_) => continue,
            }
        }
    }
}

pub async fn start_udp_worker(
    router: Arc<Router>,
    udp_socket: Arc<UdpSocket>,
    client_addr: SocketAddr,
    mut tcp_socket: TcpStream,
    timeout_duration: Duration,
    inbound_tag: String,
) {
    let inbound_packet = Arc::new(Socks5InboundPacket {
        socket: udp_socket,
        client_tcp_addr: client_addr,
        client_udp_addr: Mutex::new(None),
    });

    let reset = Arc::new(Notify::new());
    let reset_clone = reset.clone();
    tokio::spawn(async move {
        let mut drain_buf = [0u8; 1];
        loop {
            match tcp_socket.read(&mut drain_buf).await {
                Err(_) => break,
                Ok(0) => continue,
                Ok(_) => continue,
            }
        }
        debug!("tcp control stream reset");
        reset_clone.notify_waiters();
    });

    start_udp_loop(inbound_packet, router, inbound_tag, timeout_duration, reset).await;
}

pub async fn handle_client(
    mut tcp_socket: TcpStream,
    peer_addr: SocketAddr,
    local_addr: Option<SocketAddr>,
    users: Option<Vec<User>>,
) -> Result<Option<Socks5Handler<TcpStream>>> {
    // 1. Handshake
    let mut buf = [0u8; 2];
    tcp_socket.read_exact(&mut buf).await?;

    if buf[0] != 0x05 {
        return Err(new_io_other_error("Not SOCKS5 protocol"));
    }

    let nmethods = buf[1] as usize;
    let mut methods = vec![0u8; nmethods];
    tcp_socket.read_exact(&mut methods).await?;

    let method = if users.is_some() {
        if methods.contains(&0x02) {
            0x02
        } else {
            tcp_socket.write_all(&[0x05, 0xFF]).await?;
            return Err(new_io_other_error("No acceptable methods (auth required)"));
        }
    } else {
        if methods.contains(&0x00) {
            0x00
        } else {
            tcp_socket.write_all(&[0x05, 0xFF]).await?;
            return Err(new_io_other_error("No acceptable methods"));
        }
    };

    tcp_socket.write_all(&[0x05, method]).await?;

    if method == 0x02 {
        // Auth sub-negotiation
        let mut ver = [0u8; 1];
        tcp_socket.read_exact(&mut ver).await?;
        if ver[0] != 0x01 {
            return Err(new_io_other_error("Unsupported auth version"));
        }

        let mut ulen = [0u8; 1];
        tcp_socket.read_exact(&mut ulen).await?;
        let mut uname = vec![0u8; ulen[0] as usize];
        tcp_socket.read_exact(&mut uname).await?;

        let mut plen = [0u8; 1];
        tcp_socket.read_exact(&mut plen).await?;
        let mut passwd = vec![0u8; plen[0] as usize];
        tcp_socket.read_exact(&mut passwd).await?;

        let username = String::from_utf8_lossy(&uname);
        let password = String::from_utf8_lossy(&passwd);

        let valid = if let Some(users_list) = &users {
            users_list
                .iter()
                .any(|u| u.username == username && u.password == password)
        } else {
            false
        };

        if valid {
            tcp_socket.write_all(&[0x01, 0x00]).await?; // Success
        } else {
            tcp_socket.write_all(&[0x01, 0x01]).await?; // Failure
            return Err(new_io_other_error("Authentication failed"));
        }
    }

    // 2. Request
    let mut head = [0u8; 3];
    tcp_socket.read_exact(&mut head).await?;

    let ver = head[0];
    let cmd = head[1];
    let _rsv = head[2];

    if ver != 0x05 {
        return Err(new_io_other_error("Malformed SOCKS5 request"));
    }

    match cmd {
        0x01 => {
            // CONNECT (TCP)
            let target = parse_target(&mut tcp_socket).await?;

            // Reply success
            // BND.ADDR and BND.PORT should be the server's.
            // For simplicity, returning 0.0.0.0:0
            tcp_socket
                .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await?;

            Ok(Some(Socks5Handler::Stream(tcp_socket, target)))
        }
        0x03 => {
            // UDP ASSOCIATE
            let _client_udp_addr = parse_target(&mut tcp_socket).await?;

            // Bind a UDP socket
            // We should bind to the same interface as the TCP connection came from, ideally.
            let udp_bind_addr = if let Some(addr) = local_addr {
                SocketAddr::new(addr.ip(), 0)
            } else {
                "0.0.0.0:0".parse().unwrap()
            };

            let udp_socket = match UdpSocket::bind(udp_bind_addr).await {
                Ok(s) => s,
                Err(e) => {
                    info!(
                        "Failed to bind UDP to {}, falling back to 0.0.0.0:0. Error: {}",
                        udp_bind_addr, e
                    );
                    UdpSocket::bind("0.0.0.0:0").await?
                }
            };
            let local_addr = udp_socket.local_addr()?;

            info!("Bound UDP socket for SOCKS5 ASSOCIATE at {}", local_addr);

            // Reply with BND.ADDR/PORT
            let mut response = vec![0x05, 0x00, 0x00];
            match local_addr {
                SocketAddr::V4(v4) => {
                    response.push(0x01);
                    response.extend_from_slice(&v4.ip().octets());
                }
                SocketAddr::V6(v6) => {
                    response.push(0x04);
                    response.extend_from_slice(&v6.ip().octets());
                }
            }
            response.extend_from_slice(&local_addr.port().to_be_bytes());
            tcp_socket.write_all(&response).await?;

            Ok(Some(Socks5Handler::Packet(
                Arc::new(udp_socket),
                peer_addr,
                tcp_socket,
            )))
        }
        _ => {
            tcp_socket
                .write_all(&[0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await?;
            Err(new_io_other_error(format!("Unsupported command: {}", cmd)))
        }
    }
}

async fn parse_target<S>(socket: &mut S) -> Result<TargetAddr>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    TargetAddr::read_from(socket)
        .await
        .map_err(|e| std::io::Error::other(format!("{e}")))
}
