use crate::utils::interface::InterfaceInfo;
use crate::utils::interface::InterfaceInfoExt;
use std::sync::Arc;

#[cfg(not(target_os = "android"))]
use super::platform::must_bind_socket_on_interface;

use super::udp_recv::MAX_UDP_DATAGRAM;
use futures::io;
use std::net::SocketAddr;
use tokio::net::{TcpListener, TcpSocket, TcpStream, UdpSocket};
use tracing::{debug, trace};

fn resolve_domain(
    endpoint: Option<SocketAddr>,
    family_hint: Option<SocketAddr>,
    iface: Option<&InterfaceInfo>,
) -> socket2::Domain {
    if let Some(addr) = endpoint.or(family_hint) {
        return socket2::Domain::for_address(addr);
    }
    if let Some(iface) = iface {
        if iface.has_ipv6() {
            return socket2::Domain::IPV6;
        }
    }
    socket2::Domain::IPV4
}

fn create_socket(domain: socket2::Domain, ty: socket2::Type) -> std::io::Result<socket2::Socket> {
    socket2::Socket::new(domain, ty, None)
}

fn bind_to_interface(
    socket: &socket2::Socket,
    iface: &InterfaceInfo,
    family: socket2::Domain,
) -> std::io::Result<()> {
    #[cfg(not(target_os = "android"))]
    {
        must_bind_socket_on_interface(socket, iface, family)?;
        debug!("socket bound to interface: {}", iface.display_name());
    }
    #[cfg(target_os = "android")]
    {
        let _ = (socket, iface, family); // suppress unused warnings
    }
    Ok(())
}

#[cfg_attr(not(target_os = "linux"), allow(unused_variables))]
fn set_so_mark(socket: &socket2::Socket, so_mark: Option<u32>) -> std::io::Result<()> {
    #[cfg(all(target_os = "linux", not(target_os = "android")))]
    if let Some(mark) = so_mark {
        socket.set_mark(mark)?;
    }
    Ok(())
}

pub async fn new_tcp_stream(
    endpoint: SocketAddr,
    iface: Option<Arc<InterfaceInfo>>,
    so_mark: Option<u32>,
) -> std::io::Result<TcpStream> {
    let domain = socket2::Domain::for_address(endpoint);
    let socket = create_socket(domain, socket2::Type::STREAM)?;

    if let Some(ref iface) = iface
        && !endpoint.ip().is_loopback()
    {
        bind_to_interface(&socket, iface, domain)?;

        #[cfg(target_os = "linux")]
        {
            let bind_addr = match domain {
                socket2::Domain::IPV4 => {
                    SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 0)
                }
                _ => SocketAddr::new(std::net::IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED), 0),
            };
            socket.bind(&bind_addr.into())?;
        }
    } else {
        debug!("tcp socket not bound to any interface");
    }

    set_so_mark(&socket, so_mark)?;
    socket.set_keepalive(true)?;
    socket.set_tcp_nodelay(true)?;
    socket.set_nonblocking(true)?;

    TcpSocket::from_std_stream(socket.into())
        .connect(endpoint)
        .await
}

pub async fn new_udp_socket(
    src: Option<SocketAddr>,
    iface: Option<Arc<InterfaceInfo>>,
    family_hint: Option<SocketAddr>,
    so_mark: Option<u32>,
) -> std::io::Result<UdpSocket> {
    let domain = resolve_domain(src, family_hint, iface.as_deref());
    let socket = create_socket(domain, socket2::Type::DGRAM)?;

    let dst_is_loopback = family_hint.map(|a| a.ip().is_loopback()).unwrap_or(false);
    if !dst_is_loopback {
        bind_udp_socket(&socket, src, iface.as_deref(), domain)?;
    }

    set_so_mark(&socket, so_mark)?;
    socket.set_broadcast(true)?; // UDP only
    ensure_udp_send_buffer(&socket);
    socket.set_nonblocking(true)?;

    UdpSocket::from_std(socket.into())
}

/// macOS rejects any datagram larger than SO_SNDBUF with EMSGSIZE, and its default
/// (net.inet.udp.maxdgram) is only 9216 bytes. Only grows the buffer, never shrinks it.
pub fn ensure_udp_send_buffer(socket: &socket2::Socket) {
    if socket
        .send_buffer_size()
        .is_ok_and(|size| size < MAX_UDP_DATAGRAM)
        && let Err(e) = socket.set_send_buffer_size(MAX_UDP_DATAGRAM)
    {
        debug!("failed to raise UDP send buffer: {e}");
    }
}

fn bind_udp_socket(
    socket: &socket2::Socket,
    src: Option<SocketAddr>,
    iface: Option<&InterfaceInfo>,
    domain: socket2::Domain,
) -> std::io::Result<()> {
    if let Some(iface) = iface {
        bind_to_interface(socket, iface, domain)?;

        #[cfg(any(target_os = "windows", target_os = "linux"))]
        {
            let addr = src
                .map(socket2::SockAddr::from)
                .unwrap_or_else(|| _unspecified_addr(domain));
            socket.bind(&addr)?;
        }
        trace!("udp socket bound: {socket:?} iface={:?}", iface);
        return Ok(());
    }

    if let Some(src) = src {
        socket.bind(&src.into())?;
        trace!("udp socket bound: {socket:?} src={:?}", src);
        return Ok(());
    }

    trace!("udp socket not bound to any specific address: {socket:?}");

    #[cfg(target_os = "windows")]
    {
        socket.bind(&_unspecified_addr(domain))?;
    }

    Ok(())
}

fn _unspecified_addr(domain: socket2::Domain) -> socket2::SockAddr {
    let ip = match domain {
        socket2::Domain::IPV4 => std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
        _ => std::net::IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED),
    };
    SocketAddr::new(ip, 0).into()
}

/// Convert ipv6 mapped ipv4 address back to ipv4. Other address remain
/// unchanged. e.g. ::ffff:127.0.0.1 -> 127.0.0.1
pub trait ToCanonical {
    fn to_canonical(self) -> SocketAddr;
}

impl ToCanonical for SocketAddr {
    fn to_canonical(mut self) -> SocketAddr {
        self.set_ip(self.ip().to_canonical());
        self
    }
}

/// Create dualstack socket if it can
/// If failed, fallback to single stack silently
pub fn try_create_dualstack_socket(
    addr: SocketAddr,
    tcp_or_udp: socket2::Type,
) -> std::io::Result<(socket2::Socket, bool)> {
    let domain = if addr.is_ipv4() {
        socket2::Domain::IPV4
    } else {
        socket2::Domain::IPV6
    };
    let mut dualstack = false;
    let socket = socket2::Socket::new(domain, tcp_or_udp, None)?;
    if addr.is_ipv6() && addr.ip().is_unspecified() {
        if let Err(e) = socket.set_only_v6(false) {
            // If setting dualstack fails, fallback to single stack
            tracing::warn!("dualstack not supported, falling back to ipv6 only: {e}");
        } else {
            dualstack = true;
        }
    };
    socket.set_nonblocking(true)?;
    Ok((socket, dualstack))
}

pub fn try_create_dualstack_tcplistener(addr: SocketAddr) -> io::Result<TcpListener> {
    let (socket, _dualstack) = try_create_dualstack_socket(addr, socket2::Type::STREAM)?;

    // For fast restart avoid Address In Use Error
    socket.set_reuse_address(true)?;
    socket.bind(&addr.into())?;
    socket.listen(1024)?;

    let listener = TcpListener::from_std(socket.into())?;
    Ok(listener)
}

/// Socket buffer size requested for QUIC endpoints. The system defaults (about
/// 208 KiB on Linux) overflow during bursts at a few hundred Mbps; the dropped
/// datagrams look like congestion to BBR and cap throughput. quic-go asks for 7 MiB.
#[cfg(any(target_os = "ios", target_os = "android"))]
const QUIC_SOCKET_BUFFER: usize = 2 * 1024 * 1024;
#[cfg(not(any(target_os = "ios", target_os = "android")))]
const QUIC_SOCKET_BUFFER: usize = 8 * 1024 * 1024;

/// Grows the receive and send buffers of a QUIC endpoint socket towards
/// [`QUIC_SOCKET_BUFFER`]. Never shrinks them, and failures are only logged.
pub fn tune_quic_socket_buffers(socket: &std::net::UdpSocket) {
    let sock = socket2::SockRef::from(socket);
    grow_buffer(
        "receive",
        || sock.recv_buffer_size(),
        |size| sock.set_recv_buffer_size(size),
    );
    grow_buffer(
        "send",
        || sock.send_buffer_size(),
        |size| sock.set_send_buffer_size(size),
    );

    // Linux silently caps SO_RCVBUF at net.core.rmem_max; with CAP_NET_ADMIN
    // (servers usually run as root) SO_RCVBUFFORCE bypasses that cap.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    if sock
        .recv_buffer_size()
        .is_ok_and(|size| size < QUIC_SOCKET_BUFFER)
    {
        use std::os::fd::AsRawFd;
        let size = QUIC_SOCKET_BUFFER as libc::c_int;
        // SAFETY: valid fd and a c_int option value of the right length.
        let ret = unsafe {
            libc::setsockopt(
                socket.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_RCVBUFFORCE,
                &size as *const libc::c_int as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            )
        };
        if ret != 0 {
            debug!(
                "SO_RCVBUFFORCE failed, QUIC receive buffer stays capped by rmem_max: {}",
                std::io::Error::last_os_error()
            );
        }
    }
}

/// Requests `QUIC_SOCKET_BUFFER`, halving on rejection (macOS refuses sizes
/// above kern.ipc.maxsockbuf instead of capping them) until the current size.
fn grow_buffer(
    kind: &str,
    get: impl Fn() -> std::io::Result<usize>,
    set: impl Fn(usize) -> std::io::Result<()>,
) {
    let current = get().unwrap_or(0);
    let mut size = QUIC_SOCKET_BUFFER;
    while size > current {
        match set(size) {
            Ok(()) => {
                trace!("QUIC socket {kind} buffer set to {size}");
                return;
            }
            Err(e) => {
                trace!("QUIC socket {kind} buffer {size} rejected: {e}");
                size /= 2;
            }
        }
    }
    debug!("QUIC socket {kind} buffer left at {current}");
}

pub fn try_create_dualstack_udpsocket(addr: SocketAddr) -> io::Result<std::net::UdpSocket> {
    let (socket, _dualstack) = try_create_dualstack_socket(addr, socket2::Type::DGRAM)?;

    socket.bind(&addr.into())?;

    Ok(socket.into())
}
