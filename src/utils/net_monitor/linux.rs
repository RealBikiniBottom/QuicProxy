use std::io::Read;
use std::os::unix::io::AsRawFd;

use socket2::{Domain, Protocol, Socket, Type};
use tokio::io::unix::AsyncFd;
use tokio::sync::broadcast;

pub(crate) fn start_monitor(tx: broadcast::Sender<()>) -> Option<tokio::task::JoinHandle<()>> {
    Some(tokio::spawn(async move {
        if let Err(e) = monitor_linux(tx).await {
            tracing::error!("Network monitor failed: {}", e);
        }
    }))
}

pub(crate) fn stop_monitor() {}

async fn monitor_linux(tx: broadcast::Sender<()>) -> std::io::Result<()> {
    let domain = Domain::from(libc::AF_NETLINK);
    let socket = Socket::new(domain, Type::RAW, Some(Protocol::from(0)))?;
    let groups = 1 | 0x10 | 0x100;

    let mut addr: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
    addr.nl_family = libc::AF_NETLINK as u16;
    addr.nl_pid = 0;
    addr.nl_groups = groups;

    let socket_fd = socket.as_raw_fd();
    unsafe {
        let ret = libc::bind(
            socket_fd,
            &addr as *const _ as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_nl>() as u32,
        );
        if ret < 0 {
            return Err(std::io::Error::last_os_error());
        }
    }

    socket.set_nonblocking(true)?;
    let async_fd = AsyncFd::new(socket)?;
    let mut buf = [0u8; 4096];

    loop {
        let mut guard = async_fd.readable().await?;
        match guard.try_io(|inner| inner.get_ref().read(&mut buf)) {
            Ok(Ok(n)) => {
                if n > 0 {
                    tracing::debug!("Network change detected (Netlink)");
                    let _ = tx.send(());
                } else {
                    tracing::warn!("Netlink socket closed (EOF)");
                    break;
                }
            }
            Ok(Err(e)) => return Err(e),
            Err(_) => continue,
        }
    }
    Ok(())
}
