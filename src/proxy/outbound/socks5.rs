use anyhow::{Context, Result};
use async_trait::async_trait;
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UdpSocket;
use tokio::sync::watch;
use tokio::time::timeout;

use crate::config::OutboundConfig;
use crate::proxy::outbound::{AnyOutbound, AnyPacket, AnyStream, PacketInfo};
use crate::proxy::{SourceAddr, TargetAddr};

use crate::utils::new_io_other_error;
use std::time::Duration;

pub struct Socks5Outbound {
    tag: String,
    address: TargetAddr,
    username: Option<String>,
    password: Option<String>,
    connect_timeout: Duration,
    dns_server_name: Option<String>,
    bind_interface: Option<String>,
}

impl Socks5Outbound {
    pub fn new(tag: String, cfg: &OutboundConfig) -> Result<Arc<Self>> {
        let address = cfg.endpoint(&tag)?;

        Ok(Arc::new(Self {
            tag,
            address,
            username: cfg.username.clone(),
            password: cfg.password.clone(),
            connect_timeout: cfg.connect_timeout(),
            dns_server_name: cfg.dns.clone(),
            bind_interface: cfg.bind_interface.clone(),
        }))
    }
}

#[async_trait]
impl AnyOutbound for Socks5Outbound {
    fn tag(&self) -> &str {
        &self.tag
    }

    fn protocol(&self) -> &str {
        "socks5"
    }

    fn dns_server_name(&self) -> Option<&str> {
        self.dns_server_name.as_deref()
    }

    fn bind_interface(&self) -> Option<&str> {
        self.bind_interface.as_deref()
    }

    fn connect_timeout(&self) -> Duration {
        self.connect_timeout
    }

    async fn connect_stream_base(&self) -> anyhow::Result<AnyStream> {
        let proxy_addr = self.resolve_addr(&self.address).await?;

        let stream = self.new_tcp_stream(proxy_addr).await?;
        Ok(Box::new(stream))
    }

    async fn connect_stream_with(
        &self,
        target: &TargetAddr,
        mut stream: AnyStream,
    ) -> anyhow::Result<AnyStream> {
        // Wrap SOCKS5 handshake in connect timeout
        let handshake_future = async {
            // 1. Handshake
            // Send methods: [VER, NMETHODS, METHODS...]
            let mut methods = vec![0x00]; // NO AUTH
            if self.username.is_some() && self.password.is_some() {
                methods.push(0x02); // USERNAME/PASSWORD
            }

            let mut handshake = vec![0x05, methods.len() as u8];
            handshake.extend_from_slice(&methods);
            stream.write_all(&handshake).await?;

            let mut buf = [0u8; 2];
            stream.read_exact(&mut buf).await?;

            if buf[0] != 0x05 {
                return Err(new_io_other_error(format!(
                    "SOCKS5 proxy handshake failed: invalid version {}",
                    buf[0]
                )));
            }

            // Auth
            if buf[1] == 0x02 {
                if let (Some(u), Some(p)) = (&self.username, &self.password) {
                    // RFC 1929
                    let mut auth_req = vec![0x01];
                    auth_req.push(u.len() as u8);
                    auth_req.extend_from_slice(u.as_bytes());
                    auth_req.push(p.len() as u8);
                    auth_req.extend_from_slice(p.as_bytes());

                    stream.write_all(&auth_req).await?;

                    let mut auth_resp = [0u8; 2];
                    stream.read_exact(&mut auth_resp).await?;

                    if auth_resp[1] != 0x00 {
                        return Err(new_io_other_error("SOCKS5 authentication failed"));
                    }
                } else {
                    return Err(new_io_other_error(
                        "SOCKS5 proxy requested auth but no credentials provided",
                    ));
                }
            } else if buf[1] != 0x00 {
                return Err(new_io_other_error(format!(
                    "SOCKS5 proxy handshake failed: unsupported method {}",
                    buf[1]
                )));
            }

            // 2. Request
            // [VER, CMD, RSV, ATYP, DST.ADDR, DST.PORT]
            let mut request = vec![0x05, 0x01, 0x00]; // CONNECT

            if let TargetAddr::Domain(domain, _) = target {
                if domain.as_bytes().len() > 255 {
                    return Err(new_io_other_error("Domain name too long"));
                }
            }
            request.extend_from_slice(&target.to_bytes());

            stream.write_all(&request).await?;

            // 3. Reply
            // [VER, REP, RSV, ATYP, BND.ADDR, BND.PORT]
            let mut head = [0u8; 3];
            stream.read_exact(&mut head).await?;

            if head[0] != 0x05 {
                return Err(new_io_other_error("Invalid SOCKS5 reply version"));
            }

            if head[1] != 0x00 {
                return Err(new_io_other_error(format!(
                    "SOCKS5 proxy connect failed: error code {}",
                    head[1]
                )));
            }

            let _ = TargetAddr::read_from(&mut stream).await;

            Ok(Box::new(stream))
        };

        let stream = timeout(self.connect_timeout(), handshake_future)
            .await
            .with_context(|| format!("Timeout after {:?}", self.connect_timeout()))? // 处理 Elapsed
            .context("Handshake execution failed")?; // 处理 Future 内部的错误
        Ok(stream)
    }

    async fn connect_packet(&self, target: &TargetAddr) -> anyhow::Result<Arc<dyn AnyPacket>> {
        let proxy_addr = self.resolve_addr(&self.address).await?;
        let mut stream = self.new_tcp_stream(proxy_addr).await?;

        // Wrap UDP ASSOCIATE handshake in connect timeout
        let (relay_addr, _) = timeout(self.connect_timeout(), async {
            // Handshake (Auth)
            let mut methods = vec![0x00]; // NO AUTH
            if self.username.is_some() && self.password.is_some() {
                methods.push(0x02); // USERNAME/PASSWORD
            }

            let mut handshake = vec![0x05, methods.len() as u8];
            handshake.extend_from_slice(&methods);
            stream.write_all(&handshake).await?;

            let mut buf = [0u8; 2];
            stream.read_exact(&mut buf).await?;

            if buf[0] != 0x05 {
                return Err(new_io_other_error(format!(
                    "SOCKS5 proxy handshake failed: invalid version {}",
                    buf[0]
                )));
            }

            if buf[1] == 0x02 {
                if let (Some(u), Some(p)) = (&self.username, &self.password) {
                    let mut auth_req = vec![0x01];
                    auth_req.push(u.len() as u8);
                    auth_req.extend_from_slice(u.as_bytes());
                    auth_req.push(p.len() as u8);
                    auth_req.extend_from_slice(p.as_bytes());

                    stream.write_all(&auth_req).await?;

                    let mut auth_resp = [0u8; 2];
                    stream.read_exact(&mut auth_resp).await?;

                    if auth_resp[1] != 0x00 {
                        return Err(new_io_other_error("SOCKS5 authentication failed"));
                    }
                } else {
                    return Err(new_io_other_error(
                        "SOCKS5 proxy requested auth but no credentials provided",
                    ));
                }
            } else if buf[1] != 0x00 {
                return Err(new_io_other_error(format!(
                    "SOCKS5 proxy handshake failed: unsupported method {}",
                    buf[1]
                )));
            }

            // UDP ASSOCIATE
            let request = vec![0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
            stream.write_all(&request).await?;

            let mut head = [0u8; 3];
            stream.read_exact(&mut head).await?;

            if head[0] != 0x05 {
                return Err(new_io_other_error("Invalid SOCKS5 reply version"));
            }
            if head[1] != 0x00 {
                return Err(new_io_other_error(format!(
                    "SOCKS5 UDP ASSOCIATE failed: error code {}",
                    head[1]
                )));
            }

            let relay_target = TargetAddr::read_from(&mut stream)
                .await
                .map_err(|e| new_io_other_error(format!("{e}")))?;
            let relay_addr = match relay_target {
                TargetAddr::Ip(sa) => sa,
                TargetAddr::Domain(_, _) => {
                    return Err(new_io_other_error(
                        "SOCKS5 UDP relay returned domain, which is not supported yet",
                    ));
                }
            };

            // Prepare Header
            let mut header = vec![0x00, 0x00, 0x00];
            header.extend_from_slice(&target.to_bytes());

            Ok((relay_addr, header))
        })
        .await
        .map_err(|_| crate::utils::new_io_timeout_error("SOCKS5 connect timeout"))??;

        // Connect UDP socket
        let udp_socket = self.new_udp_socket(relay_addr).await?;
        udp_socket.connect(relay_addr).await?;

        let inner = Arc::new(Socks5UdpSocket::new(
            udp_socket,
            Box::new(stream) as AnyStream,
        ));

        Ok(inner)
    }
}

struct Socks5UdpSocket {
    udp: UdpSocket,
    _tcp: Mutex<Option<tokio::io::WriteHalf<AnyStream>>>,
    abort_rx: watch::Receiver<bool>,
    closer: Arc<crate::proxy::SessionCloser>,
}

impl Socks5UdpSocket {
    fn new(udp: UdpSocket, stream: AnyStream) -> Self {
        let (mut r, w) = tokio::io::split(stream);
        let (abort_tx, abort_rx) = watch::channel(false);
        let closer = Arc::new(crate::proxy::SessionCloser::new());
        let closer_clone = closer.clone();

        tokio::spawn(async move {
            let mut buf = [0u8; 1];
            loop {
                tokio::select! {
                    _ = closer_clone.wait() => break,
                    res = r.read(&mut buf) => {
                        match res {
                            Ok(0) => break,
                            Ok(_) => {}
                            Err(_) => break,
                        }
                    }
                }
            }
            let _ = abort_tx.send(true);
        });

        Self {
            udp,
            _tcp: Mutex::new(Some(w)),
            abort_rx,
            closer,
        }
    }
}

impl Drop for Socks5UdpSocket {
    fn drop(&mut self) {
        if let Ok(mut lock) = self._tcp.lock() {
            if let Some(mut stream) = lock.take() {
                tokio::spawn(async move {
                    let _ = stream.shutdown().await;
                });
            }
        }
    }
}

use bytes::{Bytes, BytesMut};

#[async_trait]
impl AnyPacket for Socks5UdpSocket {
    fn closer(&self) -> Arc<crate::proxy::SessionCloser> {
        self.closer.clone()
    }

    async fn send_to(
        &self,
        buf: Bytes,
        _from: &SourceAddr,
        target: &TargetAddr,
    ) -> anyhow::Result<usize> {
        if *self.abort_rx.borrow() {
            return Err(anyhow::anyhow!("Control stream closed"));
        }

        let mut header = vec![0x00, 0x00, 0x00];
        if let TargetAddr::Domain(domain, _) = target {
            if domain.as_bytes().len() > 255 {
                return Err(anyhow::anyhow!("Domain name too long"));
            }
        }
        header.extend_from_slice(&target.to_bytes());

        let mut data = Vec::with_capacity(header.len() + buf.len());
        data.extend_from_slice(&header);
        data.extend_from_slice(&buf);
        self.udp.send(&data).await.map_err(Into::into)
    }

    async fn recv_from(&self) -> anyhow::Result<PacketInfo> {
        let mut buf = BytesMut::with_capacity(1024 * 2);
        let mut abort_rx = self.abort_rx.clone();
        loop {
            buf.clear();
            let n = tokio::select! {
                res = self.udp.recv_buf(&mut buf) => res?,
                _ = abort_rx.changed() => {
                    return Err(anyhow::anyhow!("Control stream closed"));
                }
                _ = self.closer.wait() => {
                    return Err(anyhow::anyhow!("Session closed"));
                }
            };

            if n < 4 {
                continue;
            }

            let mut cursor = std::io::Cursor::new(&buf[3..n]);
            match TargetAddr::read_from(&mut cursor).await {
                Ok(target) => {
                    let header_len = 3 + cursor.position() as usize;
                    if header_len > n {
                        continue;
                    }

                    let _ = buf.split_to(header_len);
                    return Ok((target, TargetAddr::dummy(), buf.freeze()));
                }
                Err(_) => continue,
            }
        }
    }
}
