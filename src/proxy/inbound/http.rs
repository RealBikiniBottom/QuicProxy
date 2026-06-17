use crate::config::InboundConfig;
use crate::proxy::TargetAddr;
use crate::proxy::inbound::{AnyInbound, create_tcp_listener, setup_system_proxy};
use crate::proxy::router::get_router;
use crate::utils::{PrefixedReadStream, format_duration, new_io_other_error, now};
use anyhow::Context;
use async_trait::async_trait;
use base64::Engine;
use base64::prelude::BASE64_STANDARD;
use bytes::BytesMut;
use serde::Deserialize;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tracing::{Instrument, debug, error, info, info_span};

#[derive(Clone, Debug, Deserialize)]
pub struct User {
    pub username: String,
    pub password: String,
}

pub struct HttpInbound {
    tag: String,
    idle_timeout: Duration,
    set_system_proxy: bool,
    addr: SocketAddr,
    users: Option<Vec<User>>,
}

pub struct StreamHandler<S> {
    pub stream: PrefixedReadStream<S>,
    pub target: TargetAddr,
}

impl HttpInbound {
    pub fn new(tag: String, cfg: &InboundConfig) -> anyhow::Result<Self> {
        let users = match (&cfg.username, &cfg.password) {
            (Some(u), Some(p)) => Some(vec![User {
                username: u.clone(),
                password: p.clone(),
            }]),
            _ => None,
        };
        let addr: SocketAddr = format!(
            "{}:{}",
            cfg.address.clone().context("Required address")?,
            cfg.port.context("Required port")?
        )
        .parse()
        .context("failed to parse SocketAddr")?;

        Ok(Self {
            tag,
            idle_timeout: Duration::from_secs(cfg.idle_timeout.unwrap_or(30)),
            set_system_proxy: cfg.set_system_proxy,
            addr,
            users,
        })
    }
}

#[async_trait]
impl AnyInbound for HttpInbound {
    fn protocol(&self) -> &str {
        "http"
    }

    fn idle_timeout(&self) -> Duration {
        self.idle_timeout
    }

    async fn listen(&self) -> anyhow::Result<()> {
        let listener = create_tcp_listener(self.addr).await?;
        info!("HTTP Inbound listening on {}", self.addr);

        let _proxy_guard = setup_system_proxy(
            self.set_system_proxy,
            &self.addr.ip().to_string(),
            self.addr.port(),
        )?;

        let users = self.users.as_ref().map(|u| Arc::new(u.clone()));
        let tag = self.tag.clone();

        loop {
            let (socket, peer_addr) = listener.accept().await?;
            info!("Accepted request from {}", peer_addr);
            let start_time = now();
            let router = get_router();
            let tag_clone = tag.clone();
            let users = users.clone();
            let span = info_span!("http", s = peer_addr.to_string(),);

            tokio::spawn(
                async move {
                    let result = handle_client(socket, users).await;
                    match result {
                        Ok(Some(handler)) => {
                            info!(
                                "Parsed dst: {} cost: {}",
                                handler.target,
                                format_duration(start_time.elapsed())
                            );

                            if let Err(e) = router
                                .dispatch_stream(
                                    Box::new(handler.stream),
                                    &handler.target,
                                    &tag_clone,
                                )
                                .await
                            {
                                error!("Routing error: {:?}", e);
                            }
                        }
                        Ok(None) => {
                            // Handled non-connect or failed gracefully
                        }
                        Err(e) => {
                            error!("HTTP Inbound error: {}", e);
                        }
                    }
                }
                .instrument(span),
            );
        }
    }
}

pub async fn handle_client<S>(
    mut socket: S,
    users: Option<Arc<Vec<User>>>,
) -> std::io::Result<Option<StreamHandler<S>>>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let mut buf = BytesMut::with_capacity(1024 * 2);

    // Read headers
    // We need to read until \r\n\r\n
    loop {
        let n = socket.read_buf(&mut buf).await?;
        if n == 0 {
            return Ok(None);
        }

        // Check if we have a full header
        let (method, path, headers_offset, host_header, auth_header) = {
            let mut headers = [httparse::EMPTY_HEADER; 64];
            let mut req = httparse::Request::new(&mut headers);
            match req.parse(&buf) {
                Ok(httparse::Status::Complete(offset)) => {
                    let m = req.method.unwrap_or("").to_string();
                    let p = req.path.unwrap_or("").to_string();
                    let h = req
                        .headers
                        .iter()
                        .find(|h| h.name.eq_ignore_ascii_case("Host"))
                        .map(|v| std::str::from_utf8(v.value).unwrap_or("").to_string());
                    let auth = req
                        .headers
                        .iter()
                        .find(|h| h.name.eq_ignore_ascii_case("Proxy-Authorization"))
                        .map(|v| std::str::from_utf8(v.value).unwrap_or("").to_string());
                    (Some(m), Some(p), Some(offset), h, auth)
                }
                Ok(httparse::Status::Partial) => (None, None, None, None, None),
                Err(e) => return Err(new_io_other_error(format!("Invalid HTTP request: {}", e))),
            }
        };

        if let Some(method) = method {
            let path = path.ok_or_else(|| new_io_other_error("path missing in parsed request"))?;
            let offset = headers_offset
                .ok_or_else(|| new_io_other_error("headers_offset missing in parsed request"))?;

            // Authentication logic
            if let Some(users) = &users {
                let mut authorized = false;
                if let Some(auth_val) = auth_header {
                    if let Some(encoded) = auth_val.strip_prefix("Basic ").map(|s| s.trim()) {
                        if let Ok(decoded) = BASE64_STANDARD.decode(encoded) {
                            if let Ok(creds) = String::from_utf8(decoded) {
                                if let Some((u, p)) = creds.split_once(':') {
                                    if users
                                        .iter()
                                        .any(|user| user.username == u && user.password == p)
                                    {
                                        authorized = true;
                                    }
                                }
                            }
                        }
                    }
                }

                if !authorized {
                    let response = "HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"Proxy\"\r\nContent-Length: 0\r\n\r\n";
                    socket.write_all(response.as_bytes()).await?;
                    return Err(new_io_other_error("Authentication failed"));
                }
            }

            if method == "CONNECT" {
                // Handle CONNECT
                let target = parse_target(&path)?;

                // Respond with 200 OK
                socket
                    .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                    .await?;

                // We consumed 'offset' bytes. The rest is payload (early data).
                // buf.split_off(offset) returns the suffix (payload), buf keeps prefix (headers).
                // We want the suffix as the prefix for the stream.
                let payload = buf.split_off(offset);

                if !payload.is_empty() {
                    debug!("HTTP CONNECT had {} bytes of early data", payload.len());
                }

                return Ok(Some(StreamHandler {
                    stream: PrefixedReadStream::new(socket, payload),
                    target,
                }));
            } else {
                // Handle other methods (GET, etc.)
                // Determine target
                let target = if path.starts_with("http://") || path.starts_with("https://") {
                    parse_url_target(&path)?
                } else if let Some(host) = host_header {
                    parse_host_header(&host)?
                } else {
                    return Err(new_io_other_error("No Host header or absolute URI"));
                };

                // Forward everything we read so far
                return Ok(Some(StreamHandler {
                    stream: PrefixedReadStream::new(socket, buf),
                    target,
                }));
            }
        }
    }
}

fn parse_target(path: &str) -> std::io::Result<TargetAddr> {
    // path for CONNECT is usually "host:port"
    if let Ok(addr) = path.parse::<std::net::SocketAddr>() {
        return Ok(TargetAddr::Ip(addr));
    }

    // Try domain:port
    if let Some((host, port_str)) = path.rsplit_once(':') {
        if let Ok(port) = port_str.parse::<u16>() {
            return Ok(TargetAddr::Domain(host.to_string(), port));
        }
    }

    Err(new_io_other_error(format!(
        "Invalid target in CONNECT: {}",
        path
    )))
}

fn parse_host_header(host: &str) -> std::io::Result<TargetAddr> {
    // host header can be "domain" or "domain:port" or "ip:port"
    if let Ok(addr) = host.parse::<std::net::SocketAddr>() {
        return Ok(TargetAddr::Ip(addr));
    }

    if let Some((domain, port_str)) = host.rsplit_once(':') {
        if let Ok(port) = port_str.parse::<u16>() {
            return Ok(TargetAddr::Domain(domain.to_string(), port));
        }
    }

    // Default to port 80 if no port specified
    Ok(TargetAddr::Domain(host.to_string(), 80))
}

fn parse_url_target(url: &str) -> std::io::Result<TargetAddr> {
    // Basic parsing for http://host:port/path or http://host/path
    // We can use a proper URL parser if we add 'url' crate, but for now manual parsing is okay if simple.
    // Or we can just strip scheme.

    let without_scheme = if let Some(rest) = url.strip_prefix("http://") {
        rest
    } else if let Some(rest) = url.strip_prefix("https://") {
        rest
    } else {
        url
    };

    // Find end of host (slash or end of string)
    let host_end = without_scheme.find('/').unwrap_or(without_scheme.len());
    let host_port = &without_scheme[..host_end];

    // Now parse host_port using parse_host_header logic (defaults to 80)
    // Wait, if it was https://, default port should be 443?
    // Standard HTTP proxy usually receives CONNECT for HTTPS.
    // If we receive GET https://..., it's weird but possible.
    // Let's assume port 80 if http://, 443 if https://

    let default_port = if url.starts_with("https://") { 443 } else { 80 };

    if let Ok(addr) = host_port.parse::<std::net::SocketAddr>() {
        return Ok(TargetAddr::Ip(addr));
    }

    if let Some((domain, port_str)) = host_port.rsplit_once(':') {
        if let Ok(port) = port_str.parse::<u16>() {
            return Ok(TargetAddr::Domain(domain.to_string(), port));
        }
    }

    Ok(TargetAddr::Domain(host_port.to_string(), default_port))
}
