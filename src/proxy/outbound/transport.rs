//! v2ray-style stream transports for outbounds.
//!
//! A transport wraps the raw base connection (plain TCP or TCP + TLS) of an
//! outbound into another byte stream before the proxy protocol handshake is
//! written. Only `ws` (RFC 6455 client over an existing stream) is currently
//! implemented; plain TCP returns the stream untouched.

use std::io;
use std::pin::Pin;
use std::task::{Context as TaskContext, Poll};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use bytes::{Buf, BytesMut};
use futures::{Sink, Stream};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::time::timeout;
use tokio_tungstenite::tungstenite::{
    client::IntoClientRequest,
    error::Error as WsError,
    protocol::{Message, WebSocketConfig},
};
use tokio_tungstenite::WebSocketStream;

use crate::config::TransportConfig;
use crate::proxy::outbound::AnyStream;
use crate::proxy::TargetAddr;

/// Wrap `stream` (an established TCP or TCP+TLS connection) with the stream
/// transport configured on an outbound.
///
/// The base connection is returned unchanged when no transport is configured
/// or its type is the plain TCP transport.
pub async fn wrap_transport_stream(
    transport: Option<&TransportConfig>,
    server: &TargetAddr,
    stream: AnyStream,
    connect_timeout: Duration,
) -> Result<AnyStream> {
    let Some(transport) = transport else {
        return Ok(stream);
    };

    match transport.protocol_type.as_str() {
        "" | "tcp" => Ok(stream),
        "ws" | "websocket" => {
            let ws = connect_websocket(transport, server, stream, connect_timeout).await?;
            Ok(Box::new(ws))
        }
        other => bail!("unsupported transport type: {}", other),
    }
}

async fn connect_websocket(
    transport: &TransportConfig,
    server: &TargetAddr,
    stream: AnyStream,
    connect_timeout: Duration,
) -> Result<WsByteStream<AnyStream>> {
    let authority = ws_authority(transport, server);
    let path = ws_path(transport);
    let request = format!("ws://{}{}", authority, path).into_client_request().map_err(|e| {
        new_ws_error(format!("invalid websocket request URL: {}", e))
    })?;

    let config = WebSocketConfig::default();
    let (ws, _response) = timeout(
        connect_timeout,
        tokio_tungstenite::client_async_with_config(request, stream, Some(config)),
    )
    .await
    .with_context(|| format!("websocket handshake timeout after {:?}", connect_timeout))?
    .context("websocket handshake failed")?;

    Ok(WsByteStream::new(ws))
}

/// The HTTP Host / URL authority of the upgrade request.
///
/// A configured `host` overrides the server endpoint (v2ray `ws`-style
/// virtual hosting); otherwise the server `host:port` is used, which matches
/// how sing-box builds its websocket requests.
fn ws_authority(transport: &TransportConfig, server: &TargetAddr) -> String {
    if let Some(host) = transport.host.as_deref().filter(|host| !host.is_empty()) {
        return host.to_string();
    }
    match server {
        TargetAddr::Ip(addr) => addr.to_string(),
        TargetAddr::Domain(host, port) => format!("{}:{}", host, port),
    }
}

fn ws_path(transport: &TransportConfig) -> String {
    let path = transport.path.as_deref().unwrap_or("/");
    if path.is_empty() {
        return "/".to_string();
    }
    if path.starts_with('/') {
        path.to_string()
    } else {
        format!("/{}", path)
    }
}

fn new_ws_error(message: impl Into<String>) -> anyhow::Error {
    anyhow::anyhow!(message.into())
}

fn ws_io_error(error: WsError) -> io::Error {
    match error {
        WsError::Io(error) => error,
        other => io::Error::other(other.to_string()),
    }
}

/// A websocket connection adapted back into a plain duplex byte stream.
///
/// Outgoing bytes are sent as websocket binary messages; incoming binary (and
/// text, tolerated for interoperability) messages are re-assembled into a
/// continuous stream. Control frames and fragmentation are handled by
/// tungstenite.
pub struct WsByteStream<S> {
    inner: WebSocketStream<S>,
    read_buf: BytesMut,
    read_eof: bool,
}

impl<S> WsByteStream<S> {
    pub fn new(inner: WebSocketStream<S>) -> Self {
        Self {
            inner,
            read_buf: BytesMut::new(),
            read_eof: false,
        }
    }
}

impl<S> AsyncRead for WsByteStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = &mut *self;
        loop {
            if !this.read_buf.is_empty() {
                let n = this.read_buf.len().min(buf.remaining());
                buf.put_slice(&this.read_buf[..n]);
                this.read_buf.advance(n);
                return Poll::Ready(Ok(()));
            }
            if this.read_eof {
                return Poll::Ready(Ok(()));
            }
            match Pin::new(&mut this.inner).poll_next(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(None) => {
                    this.read_eof = true;
                    return Poll::Ready(Ok(()));
                }
                Poll::Ready(Some(Err(error))) => return Poll::Ready(Err(ws_io_error(error))),
                Poll::Ready(Some(Ok(message))) => match message {
                    Message::Binary(data) => this.read_buf.extend_from_slice(&data),
                    Message::Text(data) => this.read_buf.extend_from_slice(data.as_bytes()),
                    Message::Close(_) => {
                        this.read_eof = true;
                        return Poll::Ready(Ok(()));
                    }
                    Message::Ping(_) | Message::Pong(_) | Message::Frame(_) => {}
                },
            }
        }
    }
}

impl<S> AsyncWrite for WsByteStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = &mut *self;
        match Pin::new(&mut this.inner).poll_ready(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(error)) => return Poll::Ready(Err(ws_io_error(error))),
            Poll::Ready(Ok(())) => {}
        }

        if let Err(error) = Pin::new(&mut this.inner)
            .start_send(Message::Binary(buf.to_vec().into()))
        {
            return Poll::Ready(Err(ws_io_error(error)));
        }

        // Drive the buffered frames down to the underlying stream right away so
        // small writes are not held back by tungstenite's internal write
        // buffer. If the socket is blocked the message is already accepted and
        // a later poll finishes the flush.
        match Pin::new(&mut this.inner).poll_flush(cx) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(buf.len())),
            Poll::Ready(Err(WsError::ConnectionClosed)) => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "websocket connection closed",
            ))),
            Poll::Ready(Err(error)) => Poll::Ready(Err(ws_io_error(error))),
            Poll::Pending => Poll::Ready(Ok(buf.len())),
        }
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<io::Result<()>> {
        let this = &mut *self;
        match Pin::new(&mut this.inner).poll_flush(cx) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
            Poll::Ready(Err(WsError::ConnectionClosed)) => Poll::Ready(Ok(())),
            Poll::Ready(Err(error)) => Poll::Ready(Err(ws_io_error(error))),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<io::Result<()>> {
        let this = &mut *self;
        // Sends the websocket close frame (half-close). Reads may still
        // continue until the peer closes the connection, mirroring TCP
        // half-close semantics used by `copy_bidirectional`.
        match Pin::new(&mut this.inner).poll_close(cx) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
            Poll::Ready(Err(WsError::ConnectionClosed)) => Poll::Ready(Ok(())),
            Poll::Ready(Err(error)) => Poll::Ready(Err(ws_io_error(error))),
            Poll::Pending => Poll::Pending,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    fn ws_config(path: &str) -> TransportConfig {
        TransportConfig {
            protocol_type: "ws".to_string(),
            path: Some(path.to_string()),
            host: None,
            service_name: None,
        }
    }

    /// Start a websocket echo server on a random localhost port and return its
    /// address. The server accepts one connection and echoes every byte it
    /// receives back over the websocket.
    async fn spawn_ws_echo_server() -> std::net::SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let ws = tokio_tungstenite::accept_async(tcp).await.unwrap();
            let stream = WsByteStream::new(ws);
            let (mut rd, mut wr) = tokio::io::split(stream);
            let _ = tokio::io::copy(&mut rd, &mut wr).await;
        });
        addr
    }

    #[tokio::test]
    async fn ws_transport_echoes_small_and_large_payloads() {
        let addr = spawn_ws_echo_server().await;

        let tcp = TcpStream::connect(addr).await.unwrap();
        let target = TargetAddr::from_str2("127.0.0.1", addr.port()).unwrap();
        let transport_cfg = ws_config("/trojan");
        let stream: AnyStream = wrap_transport_stream(
            Some(&transport_cfg),
            &target,
            Box::new(tcp) as AnyStream,
            Duration::from_secs(5),
        )
        .await
        .expect("websocket client handshake must succeed");

        let (mut rd, mut wr) = tokio::io::split(stream);

        // Small round trip.
        let small = b"trojan-over-websocket small payload";
        wr.write_all(small).await.unwrap();
        let mut echoed = vec![0; small.len()];
        rd.read_exact(&mut echoed).await.unwrap();
        assert_eq!(&echoed, small);

        // Large payload spanning many websocket messages in both directions.
        const CHUNK: usize = 64 * 1024;
        const CHUNKS: usize = 32; // 2 MiB total
        let expected = (0..CHUNK)
            .map(|i| ((i * 31) % 251) as u8)
            .collect::<Vec<_>>();
        let expected_for_writer = expected.clone();
        let writer = tokio::spawn(async move {
            for _ in 0..CHUNKS {
                wr.write_all(&expected_for_writer).await.unwrap();
            }
            wr.shutdown().await.unwrap();
        });
        let mut received = Vec::with_capacity(CHUNK * CHUNKS);
        let mut chunk_buf = vec![0; CHUNK];
        for _ in 0..CHUNKS {
            rd.read_exact(&mut chunk_buf).await.unwrap();
            assert_eq!(chunk_buf, expected, "large payload mismatch");
            received.extend_from_slice(&chunk_buf);
        }
        assert_eq!(received.len(), CHUNK * CHUNKS);
        writer.await.unwrap();
    }
}
