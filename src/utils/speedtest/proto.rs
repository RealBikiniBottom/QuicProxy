//! Wire protocol for the built-in speed test.
//!
//! The client opens a proxied TCP stream to [`SPEEDTEST_DOMAIN`]:[`TCP_PORT`]
//! through the node under test. A quicproxy server routes that domain to its
//! `speedtest` outbound, which answers in-process: the bytes never leave the
//! server, so only the client → node path is measured. The proxy tunnel is
//! already encrypted, so the protocol is plain binary.
//!
//! ```text
//! handshake  C→S  "QPST" ver(u8)          S→C  "QPST" ver(u8)
//! download   C→S  0x01 len(u64 BE)        S→C  len bytes
//! upload     C→S  0x02 len(u64 BE) data   S→C  received(u64 BE)
//! ping       C→S  0x03 seq(u64 BE)        S→C  0x03 seq(u64 BE)
//! upload v2  C→S  0x04 len(u64 BE) data   S→C  received-so-far(u64 BE)…
//! ```
//!
//! Each side sends its own version and uses the lower of the two. Version 2
//! adds `0x04`: while receiving, the server reports the bytes received so far
//! every [`PROGRESS_INTERVAL`] or [`PROGRESS_BYTES`], ending with a report
//! equal to `len`. The client counts upload throughput from these reports
//! (bytes the server has really received) instead of bytes it has written,
//! so it must read them while it writes. A version 1 server ignores the
//! client's version and only knows `0x02`.
//!
//! UDP: datagrams sent to [`SPEEDTEST_DOMAIN`]:[`UDP_PORT`] are echoed back
//! unchanged.

use std::io;

use bytes::Bytes;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub const SPEEDTEST_DOMAIN: &str = "speedtest.quicproxy.internal";
pub const TCP_PORT: u16 = 1;
pub const UDP_PORT: u16 = 2;

pub const MAGIC: &[u8; 4] = b"QPST";
pub const VERSION: u8 = 2;
/// First version with [`CMD_UPLOAD_ACKED`].
pub const VERSION_UPLOAD_ACKED: u8 = 2;

pub const CMD_DOWNLOAD: u8 = 0x01;
pub const CMD_UPLOAD: u8 = 0x02;
pub const CMD_PING: u8 = 0x03;
pub const CMD_UPLOAD_ACKED: u8 = 0x04;

/// Upload progress reports are sent at least this often while data arrives…
pub const PROGRESS_INTERVAL: std::time::Duration = std::time::Duration::from_millis(100);
/// …and after at most this many bytes.
pub const PROGRESS_BYTES: u64 = 256 * 1024;

/// Largest single download/upload a server accepts, so one request can't be
/// used to make the server push unbounded traffic.
pub const MAX_TRANSFER: u64 = 1 << 30;

/// Size of the reusable payload block written for downloads and uploads.
pub const CHUNK: usize = 64 * 1024;

/// Largest UDP echo datagram the server accepts.
pub const MAX_UDP_PAYLOAD: usize = 1400;

pub fn payload_chunk() -> Bytes {
    static CHUNK_BYTES: std::sync::LazyLock<Bytes> =
        std::sync::LazyLock::new(|| Bytes::from(vec![0u8; CHUNK]));
    CHUNK_BYTES.clone()
}

/// Returns the protocol version both sides speak.
pub async fn client_handshake<S: AsyncRead + AsyncWrite + Unpin>(s: &mut S) -> io::Result<u8> {
    let mut hello = [0u8; 5];
    hello[..4].copy_from_slice(MAGIC);
    hello[4] = VERSION;
    s.write_all(&hello).await?;
    s.flush().await?;
    let mut reply = [0u8; 5];
    s.read_exact(&mut reply).await?;
    if &reply[..4] != MAGIC {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "node does not support built-in speed test",
        ));
    }
    Ok(reply[4].clamp(1, VERSION))
}

/// Writes `len` payload bytes.
pub async fn write_payload<S: AsyncWrite + Unpin>(s: &mut S, mut len: u64) -> io::Result<()> {
    let chunk = payload_chunk();
    while len > 0 {
        let n = (len as usize).min(CHUNK);
        s.write_all(&chunk[..n]).await?;
        len -= n as u64;
    }
    s.flush().await
}

/// Reads and discards exactly `len` bytes.
pub async fn discard<S: AsyncRead + Unpin>(s: &mut S, mut len: u64) -> io::Result<u64> {
    let mut buf = vec![0u8; CHUNK];
    let mut total = 0u64;
    while len > 0 {
        let want = (len as usize).min(buf.len());
        let n = s.read(&mut buf[..want]).await?;
        if n == 0 {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        len -= n as u64;
        total += n as u64;
    }
    Ok(total)
}

/// Reads and discards exactly `len` bytes, writing the running total after
/// every [`PROGRESS_INTERVAL`] or [`PROGRESS_BYTES`] and once more at the end.
pub async fn discard_reporting<S: AsyncRead + AsyncWrite + Unpin>(
    s: &mut S,
    mut len: u64,
) -> io::Result<u64> {
    let mut buf = vec![0u8; CHUNK];
    let mut total = 0u64;
    let mut reported = 0u64;
    let mut last = tokio::time::Instant::now();
    while len > 0 {
        let want = (len as usize).min(buf.len());
        let n = s.read(&mut buf[..want]).await?;
        if n == 0 {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        len -= n as u64;
        total += n as u64;
        if len == 0 || total - reported >= PROGRESS_BYTES || last.elapsed() >= PROGRESS_INTERVAL {
            s.write_u64(total).await?;
            s.flush().await?;
            reported = total;
            last = tokio::time::Instant::now();
        }
    }
    Ok(total)
}

/// Serves one speed test stream until the client closes it.
pub async fn serve<S: AsyncRead + AsyncWrite + Unpin>(mut s: S) -> io::Result<()> {
    let mut hello = [0u8; 5];
    s.read_exact(&mut hello).await?;
    if &hello[..4] != MAGIC {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "bad speedtest magic",
        ));
    }
    let mut reply = [0u8; 5];
    reply[..4].copy_from_slice(MAGIC);
    reply[4] = VERSION;
    s.write_all(&reply).await?;
    s.flush().await?;

    loop {
        let mut cmd = [0u8; 1];
        match s.read_exact(&mut cmd).await {
            Ok(_) => {}
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(e) => return Err(e),
        }
        let arg = s.read_u64().await?;
        match cmd[0] {
            CMD_DOWNLOAD => write_payload(&mut s, arg.min(MAX_TRANSFER)).await?,
            CMD_UPLOAD => {
                if arg > MAX_TRANSFER {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "speedtest upload too large",
                    ));
                }
                let got = discard(&mut s, arg).await?;
                s.write_u64(got).await?;
                s.flush().await?;
            }
            CMD_UPLOAD_ACKED => {
                if arg > MAX_TRANSFER {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "speedtest upload too large",
                    ));
                }
                discard_reporting(&mut s, arg).await?;
            }
            CMD_PING => {
                let mut pong = [0u8; 9];
                pong[0] = CMD_PING;
                pong[1..].copy_from_slice(&arg.to_be_bytes());
                s.write_all(&pong).await?;
                s.flush().await?;
            }
            other => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("unknown speedtest command {other}"),
                ));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn round_trip_over_duplex() {
        let (mut client, server) = tokio::io::duplex(256 * 1024);
        let server = tokio::spawn(serve(server));

        assert_eq!(client_handshake(&mut client).await.unwrap(), VERSION);

        // download
        client.write_u8(CMD_DOWNLOAD).await.unwrap();
        client.write_u64(300_000).await.unwrap();
        assert_eq!(discard(&mut client, 300_000).await.unwrap(), 300_000);

        // upload
        client.write_u8(CMD_UPLOAD).await.unwrap();
        client.write_u64(200_000).await.unwrap();
        write_payload(&mut client, 200_000).await.unwrap();
        assert_eq!(client.read_u64().await.unwrap(), 200_000);

        // ping
        client.write_u8(CMD_PING).await.unwrap();
        client.write_u64(42).await.unwrap();
        assert_eq!(client.read_u8().await.unwrap(), CMD_PING);
        assert_eq!(client.read_u64().await.unwrap(), 42);

        drop(client);
        server.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn acked_upload_reports_progress() {
        let (client, server) = tokio::io::duplex(64 * 1024);
        let server = tokio::spawn(serve(server));
        let (mut rd, mut wr) = tokio::io::split(client);
        let mut hello = [0u8; 5];
        hello[..4].copy_from_slice(MAGIC);
        hello[4] = VERSION;
        wr.write_all(&hello).await.unwrap();
        let mut reply = [0u8; 5];
        rd.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply[4], VERSION);

        // Write and read concurrently, as the client does: the server's
        // reports would otherwise fill the pipe and stall both sides.
        let len = 3 * PROGRESS_BYTES + 1000;
        let writer = async {
            wr.write_u8(CMD_UPLOAD_ACKED).await.unwrap();
            wr.write_u64(len).await.unwrap();
            write_payload(&mut wr, len).await.unwrap();
        };
        let reader = async {
            let mut reports = Vec::new();
            loop {
                let v = rd.read_u64().await.unwrap();
                reports.push(v);
                if v == len {
                    return reports;
                }
            }
        };
        let ((), reports) = tokio::join!(writer, reader);
        // One report per PROGRESS_BYTES (reads need not align with it), then
        // the final total.
        assert!(reports.len() >= 3, "{reports:?}");
        assert!(reports.windows(2).all(|w| w[0] < w[1]), "{reports:?}");
        assert!(
            reports
                .windows(2)
                .all(|w| w[1] - w[0] <= PROGRESS_BYTES + CHUNK as u64)
        );

        drop((rd, wr));
        server.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn v1_server_negotiates_down() {
        let (mut client, mut server) = tokio::io::duplex(1024);
        tokio::spawn(async move {
            let mut hello = [0u8; 5];
            server.read_exact(&mut hello).await.unwrap();
            assert_eq!(hello[4], VERSION);
            let mut reply = *b"QPST\x01";
            reply[4] = 1;
            server.write_all(&reply).await.unwrap();
        });
        assert_eq!(client_handshake(&mut client).await.unwrap(), 1);
    }

    #[tokio::test]
    async fn rejects_non_speedtest_peer() {
        let (mut client, mut server) = tokio::io::duplex(1024);
        tokio::spawn(async move {
            let mut buf = [0u8; 5];
            let _ = server.read_exact(&mut buf).await;
            let _ = server.write_all(b"HTTP/").await;
        });
        let err = client_handshake(&mut client).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }
}
