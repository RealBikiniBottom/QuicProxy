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
//! ```
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
pub const VERSION: u8 = 1;

pub const CMD_DOWNLOAD: u8 = 0x01;
pub const CMD_UPLOAD: u8 = 0x02;
pub const CMD_PING: u8 = 0x03;

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

pub async fn client_handshake<S: AsyncRead + AsyncWrite + Unpin>(s: &mut S) -> io::Result<()> {
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
    Ok(())
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

        client_handshake(&mut client).await.unwrap();

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
