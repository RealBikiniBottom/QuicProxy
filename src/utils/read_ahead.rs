//! Buffered reads for framed protocols.
//!
//! Instead of several small `read_exact` calls per frame (each one a full trip through
//! TLS or QUIC) plus a zeroed allocation for the payload, a reader keeps one `BytesMut`,
//! fills it with whatever the stream has ready, and cuts complete frames out of it with
//! `split_to`, which does not copy. Nothing is consumed until a whole frame is buffered,
//! so a read that is cancelled midway loses no bytes.

use bytes::BytesMut;
use std::future::poll_fn;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll, ready};
use tokio::io::{AsyncRead, ReadBuf};

/// How much free space to offer the stream on each read. One TLS record holds at most
/// 16KB of plaintext, so this usually takes a whole record, or several frames, at once.
pub const READ_AHEAD: usize = 16 * 1024;

/// Polls until `buf` holds at least `count` bytes.
///
/// Returns `Ok(false)` when the stream ends while `buf` is empty and `allow_eof` is set,
/// i.e. a clean close between frames. Any other EOF is `UnexpectedEof`.
pub fn poll_fill<S: AsyncRead + Unpin + ?Sized>(
    stream: &mut S,
    cx: &mut Context<'_>,
    buf: &mut BytesMut,
    count: usize,
    allow_eof: bool,
) -> Poll<io::Result<bool>> {
    while buf.len() < count {
        buf.reserve(READ_AHEAD.max(count - buf.len()));
        let n = {
            let mut read_buf = ReadBuf::uninit(buf.spare_capacity_mut());
            ready!(Pin::new(&mut *stream).poll_read(cx, &mut read_buf))?;
            read_buf.filled().len()
        };
        if n == 0 {
            if allow_eof && buf.is_empty() {
                return Poll::Ready(Ok(false));
            }
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "unexpected EOF in the middle of a frame",
            )));
        }
        // SAFETY: `poll_read` initialised the first `n` bytes of the spare capacity.
        unsafe { buf.set_len(buf.len() + n) };
    }
    Poll::Ready(Ok(true))
}

/// Async form of [`poll_fill`].
pub async fn fill<S: AsyncRead + Unpin + ?Sized>(
    stream: &mut S,
    buf: &mut BytesMut,
    count: usize,
    allow_eof: bool,
) -> io::Result<bool> {
    poll_fn(|cx| poll_fill(stream, cx, buf, count, allow_eof)).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;

    #[tokio::test]
    async fn fill_reads_ahead_and_keeps_partial_frames() {
        let (mut client, mut server) = tokio::io::duplex(64);
        client.write_all(b"abcdefgh").await.unwrap();
        let mut buf = BytesMut::new();

        assert!(fill(&mut server, &mut buf, 3, false).await.unwrap());
        // Read ahead past the 3 bytes asked for.
        assert_eq!(&buf[..], b"abcdefgh");
        let _ = buf.split_to(3);

        client.write_all(b"ij").await.unwrap();
        drop(client);
        assert!(fill(&mut server, &mut buf, 7, false).await.unwrap());
        assert_eq!(&buf[..], b"defghij");
        let _ = buf.split_to(7);

        // Clean EOF between frames.
        assert!(!fill(&mut server, &mut buf, 2, true).await.unwrap());
    }

    #[tokio::test]
    async fn eof_inside_a_frame_is_an_error() {
        let (mut client, mut server) = tokio::io::duplex(64);
        client.write_all(b"ab").await.unwrap();
        drop(client);
        let mut buf = BytesMut::new();
        let err = fill(&mut server, &mut buf, 4, true).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
        assert_eq!(&buf[..], b"ab");
    }
}
