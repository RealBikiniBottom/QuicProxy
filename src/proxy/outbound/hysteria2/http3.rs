//! Minimal HTTP/3 client used for the Hysteria2 authentication handshake.
//!
//! Full HTTP/3 (RFC 9114) support is far beyond what the handshake needs,
//! and no H3/QPACK crate is compatible with this project's quinn fork. The
//! wire format this module speaks is therefore implemented directly on top
//! of a raw QUIC connection, mirroring what quic-go's http3 client does for
//! the Hysteria2 auth exchange:
//!
//! 1. Open a unidirectional control stream (stream type 0x00) and send an
//!    empty SETTINGS frame.
//! 2. Open a bidirectional stream and send one HEADERS frame carrying the
//!    QPACK-encoded request field section, then finish the write side.
//! 3. Read frames until end of stream; the response HEADERS field section
//!    is QPACK-decoded and its `:status` checked.
//!
//! The server side of this exchange (quic-go's http3 package, used by
//! sing-box, mihomo and the official hysteria server alike) never uses the
//! dynamic table against a client that advertises zero
//! SETTINGS_QPACK_MAX_TABLE_CAPACITY, so the QPACK subset in `qpack` is
//! sufficient for both directions.

use crate::proxy::outbound::hysteria2::qpack;
use anyhow::{Context, Result, bail};
use std::time::Duration;
use tokio::io::AsyncReadExt;

/// The HTTP/3 status code a Hysteria2 server returns on auth success.
pub const STATUS_AUTH_OK: u16 = 233;
/// The stream type of the HTTP/3 control stream.
const STREAM_TYPE_CONTROL: u8 = 0x00;
/// The HTTP/3 frame type for SETTINGS.
const FRAME_SETTINGS: u64 = 0x04;
/// The HTTP/3 frame type for HEADERS.
const FRAME_HEADERS: u64 = 0x01;
/// The HTTP/3 frame type for DATA.

/// Upper bound on the response size read for one auth exchange. Legitimate
/// responses are a few hundred bytes; anything beyond a small HTML
/// masquerade page is treated as a failure to avoid unbounded reads.
const MAX_AUTH_RESPONSE_BYTES: usize = 64 * 1024;

/// Result of a successful HTTP/3 auth exchange.
#[derive(Debug, Clone)]
pub(crate) struct AuthResult {
    pub status: u16,
    pub udp_enabled: bool,
}

/// The client's HTTP/3 control stream. Kept alive (by the connection
/// state) for the whole QUIC connection: closing it early is an HTTP/3
/// protocol violation.
pub(crate) struct H3Control {
    _settings_stream: quinn::SendStream,
}

impl H3Control {
    /// Open the unidirectional control stream and send an empty SETTINGS
    /// frame (RFC 9114 section 6.2.1).
    pub(crate) async fn open(conn: &quinn::Connection) -> Result<Self> {
        let mut settings = conn
            .open_uni()
            .await
            .context("failed to open HTTP/3 control stream")?;
        settings
            .write_all(&[STREAM_TYPE_CONTROL, FRAME_SETTINGS as u8, 0x00])
            .await
            .context("failed to write HTTP/3 SETTINGS")?;
        Ok(Self {
            _settings_stream: settings,
        })
    }
}

/// Append a QUIC varint (RFC 9000) to `out`.
fn append_varint(out: &mut Vec<u8>, value: u64) {
    match value {
        0..=63 => out.push(value as u8),
        64..=16383 => {
            out.push(0x40 | ((value >> 8) as u8));
            out.push(value as u8);
        }
        16384..=1_073_741_823 => {
            out.push(0x80 | ((value >> 24) as u8));
            out.push((value >> 16) as u8);
            out.push((value >> 8) as u8);
            out.push(value as u8);
        }
        _ => {
            out.push(0xc0 | ((value >> 56) as u8));
            out.push((value >> 48) as u8);
            out.push((value >> 40) as u8);
            out.push((value >> 32) as u8);
            out.push((value >> 24) as u8);
            out.push((value >> 16) as u8);
            out.push((value >> 8) as u8);
            out.push(value as u8);
        }
    }
}

/// Read a QUIC varint (RFC 9000 section 16) from `reader`, bounded by
/// `budget`.
async fn read_varint<R: AsyncReadExt + Unpin>(reader: &mut R, budget: &mut usize) -> Result<u64> {
    let first = reader.read_u8().await.context("failed to read varint")?;
    *budget = budget.saturating_sub(1);
    let len = 1usize << (first >> 6);
    let mut buf = [0u8; 7];
    let tail = len - 1;
    if tail > 0 {
        *budget = budget.saturating_sub(tail);
        reader
            .read_exact(&mut buf[..tail])
            .await
            .context("failed to read varint")?;
    }
    let mut value = (first & 0x3f) as u64;
    for b in &buf[..tail] {
        value = (value << 8) | *b as u64;
    }
    Ok(value)
}

/// Parse a QUIC varint (RFC 9000 section 16) from a byte slice; returns
/// the value and the number of bytes consumed.
#[cfg(test)]
fn parse_varint(bytes: &[u8]) -> Result<(u64, usize)> {
    let first = *bytes.first().context("empty varint")?;
    let len = 1usize << (first >> 6);
    if bytes.len() < len {
        bail!("truncated varint");
    }
    let mut value = (first & 0x3f) as u64;
    for b in &bytes[1..len] {
        value = (value << 8) | *b as u64;
    }
    Ok((value, len))
}

/// Build the Hysteria2 auth request: a HEADERS frame whose QPACK field
/// section describes the auth POST.
pub(crate) fn build_auth_request(password: &str, padding: &str) -> Vec<u8> {
    let fields = [
        (":method", "POST"),
        (":scheme", "https"),
        (":path", "/auth"),
        (":authority", "hysteria"),
        ("hysteria-auth", password),
        ("hysteria-cc-rx", "0"),
        ("hysteria-padding", padding),
    ];
    let payload = qpack::encode_field_section(&fields);
    let mut frame = Vec::with_capacity(2 + 2 + payload.len());
    append_varint(&mut frame, FRAME_HEADERS);
    append_varint(&mut frame, payload.len() as u64);
    frame.extend_from_slice(&payload);
    frame
}

/// Perform the Hysteria2 HTTP/3 auth handshake on `conn`.
///
/// Sends the control-stream SETTINGS and the auth POST, then reads the
/// response and checks the status code. `H3Control` must be retained by
/// the caller until the QUIC connection is closed.
pub(crate) async fn authenticate(
    conn: &quinn::Connection,
    password: &str,
    timeout: Duration,
) -> Result<(AuthResult, H3Control)> {
    let control = H3Control::open(conn).await?;

    let (mut send, mut recv) = tokio::time::timeout(timeout, conn.open_bi())
        .await
        .context("open auth stream timed out")?
        .context("failed to open auth stream")?;

    let padding = random_padding();
    let request = build_auth_request(password, &padding);
    tokio::time::timeout(timeout, send.write_all(&request))
        .await
        .context("auth request write timed out")?
        .context("failed to write auth request")?;
    let _ = send.finish();

    let mut budget = MAX_AUTH_RESPONSE_BYTES;
    let mut status: Option<u16> = None;
    let mut udp_enabled = false;

    loop {
        if budget == 0 {
            bail!("auth response too large");
        }
        let frame_type = read_varint(&mut recv, &mut budget).await?;
        let frame_len = read_varint(&mut recv, &mut budget).await?;
        if frame_len > budget as u64 {
            bail!("auth response frame too large");
        }
        let mut payload = vec![0u8; frame_len as usize];
        tokio::time::timeout(timeout, recv.read_exact(&mut payload))
            .await
            .context("auth response read timed out")?
            .context("failed to read auth response")?;
        budget -= frame_len as usize;

        if frame_type == FRAME_HEADERS {
            let fields = qpack::decode_field_section(&payload)
                .context("failed to decode auth response headers")?;
            for (name, value) in fields {
                if name == ":status" {
                    status = Some(value.parse().context("invalid :status value")?);
                } else if name.eq_ignore_ascii_case("hysteria-udp") {
                    udp_enabled = value == "true";
                }
            }
            if status.is_some() {
                break;
            }
        }
        // A 233 response has an empty body, so the first (and only)
        // HEADERS frame carries the status. If we saw headers without a
        // status the server served a masquerade page: bail out instead of
        // reading a potentially unbounded body.
        if status.is_none() {
            bail!("auth response has no :status (masqueraded)");
        }
    }

    let status = status.context("auth response missing :status")?;
    Ok((
        AuthResult {
            status,
            udp_enabled,
        },
        control,
    ))
}

/// A short unpredictable ASCII string for the `Hysteria-Padding` header.
fn random_padding() -> String {
    use rand::RngExt;
    let mut rng = rand::rng();
    (0..16)
        .map(|_| rng.random_range(b'a'..=b'z') as char)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn varint_roundtrip() {
        for value in [
            0u64,
            1,
            63,
            64,
            16383,
            16384,
            1_073_741_823,
            1_073_741_824,
            4_611_686_018_427_387_903, // 2^62 - 1, the max varint value
        ] {
            let mut buf = Vec::new();
            append_varint(&mut buf, value);
            let (parsed, used) = parse_varint(&buf).unwrap();
            assert_eq!(parsed, value);
            assert_eq!(used, buf.len());
        }
    }

    #[test]
    fn auth_request_starts_with_headers_frame() {
        let req = build_auth_request("pw", "pad");
        let (frame_type, used) = parse_varint(&req).unwrap();
        assert_eq!(frame_type, FRAME_HEADERS);
        let (payload_len, header_len) = parse_varint(&req[used..]).unwrap();
        assert_eq!(payload_len as usize + used + header_len, req.len());
    }

    #[test]
    fn auth_request_is_decodable() {
        let req = build_auth_request("s3cret", "padding-xyz");
        let (_, used) = parse_varint(&req).unwrap();
        let (payload_len, header_len) = parse_varint(&req[used..]).unwrap();
        let payload = &req[used + header_len..used + header_len + payload_len as usize];
        let fields = qpack::decode_field_section(payload).unwrap();
        let map: std::collections::HashMap<&str, &str> = fields
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        assert_eq!(map.get(":method").copied(), Some("POST"));
        assert_eq!(map.get(":path").copied(), Some("/auth"));
        assert_eq!(map.get(":authority").copied(), Some("hysteria"));
        assert_eq!(map.get("hysteria-auth").copied(), Some("s3cret"));
    }
}
