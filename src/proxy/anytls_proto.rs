use crate::proxy::TargetAddr;
use anyhow::{Context as _, Result, bail};
use bytes::{Buf, Bytes, BytesMut};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

// ─── Shared Anytls Protocol Constants ─────────────────────────────────────────

/// Protocol version supported by this implementation
pub const PROTOCOL_VERSION: u8 = 2;

/// Agent name used in cmdSettings / cmdServerSettings handshake
pub const AGENT_NAME: &str = "quicproxy/0.1.0";

// ─── Frame layout ─────────────────────────────────────────────────────────────

pub const FRAME_HEADER_SIZE: usize = 7; // cmd(1) + streamId(4) + dataLen(2)
pub const AUTH_HASH_SIZE: usize = 32; // SHA-256 output
pub const AUTH_LENGTH_FIELD_SIZE: usize = 2; // BE u16

/// Bounds queued encrypted writes and per-stream reads. These queues are kept
/// deliberately small because a frame can carry up to 64 KiB.
pub const SESSION_QUEUE_CAPACITY: usize = 64;
pub const STREAM_QUEUE_CAPACITY: usize = 16;

/// UDP-over-TCP target domain
pub const UDP_OVER_TCP_TARGET: &str = "sp.v2.udp-over-tcp.arpa";

// ─── UoT Helpers ──────────────────────────────────────────────────────────────

/// Encode TargetAddr in UoT data-packet AddrParser format (ATYP: 0x00=IPv4, 0x01=IPv6, 0x02=Domain).
/// Note: UoT Request uses Socksaddr format (ATYP 1/3/4) — see `socksaddr_encode_target`.
pub fn uot_encode_target(target: &TargetAddr) -> Vec<u8> {
    let mut buf = Vec::new();
    match target {
        TargetAddr::Ip(std::net::SocketAddr::V4(addr)) => {
            buf.push(0x00);
            buf.extend_from_slice(&addr.ip().octets());
            buf.extend_from_slice(&addr.port().to_be_bytes());
        }
        TargetAddr::Ip(std::net::SocketAddr::V6(addr)) => {
            buf.push(0x01);
            buf.extend_from_slice(&addr.ip().octets());
            buf.extend_from_slice(&addr.port().to_be_bytes());
        }
        TargetAddr::Domain(domain, port) => {
            buf.push(0x02);
            buf.push(domain.len() as u8);
            buf.extend_from_slice(domain.as_bytes());
            buf.extend_from_slice(&port.to_be_bytes());
        }
    }
    buf
}

/// Decode TargetAddr from UoT data-packet AddrParser format (ATYP: 0x00=IPv4, 0x01=IPv6, 0x02=Domain).
pub fn uot_decode_target(data: &[u8]) -> Result<(TargetAddr, usize)> {
    if data.is_empty() {
        bail!("empty UoT packet");
    }
    match data[0] {
        0x00 => {
            // IPv4
            if data.len() < 7 {
                bail!("UoT IPv4 address too short");
            }
            let mut ip = [0u8; 4];
            ip.copy_from_slice(&data[1..5]);
            let port = u16::from_be_bytes([data[5], data[6]]);
            Ok((
                TargetAddr::Ip(std::net::SocketAddr::V4(std::net::SocketAddrV4::new(
                    std::net::Ipv4Addr::from(ip),
                    port,
                ))),
                7,
            ))
        }
        0x01 => {
            // IPv6
            if data.len() < 19 {
                bail!("UoT IPv6 address too short");
            }
            let mut ip = [0u8; 16];
            ip.copy_from_slice(&data[1..17]);
            let port = u16::from_be_bytes([data[17], data[18]]);
            Ok((
                TargetAddr::Ip(std::net::SocketAddr::V6(std::net::SocketAddrV6::new(
                    std::net::Ipv6Addr::from(ip),
                    port,
                    0,
                    0,
                ))),
                19,
            ))
        }
        0x02 => {
            // Domain
            if data.len() < 2 {
                bail!("UoT domain address too short");
            }
            let domain_len = data[1] as usize;
            if data.len() < 2 + domain_len + 2 {
                bail!("UoT domain address too short for domain length");
            }
            let domain = String::from_utf8_lossy(&data[2..2 + domain_len]).to_string();
            let port = u16::from_be_bytes([data[2 + domain_len], data[2 + domain_len + 1]]);
            Ok((TargetAddr::Domain(domain, port), 2 + domain_len + 2))
        }
        _ => bail!("unknown UoT address type: {}", data[0]),
    }
}

/// Encode TargetAddr in Socksaddr format (ATYP: 1=IPv4, 3=Domain, 4=IPv6).
/// Used for UoT Request destination encoding.
pub fn socksaddr_encode_target(target: &TargetAddr) -> Vec<u8> {
    let mut buf = Vec::new();
    match target {
        TargetAddr::Ip(std::net::SocketAddr::V4(addr)) => {
            buf.push(1u8);
            buf.extend_from_slice(&addr.ip().octets());
            buf.extend_from_slice(&addr.port().to_be_bytes());
        }
        TargetAddr::Ip(std::net::SocketAddr::V6(addr)) => {
            buf.push(4u8);
            buf.extend_from_slice(&addr.ip().octets());
            buf.extend_from_slice(&addr.port().to_be_bytes());
        }
        TargetAddr::Domain(domain, port) => {
            buf.push(3u8);
            buf.push(domain.len() as u8);
            buf.extend_from_slice(domain.as_bytes());
            buf.extend_from_slice(&port.to_be_bytes());
        }
    }
    buf
}

/// Decode TargetAddr from Socksaddr format (ATYP: 1=IPv4, 3=Domain, 4=IPv6).
/// Used for UoT Request destination parsing.
pub fn socksaddr_decode_target(data: &[u8]) -> Result<(TargetAddr, usize)> {
    if data.is_empty() {
        bail!("empty socksaddr");
    }
    match data[0] {
        1 => {
            // IPv4
            if data.len() < 7 {
                bail!("socksaddr IPv4 address too short");
            }
            let mut ip = [0u8; 4];
            ip.copy_from_slice(&data[1..5]);
            let port = u16::from_be_bytes([data[5], data[6]]);
            Ok((
                TargetAddr::Ip(std::net::SocketAddr::V4(std::net::SocketAddrV4::new(
                    std::net::Ipv4Addr::from(ip),
                    port,
                ))),
                7,
            ))
        }
        4 => {
            // IPv6
            if data.len() < 19 {
                bail!("socksaddr IPv6 address too short");
            }
            let mut ip = [0u8; 16];
            ip.copy_from_slice(&data[1..17]);
            let port = u16::from_be_bytes([data[17], data[18]]);
            Ok((
                TargetAddr::Ip(std::net::SocketAddr::V6(std::net::SocketAddrV6::new(
                    std::net::Ipv6Addr::from(ip),
                    port,
                    0,
                    0,
                ))),
                19,
            ))
        }
        3 => {
            // Domain
            if data.len() < 2 {
                bail!("socksaddr domain address too short");
            }
            let domain_len = data[1] as usize;
            if data.len() < 2 + domain_len + 2 {
                bail!("socksaddr domain address too short for domain length");
            }
            let domain = String::from_utf8_lossy(&data[2..2 + domain_len]).to_string();
            let port = u16::from_be_bytes([data[2 + domain_len], data[2 + domain_len + 1]]);
            Ok((TargetAddr::Domain(domain, port), 2 + domain_len + 2))
        }
        _ => bail!("unknown socksaddr address type: {}", data[0]),
    }
}

// ─── Frame Commands ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Command {
    Waste = 0,
    Syn = 1,
    Psh = 2,
    Fin = 3,
    Settings = 4,
    Alert = 5,
    UpdatePaddingScheme = 6,
    SynAck = 7,
    HeartRequest = 8,
    HeartResponse = 9,
    ServerSettings = 10,
}

impl From<Command> for u8 {
    fn from(cmd: Command) -> u8 {
        cmd as u8
    }
}

impl TryFrom<u8> for Command {
    type Error = anyhow::Error;

    fn try_from(v: u8) -> Result<Self> {
        Ok(match v {
            0 => Command::Waste,
            1 => Command::Syn,
            2 => Command::Psh,
            3 => Command::Fin,
            4 => Command::Settings,
            5 => Command::Alert,
            6 => Command::UpdatePaddingScheme,
            7 => Command::SynAck,
            8 => Command::HeartRequest,
            9 => Command::HeartResponse,
            10 => Command::ServerSettings,
            _ => bail!("unknown anytls command: {}", v),
        })
    }
}

/// A frame queued between a multiplexed stream and its TLS session.
pub type Frame = (u32, Command, Bytes);

pub async fn read_frame<S: AsyncRead + Unpin>(stream: &mut S) -> Result<(Command, u32, Bytes)> {
    let cmd = Command::try_from(stream.read_u8().await.context("read frame command")?)?;
    let stream_id = stream.read_u32().await.context("read frame stream id")?;
    let data_len = stream.read_u16().await.context("read frame data length")? as usize;
    let mut data = vec![0; data_len];
    if data_len != 0 {
        stream
            .read_exact(&mut data)
            .await
            .context("read frame payload")?;
    }
    Ok((cmd, stream_id, Bytes::from(data)))
}

pub fn build_frame(cmd: Command, stream_id: u32, data: &[u8]) -> Result<Vec<u8>> {
    let data_len = u16::try_from(data.len()).context("anytls frame payload exceeds 65535 bytes")?;
    let mut frame = Vec::with_capacity(FRAME_HEADER_SIZE + data.len());
    frame.push(cmd.into());
    frame.extend_from_slice(&stream_id.to_be_bytes());
    frame.extend_from_slice(&data_len.to_be_bytes());
    frame.extend_from_slice(data);
    Ok(frame)
}

pub async fn write_frame<S: AsyncWrite + Unpin>(
    stream: &mut S,
    stream_id: u32,
    cmd: Command,
    data: &[u8],
) -> Result<()> {
    stream
        .write_all(&build_frame(cmd, stream_id, data)?)
        .await?;
    stream.flush().await?;
    Ok(())
}

/// Retains an unread frame tail without copying or keeping a grow-only `Vec`.
#[derive(Default)]
pub struct StreamReadBuffer {
    pending: Bytes,
}

impl StreamReadBuffer {
    pub fn copy_to(&mut self, dst: &mut ReadBuf<'_>) -> bool {
        if self.pending.is_empty() {
            return false;
        }
        if dst.remaining() == 0 {
            return true;
        }
        let len = self.pending.len().min(dst.remaining());
        dst.put_slice(&self.pending[..len]);
        self.pending.advance(len);
        true
    }

    pub fn copy_from(&mut self, data: Bytes, dst: &mut ReadBuf<'_>) {
        debug_assert!(self.pending.is_empty());
        self.pending = data;
        self.copy_to(dst);
    }
}

/// Incremental UoT packet decoder shared by inbound and outbound.
#[derive(Default)]
pub struct UotReadBuffer {
    data: BytesMut,
}

impl UotReadBuffer {
    pub fn push(&mut self, data: &[u8]) {
        self.data.extend_from_slice(data);
    }

    pub fn next_packet(&mut self, is_connect: bool) -> Result<Option<Bytes>> {
        let header_len = if is_connect {
            if self.data.len() < 2 {
                return Ok(None);
            }
            0
        } else {
            match uot_target_len(&self.data)? {
                Some(len) => len,
                None => return Ok(None),
            }
        };
        if self.data.len() < header_len + 2 {
            return Ok(None);
        }
        let payload_len =
            u16::from_be_bytes([self.data[header_len], self.data[header_len + 1]]) as usize;
        let packet_len = header_len + 2 + payload_len;
        if self.data.len() < packet_len {
            return Ok(None);
        }
        let packet = self.data.split_to(packet_len).freeze();
        if self.data.is_empty() {
            self.data = BytesMut::new();
        }
        Ok(Some(packet))
    }
}

fn uot_target_len(data: &[u8]) -> Result<Option<usize>> {
    let required = match data.first().copied() {
        None => return Ok(None),
        Some(0x00) => 7,
        Some(0x01) => 19,
        Some(0x02) => match data.get(1) {
            Some(domain_len) => 4 + *domain_len as usize,
            None => return Ok(None),
        },
        Some(atyp) => bail!("unknown UoT address type: {}", atyp),
    };
    Ok((data.len() >= required).then_some(required))
}

pub fn encode_uot_packet(payload: &[u8], target: Option<&TargetAddr>) -> Result<Bytes> {
    let payload_len = u16::try_from(payload.len()).context("UoT payload exceeds 65535 bytes")?;
    let target = target.map(uot_encode_target).unwrap_or_default();
    let mut packet = Vec::with_capacity(target.len() + 2 + payload.len());
    packet.extend_from_slice(&target);
    packet.extend_from_slice(&payload_len.to_be_bytes());
    packet.extend_from_slice(payload);
    Ok(Bytes::from(packet))
}

pub fn decode_uot_packet(data: Bytes, is_connect: bool) -> Result<(Option<TargetAddr>, Bytes)> {
    let (target, header_len) = if is_connect {
        (None, 0)
    } else {
        let (target, len) = uot_decode_target(&data)?;
        (Some(target), len)
    };
    if data.len() < header_len + 2 {
        bail!("UoT packet too short for length");
    }
    let payload_len = u16::from_be_bytes([data[header_len], data[header_len + 1]]) as usize;
    let payload_start = header_len + 2;
    if data.len() < payload_start + payload_len {
        bail!("UoT packet too short for payload");
    }
    Ok((
        target,
        data.slice(payload_start..payload_start + payload_len),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_unknown_command_without_panicking() {
        assert!(Command::try_from(255).is_err());
    }

    #[test]
    fn stream_read_buffer_preserves_frame_tail() {
        let mut pending = StreamReadBuffer::default();
        let mut first = [0; 3];
        pending.copy_from(Bytes::from_static(b"abcdef"), &mut ReadBuf::new(&mut first));
        assert_eq!(&first, b"abc");

        let mut second = [0; 3];
        assert!(pending.copy_to(&mut ReadBuf::new(&mut second)));
        assert_eq!(&second, b"def");
    }

    #[test]
    fn uot_decoder_handles_fragmented_long_domain() {
        let target = TargetAddr::Domain("a".repeat(255), 53);
        let packet = encode_uot_packet(b"dns", Some(&target)).unwrap();
        let mut decoder = UotReadBuffer::default();
        decoder.push(&packet[..257]);
        assert!(decoder.next_packet(false).unwrap().is_none());
        decoder.push(&packet[257..]);

        let decoded = decoder.next_packet(false).unwrap().unwrap();
        let (decoded_target, payload) = decode_uot_packet(decoded, false).unwrap();
        assert_eq!(decoded_target, Some(target));
        assert_eq!(payload.as_ref(), b"dns");
    }
}
