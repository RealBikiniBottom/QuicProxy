use crate::proxy::TargetAddr;
use anyhow::{Result, bail};

// ─── Shared Anytls Protocol Constants ─────────────────────────────────────────

/// Protocol version supported by this implementation
pub const PROTOCOL_VERSION: u8 = 2;

/// Agent name used in cmdSettings / cmdServerSettings handshake
pub const AGENT_NAME: &str = "quicproxy/0.1.0";

// ─── Frame layout ─────────────────────────────────────────────────────────────

pub const FRAME_HEADER_SIZE: usize = 7; // cmd(1) + streamId(4) + dataLen(2)
pub const AUTH_HASH_SIZE: usize = 32; // SHA-256 output
pub const AUTH_LENGTH_FIELD_SIZE: usize = 2; // BE u16

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

impl From<u8> for Command {
    fn from(v: u8) -> Command {
        match v {
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
            _ => panic!("unknown anytls command: {}", v),
        }
    }
}
