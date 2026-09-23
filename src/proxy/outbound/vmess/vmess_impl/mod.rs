mod cipher;
mod client;
mod datagram;
mod header;
mod kdf;
mod stream;
mod user;

pub(crate) use cipher::{AeadCipher, AeadCipherHelper, VmessSecurity};
pub(crate) use kdf::{
    KDF_SALT_CONST_AEAD_RESP_HEADER_LEN_IV, KDF_SALT_CONST_AEAD_RESP_HEADER_LEN_KEY,
    KDF_SALT_CONST_AEAD_RESP_HEADER_PAYLOAD_IV, KDF_SALT_CONST_AEAD_RESP_HEADER_PAYLOAD_KEY,
    KDF_SALT_CONST_VMESS_HEADER_PAYLOAD_AEAD_IV,
    KDF_SALT_CONST_VMESS_HEADER_PAYLOAD_AEAD_KEY,
    KDF_SALT_CONST_VMESS_HEADER_PAYLOAD_LENGTH_AEAD_IV,
    KDF_SALT_CONST_VMESS_HEADER_PAYLOAD_LENGTH_AEAD_KEY, vmess_kdf_1_one_shot,
    vmess_kdf_3_one_shot,
};
pub(crate) use user::{new_id, ID};

pub(crate) const VERSION: u8 = 1;

pub(crate) const OPTION_CHUNK_STREAM: u8 = 1;

type Security = u8;

pub(crate) const SECURITY_AES_128_GCM: Security = 3;
pub(crate) const SECURITY_CHACHA20_POLY1305: Security = 4;
pub(crate) const SECURITY_NONE: Security = 5;

pub(crate) const COMMAND_TCP: u8 = 1;
pub(crate) const COMMAND_UDP: u8 = 2;

pub(crate) const CHUNK_SIZE: usize = 1 << 14;
pub(crate) const MAX_CHUNK_SIZE: usize = 17 * 1024;

pub use client::{Builder, VmessOption};
pub use datagram::OutboundDatagramVmess;

use crate::proxy::TargetAddr;
use bytes::BufMut;

impl TargetAddr {
    pub(crate) fn write_to_buf_vmess<B: BufMut>(&self, buf: &mut B) {
        match self {
            Self::Ip(std::net::SocketAddr::V4(addr)) => {
                buf.put_u16(addr.port());
                buf.put_u8(0x01);
                buf.put_slice(&addr.ip().octets());
            }
            Self::Ip(std::net::SocketAddr::V6(addr)) => {
                buf.put_u16(addr.port());
                buf.put_u8(0x03);
                for seg in &addr.ip().segments() {
                    buf.put_u16(*seg);
                }
            }
            Self::Domain(domain_name, port) => {
                buf.put_u16(*port);
                buf.put_u8(0x02);
                buf.put_u8(domain_name.len() as u8);
                buf.put_slice(domain_name.as_bytes());
            }
        }
    }
}
