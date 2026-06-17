use std::io;

use crate::proxy::TargetAddr;
use crate::proxy::outbound::vmess::vmess_impl::stream;
use crate::proxy::outbound::vmess::vmess_impl::user::{self, new_alter_id_list};
use crate::proxy::outbound::vmess::vmess_impl::{
    SECURITY_AES_128_GCM, SECURITY_CHACHA20_POLY1305, SECURITY_NONE,
};

#[derive(Clone)]
pub struct VmessOption {
    pub uuid: String,
    pub alter_id: u16,
    pub security: String,
    pub udp: bool,
    pub dst: TargetAddr,
}

pub struct Builder {
    pub user: Vec<user::ID>,
    pub security: u8,
    pub is_aead: bool,
    pub is_udp: bool,
    pub dst: TargetAddr,
}

impl Builder {
    pub fn new(opt: &VmessOption) -> io::Result<Self> {
        let uuid = uuid::Uuid::parse_str(&opt.uuid).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid uuid format, should be xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
            )
        })?;

        let security = match opt.security.to_lowercase().as_str() {
            "chacha20-poly1305" => SECURITY_CHACHA20_POLY1305,
            "aes-128-gcm" => SECURITY_AES_128_GCM,
            "none" => SECURITY_NONE,
            "auto" => match std::env::consts::ARCH {
                "x86_64" | "s390x" | "aarch64" => SECURITY_AES_128_GCM,
                _ => SECURITY_CHACHA20_POLY1305,
            },
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "invalid security",
                ));
            }
        };

        Ok(Self {
            user: new_alter_id_list(&user::new_id(&uuid), opt.alter_id),
            security,
            is_aead: opt.alter_id == 0,
            is_udp: opt.udp,
            dst: opt.dst.clone(),
        })
    }

    pub async fn proxy_stream<S>(&self, stream: S) -> io::Result<stream::VmessStream<S>>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    {
        let idx = crate::utils::rand_range(0..self.user.len());
        stream::VmessStream::new(
            stream,
            &self.user[idx],
            &self.dst,
            &self.security,
            self.is_aead,
            self.is_udp,
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proxy::TargetAddr;
    use crate::proxy::outbound::vmess::vmess_impl::{
        SECURITY_AES_128_GCM, SECURITY_CHACHA20_POLY1305, SECURITY_NONE,
    };

    #[test]
    fn test_vmess_option_custom() {
        let opt = VmessOption {
            uuid: "b831381d-6324-4d53-ad4f-8cda48b30811".to_string(),
            alter_id: 0,
            security: "chacha20-poly1305".to_string(),
            udp: true,
            dst: TargetAddr::from_str2("example.com", 443).unwrap(),
        };
        let builder = Builder::new(&opt).unwrap();
        assert_eq!(builder.security, SECURITY_CHACHA20_POLY1305);
        assert!(builder.is_aead);
        assert!(builder.is_udp);
    }

    #[test]
    fn test_vmess_option_aes_gcm() {
        let opt = VmessOption {
            uuid: "b831381d-6324-4d53-ad4f-8cda48b30811".to_string(),
            alter_id: 0,
            security: "aes-128-gcm".to_string(),
            udp: false,
            dst: TargetAddr::from_str2("example.com", 443).unwrap(),
        };
        let builder = Builder::new(&opt).unwrap();
        assert_eq!(builder.security, SECURITY_AES_128_GCM);
    }

    #[test]
    fn test_vmess_option_none_security() {
        let opt = VmessOption {
            uuid: "b831381d-6324-4d53-ad4f-8cda48b30811".to_string(),
            alter_id: 0,
            security: "none".to_string(),
            udp: false,
            dst: TargetAddr::from_str2("example.com", 443).unwrap(),
        };
        let builder = Builder::new(&opt).unwrap();
        assert_eq!(builder.security, SECURITY_NONE);
    }
}
