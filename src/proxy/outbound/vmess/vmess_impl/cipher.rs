use aead::AeadInPlace;
use aes_gcm::{Aes128Gcm, KeyInit, aes::cipher::Unsigned};
use bytes::Bytes;
use chacha20poly1305::ChaCha20Poly1305;

pub trait AeadCipherHelper: AeadInPlace {
    fn new_with_slice(key: &[u8]) -> Self;

    fn encrypt_in_place_with_slice(&self, nonce: &[u8], aad: &[u8], buffer: &mut [u8]) {
        let tag_pos = buffer.len() - Self::TagSize::to_usize();
        let (msg, tag) = buffer.split_at_mut(tag_pos);
        let x = self
            .encrypt_in_place_detached(nonce.into(), aad, msg)
            .expect("encryption failure!");
        tag.copy_from_slice(x.as_slice());
    }

    fn decrypt_in_place_with_slice(
        &self,
        nonce: &[u8],
        aad: &[u8],
        buffer: &mut [u8],
    ) -> Result<(), aes_gcm::Error> {
        let tag_pos = buffer.len() - Self::TagSize::to_usize();
        let (msg, tag) = buffer.split_at_mut(tag_pos);
        self.decrypt_in_place_detached(
            nonce.into(),
            aad,
            msg,
            aes_gcm::aead::Tag::<Self>::from_slice(tag),
        )
    }
}

impl AeadCipherHelper for Aes128Gcm {
    fn new_with_slice(key: &[u8]) -> Self {
        Aes128Gcm::new_from_slice(key).expect("Aes128Gcm: invalid key")
    }
}

impl AeadCipherHelper for ChaCha20Poly1305 {
    fn new_with_slice(key: &[u8]) -> Self {
        ChaCha20Poly1305::new_from_slice(key).expect("ChaCha20Poly1305: invalid key")
    }
}

pub enum VmessSecurity {
    Aes128Gcm(Aes128Gcm),
    ChaCha20Poly1305(ChaCha20Poly1305),
}

impl VmessSecurity {
    #[inline(always)]
    pub fn overhead_len(&self) -> usize {
        16
    }

    #[inline(always)]
    pub fn nonce_len(&self) -> usize {
        12
    }
}

pub(crate) struct AeadCipher {
    pub security: VmessSecurity,
    nonce: [u8; 32],
    iv: Bytes,
    count: u16,
}

impl AeadCipher {
    pub fn new(iv: &[u8], security: VmessSecurity) -> Self {
        Self {
            security,
            nonce: [0u8; 32],
            iv: Bytes::copy_from_slice(iv),
            count: 0,
        }
    }

    pub fn decrypt_inplace(&mut self, buf: &mut [u8]) -> std::io::Result<()> {
        let mut nonce = self.nonce;
        let security = &self.security;
        let iv = &self.iv;
        let count = &mut self.count;

        nonce[..2].copy_from_slice(&count.to_be_bytes());
        nonce[2..12].copy_from_slice(&iv[2..12]);
        *count += 1;

        let nonce = &nonce[..security.nonce_len()];
        match security {
            VmessSecurity::Aes128Gcm(cipher) => {
                cipher
                    .decrypt_in_place_with_slice(nonce, &[], &mut buf[..])
                    .map_err(|e| {
                        std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string())
                    })?;
            }
            VmessSecurity::ChaCha20Poly1305(cipher) => {
                cipher
                    .decrypt_in_place_with_slice(nonce, &[], &mut buf[..])
                    .map_err(|e| {
                        std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string())
                    })?;
            }
        }

        Ok(())
    }

    pub fn encrypt_inplace(&mut self, buf: &mut [u8]) -> std::io::Result<()> {
        let mut nonce = self.nonce;
        let security = &self.security;
        let iv = &self.iv;
        let count = &mut self.count;

        nonce[..2].copy_from_slice(&count.to_be_bytes());
        nonce[2..12].copy_from_slice(&iv[2..12]);
        *count += 1;

        let nonce = &nonce[..security.nonce_len()];
        match security {
            VmessSecurity::Aes128Gcm(cipher) => {
                cipher.encrypt_in_place_with_slice(nonce, &[], &mut buf[..]);
            }
            VmessSecurity::ChaCha20Poly1305(cipher) => {
                cipher.encrypt_in_place_with_slice(nonce, &[], &mut buf[..]);
            }
        }

        Ok(())
    }
}
