use hmac::{Hmac, Mac};
use sha2::Sha256;
type HmacSha256 = Hmac<Sha256>;

const IPAD: u8 = 0x36;
const OPAD: u8 = 0x5C;
const BLOCK_LEN: usize = 64;
const TAG_LEN: usize = 32;

pub const KDF_SALT_CONST_AUTH_ID_ENCRYPTION_KEY: &[u8; 22] = b"AES Auth ID Encryption";
pub const KDF_SALT_CONST_AEAD_RESP_HEADER_LEN_KEY: &[u8; 24] = b"AEAD Resp Header Len Key";
pub const KDF_SALT_CONST_AEAD_RESP_HEADER_LEN_IV: &[u8; 23] = b"AEAD Resp Header Len IV";
pub const KDF_SALT_CONST_AEAD_RESP_HEADER_PAYLOAD_KEY: &[u8; 20] = b"AEAD Resp Header Key";
pub const KDF_SALT_CONST_AEAD_RESP_HEADER_PAYLOAD_IV: &[u8; 19] = b"AEAD Resp Header IV";
pub const KDF_SALT_CONST_VMESS_AEAD_KDF: &[u8; 14] = b"VMess AEAD KDF";
pub const KDF_SALT_CONST_VMESS_HEADER_PAYLOAD_AEAD_KEY: &[u8; 21] = b"VMess Header AEAD Key";
pub const KDF_SALT_CONST_VMESS_HEADER_PAYLOAD_AEAD_IV: &[u8; 23] = b"VMess Header AEAD Nonce";
pub const KDF_SALT_CONST_VMESS_HEADER_PAYLOAD_LENGTH_AEAD_KEY: &[u8; 28] = b"VMess Header AEAD Key_Length";
pub const KDF_SALT_CONST_VMESS_HEADER_PAYLOAD_LENGTH_AEAD_IV: &[u8; 30] = b"VMess Header AEAD Nonce_Length";

macro_rules! impl_hmac_kdf {
    ($name:ident, $inner:ty) => {
        #[derive(Clone)]
        pub struct $name {
            okey: [u8; BLOCK_LEN],
            hasher: $inner,
            hasher_outer: $inner,
        }

        impl $name {
            pub fn new(mut hasher: $inner, key: &[u8]) -> Self {
                let mut ikey = [0u8; BLOCK_LEN];
                let mut okey = [0u8; BLOCK_LEN];
                let hasher_outer = hasher.clone();
                if key.len() > BLOCK_LEN {
                    hasher.update(key);
                    let hkey = digest_bytes(&mut hasher);

                    ikey[..TAG_LEN].copy_from_slice(&hkey[..TAG_LEN]);
                    okey[..TAG_LEN].copy_from_slice(&hkey[..TAG_LEN]);
                } else {
                    ikey[..key.len()].copy_from_slice(key);
                    okey[..key.len()].copy_from_slice(key);
                }

                for idx in 0..BLOCK_LEN {
                    ikey[idx] ^= IPAD;
                    okey[idx] ^= OPAD;
                }
                hasher.update(&ikey);
                Self {
                    okey,
                    hasher,
                    hasher_outer,
                }
            }

            pub fn update(&mut self, m: &[u8]) {
                self.hasher.update(m);
            }

            pub fn finalize(mut self) -> [u8; TAG_LEN] {
                let h1 = digest_bytes(&mut self.hasher);

                self.hasher_outer.update(&self.okey);
                self.hasher_outer.update(&h1);

                let mut result = [0u8; TAG_LEN];
                let out = digest_bytes(&mut self.hasher_outer);
                result.copy_from_slice(&out);
                result
            }
        }
    };
}

fn digest_bytes(h: &mut HmacSha256) -> Vec<u8> {
    let h_clone = h.clone();
    h_clone.finalize().into_bytes().to_vec()
}

impl_hmac_kdf!(VmessKdf1, HmacSha256);

// For VmessKdf2/VmessKdf3 we need a different approach since they wrap non-hmac types
// Let's just implement them directly

#[derive(Clone)]
pub struct VmessKdf2 {
    okey: [u8; BLOCK_LEN],
    hasher: VmessKdf1,
    hasher_outer: VmessKdf1,
}

impl VmessKdf2 {
    pub fn new(mut hasher: VmessKdf1, key: &[u8]) -> Self {
        let mut ikey = [0u8; BLOCK_LEN];
        let mut okey = [0u8; BLOCK_LEN];
        let hasher_outer = hasher.clone();
        if key.len() > BLOCK_LEN {
            hasher.update(key);
            let hkey = hasher.clone().finalize();

            ikey[..TAG_LEN].copy_from_slice(&hkey[..TAG_LEN]);
            okey[..TAG_LEN].copy_from_slice(&hkey[..TAG_LEN]);
        } else {
            ikey[..key.len()].copy_from_slice(key);
            okey[..key.len()].copy_from_slice(key);
        }

        for idx in 0..BLOCK_LEN {
            ikey[idx] ^= IPAD;
            okey[idx] ^= OPAD;
        }
        hasher.update(&ikey);
        Self {
            okey,
            hasher,
            hasher_outer,
        }
    }

    pub fn update(&mut self, m: &[u8]) {
        self.hasher.update(m);
    }

    pub fn finalize(mut self) -> [u8; TAG_LEN] {
        let h1 = self.hasher.finalize();

        self.hasher_outer.update(&self.okey);
        self.hasher_outer.update(&h1);

        self.hasher_outer.finalize()
    }
}

#[derive(Clone)]
pub struct VmessKdf3 {
    okey: [u8; BLOCK_LEN],
    hasher: VmessKdf2,
    hasher_outer: VmessKdf2,
}

impl VmessKdf3 {
    pub fn new(mut hasher: VmessKdf2, key: &[u8]) -> Self {
        let mut ikey = [0u8; BLOCK_LEN];
        let mut okey = [0u8; BLOCK_LEN];
        let hasher_outer = hasher.clone();
        if key.len() > BLOCK_LEN {
            hasher.update(key);
            let hkey = hasher.clone().finalize();

            ikey[..TAG_LEN].copy_from_slice(&hkey[..TAG_LEN]);
            okey[..TAG_LEN].copy_from_slice(&hkey[..TAG_LEN]);
        } else {
            ikey[..key.len()].copy_from_slice(key);
            okey[..key.len()].copy_from_slice(key);
        }

        for idx in 0..BLOCK_LEN {
            ikey[idx] ^= IPAD;
            okey[idx] ^= OPAD;
        }
        hasher.update(&ikey);
        Self {
            okey,
            hasher,
            hasher_outer,
        }
    }

    pub fn update(&mut self, m: &[u8]) {
        self.hasher.update(m);
    }

    pub fn finalize(mut self) -> [u8; TAG_LEN] {
        let h1 = self.hasher.finalize();

        self.hasher_outer.update(&self.okey);
        self.hasher_outer.update(&h1);

        self.hasher_outer.finalize()
    }
}

#[inline]
fn get_vmess_kdf_1(key1: &[u8]) -> VmessKdf1 {
    VmessKdf1::new(
        HmacSha256::new_from_slice(KDF_SALT_CONST_VMESS_AEAD_KDF).unwrap(),
        key1,
    )
}

pub fn vmess_kdf_1_one_shot(id: &[u8], key1: &[u8]) -> [u8; 32] {
    let mut h = get_vmess_kdf_1(key1);
    h.update(id);
    h.finalize()
}

#[inline]
fn get_vmess_kdf_2(key1: &[u8], key2: &[u8]) -> VmessKdf2 {
    VmessKdf2::new(get_vmess_kdf_1(key1), key2)
}

#[inline]
fn get_vmess_kdf_3(key1: &[u8], key2: &[u8], key3: &[u8]) -> VmessKdf3 {
    VmessKdf3::new(get_vmess_kdf_2(key1, key2), key3)
}

pub fn vmess_kdf_3_one_shot(id: &[u8], key1: &[u8], key2: &[u8], key3: &[u8]) -> [u8; 32] {
    let mut h = get_vmess_kdf_3(key1, key2, key3);
    h.update(id);
    h.finalize()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kdf_1_one_shot() {
        assert_eq!(
            vmess_kdf_1_one_shot(b"test", KDF_SALT_CONST_AUTH_ID_ENCRYPTION_KEY).to_vec(),
            vec![
                149, 109, 253, 20, 158, 39, 112, 199, 28, 74, 3, 106, 99, 8, 234, 59, 64, 172, 126,
                5, 155, 28, 59, 21, 220, 196, 241, 54, 138, 5, 71, 107
            ]
        );
    }
}
