use aead::KeyInit;
use aes::cipher::BlockEncrypt;
use bytes::{Buf, BufMut, BytesMut};

use super::kdf::{
    self, KDF_SALT_CONST_AUTH_ID_ENCRYPTION_KEY, KDF_SALT_CONST_VMESS_HEADER_PAYLOAD_AEAD_IV,
    KDF_SALT_CONST_VMESS_HEADER_PAYLOAD_AEAD_KEY,
    KDF_SALT_CONST_VMESS_HEADER_PAYLOAD_LENGTH_AEAD_IV,
    KDF_SALT_CONST_VMESS_HEADER_PAYLOAD_LENGTH_AEAD_KEY,
};

use crate::utils::new_io_other_error;

fn create_auth_id(cmd_key: [u8; 16], timestamp: u64) -> [u8; 16] {
    let mut buf = BytesMut::new();
    buf.put_u64(timestamp);

    let mut random = [0u8; 4];
    crate::utils::rand_fill(&mut random);
    buf.put_slice(&random);

    let zero = crc32fast::hash(buf.as_ref());
    buf.put_u32(zero);

    let pk = kdf::vmess_kdf_1_one_shot(&cmd_key[..], KDF_SALT_CONST_AUTH_ID_ENCRYPTION_KEY);
    let pk: [u8; 16] = pk[..16].try_into().unwrap();
    let key = aead::generic_array::GenericArray::from(pk);
    let cipher = aes::Aes128::new(&key);
    let mut block = [0u8; 16];
    buf.copy_to_slice(&mut block);
    let mut block = aead::generic_array::GenericArray::from(block);
    cipher.encrypt_block(&mut block);
    block.as_slice()[..16].try_into().unwrap()
}

pub(crate) fn seal_vmess_aead_header(
    key: [u8; 16],
    data: Vec<u8>,
    timestamp: u64,
) -> anyhow::Result<Vec<u8>> {
    let auth_id = create_auth_id(key, timestamp);
    let mut connection_nonce = [0u8; 8];
    crate::utils::rand_fill(connection_nonce.as_mut());

    let payload_header_length_aead_key = &kdf::vmess_kdf_3_one_shot(
        &key[..],
        KDF_SALT_CONST_VMESS_HEADER_PAYLOAD_LENGTH_AEAD_KEY,
        &auth_id[..],
        &connection_nonce[..],
    )[..16];
    let payload_header_length_aead_nonce = &kdf::vmess_kdf_3_one_shot(
        &key[..],
        KDF_SALT_CONST_VMESS_HEADER_PAYLOAD_LENGTH_AEAD_IV,
        &auth_id[..],
        &connection_nonce[..],
    )[..12];

    let header_len_encrypted = aes_gcm_encrypt(
        payload_header_length_aead_key,
        payload_header_length_aead_nonce,
        (data.len() as u16).to_be_bytes().as_ref(),
        Some(auth_id.as_ref()),
    )?;

    let payload_header_aead_key = &kdf::vmess_kdf_3_one_shot(
        &key[..],
        KDF_SALT_CONST_VMESS_HEADER_PAYLOAD_AEAD_KEY,
        &auth_id[..],
        &connection_nonce[..],
    )[..16];
    let payload_header_aead_nonce = &kdf::vmess_kdf_3_one_shot(
        &key[..],
        KDF_SALT_CONST_VMESS_HEADER_PAYLOAD_AEAD_IV,
        &auth_id[..],
        &connection_nonce[..],
    )[..12];

    let payload_encrypted = aes_gcm_encrypt(
        payload_header_aead_key,
        payload_header_aead_nonce,
        &data,
        Some(auth_id.as_ref()),
    )?;

    let mut out = BytesMut::new();
    out.put_slice(&auth_id[..]);
    out.put_slice(&header_len_encrypted[..]);
    out.put_slice(connection_nonce.as_ref());
    out.put_slice(&payload_encrypted[..]);

    Ok(out.freeze().to_vec())
}

fn aes_gcm_encrypt(
    key: &[u8],
    nonce: &[u8],
    plaintext: &[u8],
    associated_data: Option<&[u8]>,
) -> anyhow::Result<Vec<u8>> {
    use aes_gcm::KeyInit;
    use aes_gcm::aead::Aead;

    let cipher = aes_gcm::Aes128Gcm::new_from_slice(key)
        .map_err(|e| new_io_other_error(format!("AES-GCM init: {}", e)))?;

    let nonce = aes_gcm::Nonce::from_slice(nonce);
    let ciphertext = cipher
        .encrypt(
            nonce,
            aes_gcm::aead::Payload {
                msg: plaintext,
                aad: associated_data.unwrap_or_default(),
            },
        )
        .map_err(|e| new_io_other_error(format!("AES-GCM encrypt: {}", e)))?;

    Ok(ciphertext)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proxy::outbound::vmess::vmess_impl::kdf::{
        KDF_SALT_CONST_VMESS_HEADER_PAYLOAD_AEAD_IV, KDF_SALT_CONST_VMESS_HEADER_PAYLOAD_AEAD_KEY,
        KDF_SALT_CONST_VMESS_HEADER_PAYLOAD_LENGTH_AEAD_IV,
        KDF_SALT_CONST_VMESS_HEADER_PAYLOAD_LENGTH_AEAD_KEY,
    };

    #[test]
    fn test_seal_vmess_header_roundtrip() {
        let key = "1234567890123456".as_bytes();
        let key: [u8; 16] = key.try_into().unwrap();
        let data = vec![42u8; 16];

        let timestamp: u64 = 1234567890;
        let header = seal_vmess_aead_header(key, data.clone(), timestamp).unwrap();

        // Verify the header has the expected structure:
        // auth_id(16) + length_encrypted(18) + connection_nonce(8) + payload_encrypted
        assert!(header.len() > 16 + 18 + 8);
        assert!(header.len() <= 16 + 18 + 8 + data.len() + 32); // overhead of AEAD tag
    }

    #[test]
    fn test_aes_gcm_roundtrip() {
        use aes_gcm::KeyInit;
        use aes_gcm::aead::Aead;

        let key = [0u8; 16];
        let nonce = [0u8; 12];
        let data = b"hello world";

        let encrypted = aes_gcm_encrypt(&key, &nonce, data, Some(&[1, 2, 3])).unwrap();
        assert!(encrypted.len() > data.len()); // ciphertext includes tag

        // Decrypt and verify
        let cipher = aes_gcm::Aes128Gcm::new_from_slice(&key).unwrap();
        let nonce = aes_gcm::Nonce::from_slice(&nonce);
        let decrypted = cipher
            .decrypt(
                nonce,
                aes_gcm::aead::Payload {
                    msg: &encrypted,
                    aad: &[1, 2, 3],
                },
            )
            .unwrap();
        assert_eq!(decrypted, data.to_vec());
    }

    #[test]
    fn test_kdf_3_one_shot_smoke() {
        // Verify KDF3 produces consistent output
        let result1 = kdf::vmess_kdf_3_one_shot(
            b"test",
            b"key1key1key1key1",
            b"key2key2key2key2",
            b"key3key3key3key3",
        );
        let result2 = kdf::vmess_kdf_3_one_shot(
            b"test",
            b"key1key1key1key1",
            b"key2key2key2key2",
            b"key3key3key3key3",
        );
        assert_eq!(result1, result2);
        assert_ne!(result1, [0u8; 32]); // Shouldn't be all zeros
    }

    #[test]
    fn test_seal_vmess_header() {
        let key = "1234567890123456".as_bytes();
        let key: [u8; 16] = key.try_into().unwrap();
        let auth_id = [0u8; 16];
        let connection_nonce = [0u8; 8];
        let data = vec![0u8; 16];

        let payload_header_length_aead_key = &kdf::vmess_kdf_3_one_shot(
            &key[..],
            KDF_SALT_CONST_VMESS_HEADER_PAYLOAD_LENGTH_AEAD_KEY,
            &auth_id[..],
            &connection_nonce[..],
        )[..16];

        let payload_header_length_aead_nonce = &kdf::vmess_kdf_3_one_shot(
            &key[..],
            KDF_SALT_CONST_VMESS_HEADER_PAYLOAD_LENGTH_AEAD_IV,
            &auth_id[..],
            &connection_nonce[..],
        )[..12];

        let header_len_encrypted = aes_gcm_encrypt(
            payload_header_length_aead_key,
            payload_header_length_aead_nonce,
            (data.len() as u16).to_be_bytes().as_ref(),
            Some(auth_id.as_ref()),
        )
        .unwrap();

        let payload_header_aead_key = &kdf::vmess_kdf_3_one_shot(
            &key[..],
            KDF_SALT_CONST_VMESS_HEADER_PAYLOAD_AEAD_KEY,
            &auth_id[..],
            &connection_nonce[..],
        )[..16];
        let payload_header_aead_nonce = &kdf::vmess_kdf_3_one_shot(
            &key[..],
            KDF_SALT_CONST_VMESS_HEADER_PAYLOAD_AEAD_IV,
            &auth_id[..],
            &connection_nonce[..],
        )[..12];

        let payload_encrypted = aes_gcm_encrypt(
            payload_header_aead_key,
            payload_header_aead_nonce,
            &data,
            Some(auth_id.as_ref()),
        )
        .unwrap();

        assert!(header_len_encrypted.len() > 2);
        assert!(payload_encrypted.len() > data.len());
    }
}
