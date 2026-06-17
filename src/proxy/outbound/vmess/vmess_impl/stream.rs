use std::fmt::Debug;
use std::io;
use std::pin::Pin;
use std::task::Poll;
use std::time::SystemTime;

use aes_gcm::{Aes128Gcm, KeyInit};
use bytes::{BufMut, BytesMut};
use chacha20poly1305::ChaCha20Poly1305;
use futures::ready;

use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};

use crate::proxy::TargetAddr;

use super::cipher::{AeadCipher, AeadCipherHelper, VmessSecurity};
use super::header;
use super::kdf::{
    self, KDF_SALT_CONST_AEAD_RESP_HEADER_LEN_IV, KDF_SALT_CONST_AEAD_RESP_HEADER_LEN_KEY,
    KDF_SALT_CONST_AEAD_RESP_HEADER_PAYLOAD_IV, KDF_SALT_CONST_AEAD_RESP_HEADER_PAYLOAD_KEY,
};
use super::user::ID;
use super::{
    CHUNK_SIZE, COMMAND_TCP, COMMAND_UDP, MAX_CHUNK_SIZE, OPTION_CHUNK_STREAM,
    SECURITY_AES_128_GCM, SECURITY_CHACHA20_POLY1305, SECURITY_NONE, VERSION,
};

pub struct VmessStream<S> {
    stream: S,
    aead_read_cipher: Option<AeadCipher>,
    aead_write_cipher: Option<AeadCipher>,
    dst: TargetAddr,
    id: ID,
    req_body_iv: Vec<u8>,
    req_body_key: Vec<u8>,
    resp_body_iv: Vec<u8>,
    resp_body_key: Vec<u8>,
    resp_v: u8,
    security: u8,
    is_aead: bool,
    is_udp: bool,

    read_state: ReadState,
    #[allow(dead_code)]
    read_pos: usize,
    read_buf: BytesMut,

    write_state: WriteState,
    write_buf: BytesMut,
}

impl<S> Debug for VmessStream<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VmessStream")
            .field("dst", &self.dst)
            .field("is_aead", &self.is_aead)
            .field("is_udp", &self.is_udp)
            .finish()
    }
}

enum ReadState {
    AeadWaitingHeaderSize,
    AeadWaitingHeader(usize),
    StreamWaitingLength,
    StreamWaitingData(usize),
    StreamFlushingData(usize),
}

enum WriteState {
    BuildingData,
    FlushingData(usize, (usize, usize)),
}

fn hash_timestamp(now: u64) -> [u8; 16] {
    let mut hasher = md5::Context::new();
    hasher.consume(now.to_string().as_bytes());
    hasher.finalize().into()
}

/// HMAC-MD5 implementation: H(K XOR opad || H(K XOR ipad || text))
fn hmac_md5(key: &[u8], data: &[u8]) -> [u8; 16] {
    const BLOCK_SIZE: usize = 64;

    let mut key_block = [0u8; BLOCK_SIZE];
    if key.len() > BLOCK_SIZE {
        let h: [u8; 16] = md5::compute(key).into();
        key_block[..16].copy_from_slice(&h);
    } else {
        key_block[..key.len()].copy_from_slice(key);
    }

    let mut ipad = [0u8; BLOCK_SIZE];
    let mut opad = [0u8; BLOCK_SIZE];
    for i in 0..BLOCK_SIZE {
        ipad[i] = key_block[i] ^ 0x36;
        opad[i] = key_block[i] ^ 0x5C;
    }

    let mut inner = md5::Context::new();
    inner.consume(&ipad);
    inner.consume(data);
    let inner_hash: [u8; 16] = inner.finalize().into();

    let mut outer = md5::Context::new();
    outer.consume(&opad);
    outer.consume(&inner_hash);
    outer.finalize().into()
}

impl<S> VmessStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    pub(crate) async fn new(
        stream: S,
        id: &ID,
        dst: &TargetAddr,
        security: &u8,
        is_aead: bool,
        is_udp: bool,
    ) -> io::Result<VmessStream<S>> {
        let mut rand_bytes = [0u8; 33];
        crate::utils::rand_fill(&mut rand_bytes[..]);
        let req_body_iv = rand_bytes[0..16].to_vec();
        let req_body_key = rand_bytes[16..32].to_vec();
        let resp_v = rand_bytes[32];

        let (resp_body_key, resp_body_iv) = if is_aead {
            (
                crate::utils::sha256(req_body_key.as_slice())[0..16].to_vec(),
                crate::utils::sha256(req_body_iv.as_slice())[0..16].to_vec(),
            )
        } else {
            (
                crate::utils::md5(req_body_key.as_slice()),
                crate::utils::md5(req_body_iv.as_slice()),
            )
        };

        let (aead_read_cipher, aead_write_cipher) = match *security {
            SECURITY_NONE => (None, None),
            SECURITY_AES_128_GCM => {
                let write_cipher =
                    VmessSecurity::Aes128Gcm(Aes128Gcm::new_with_slice(&req_body_key));
                let write_cipher = AeadCipher::new(&req_body_iv, write_cipher);
                let reader_cipher =
                    VmessSecurity::Aes128Gcm(Aes128Gcm::new_with_slice(&resp_body_key));
                let read_cipher = AeadCipher::new(&resp_body_iv, reader_cipher);
                (Some(read_cipher), Some(write_cipher))
            }
            SECURITY_CHACHA20_POLY1305 => {
                let mut key = [0u8; 32];
                key[..16].copy_from_slice(&crate::utils::md5(&req_body_key));
                let tmp = crate::utils::md5(&key[..16]);
                key[16..].copy_from_slice(&tmp);

                let write_cipher =
                    VmessSecurity::ChaCha20Poly1305(ChaCha20Poly1305::new_with_slice(&key));
                let write_cipher = AeadCipher::new(&req_body_iv, write_cipher);

                let mut key = [0u8; 32];
                key[..16].copy_from_slice(&crate::utils::md5(&resp_body_key));
                let tmp = crate::utils::md5(&key[..16]);
                key[16..].copy_from_slice(&tmp);

                let reader_cipher =
                    VmessSecurity::ChaCha20Poly1305(ChaCha20Poly1305::new_with_slice(&key));
                let read_cipher = AeadCipher::new(&resp_body_iv, reader_cipher);

                (Some(read_cipher), Some(write_cipher))
            }
            _ => {
                return Err(io::Error::other("unsupported security"));
            }
        };

        let mut stream = Self {
            stream,
            aead_read_cipher,
            aead_write_cipher,
            dst: dst.to_owned(),
            id: id.to_owned(),
            req_body_iv,
            req_body_key,
            resp_body_iv,
            resp_body_key,
            resp_v,
            security: *security,
            is_aead,
            is_udp,

            read_state: ReadState::AeadWaitingHeaderSize,
            read_pos: 0,
            read_buf: BytesMut::new(),

            write_state: WriteState::BuildingData,
            write_buf: BytesMut::new(),
        };

        stream.send_handshake_request().await?;

        Ok(stream)
    }

    pub fn get_stream(self) -> S {
        self.stream
    }
}

impl<S> VmessStream<S>
where
    S: AsyncWrite + Unpin,
{
    async fn send_handshake_request(&mut self) -> io::Result<()> {
        let &mut Self {
            ref mut stream,
            ref req_body_key,
            ref req_body_iv,
            ref resp_v,
            ref security,
            ref dst,
            ref is_aead,
            ref is_udp,
            ref id,
            ..
        } = self;

        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("check your system clock")
            .as_secs();

        let mut mbuf = BytesMut::new();

        if !is_aead {
            // HMAC-MD5: HMAC(key, timestamp)
            let hmac_result = hmac_md5(id.uuid.as_bytes(), &now.to_be_bytes());
            mbuf.put_slice(&hmac_result);
        }

        let mut buf = BytesMut::new();
        buf.put_u8(VERSION);
        buf.put_slice(req_body_iv);
        buf.put_slice(req_body_key);
        buf.put_u8(*resp_v);
        buf.put_u8(OPTION_CHUNK_STREAM);

        let p = crate::utils::rand_range(0..16);
        buf.put_u8((p << 4) as u8 | security);

        buf.put_u8(0);

        if *is_udp {
            buf.put_u8(COMMAND_UDP);
        } else {
            buf.put_u8(COMMAND_TCP);
        }

        dst.write_to_buf_vmess(&mut buf);

        if p > 0 {
            let mut padding = vec![0u8; p as usize];
            crate::utils::rand_fill(&mut padding[..]);
            buf.put_slice(&padding);
        }

        let sum = const_fnv1a_hash::fnv1a_hash_32(&buf, None);
        buf.put_slice(&sum.to_be_bytes());

        if !is_aead {
            let mut data = buf.to_vec();
            aes_cfb_encrypt(&id.cmd_key[..], &hash_timestamp(now)[..], &mut data)
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

            mbuf.put_slice(data.as_slice());
            let out = mbuf.freeze();
            stream.write_all(&out).await?;
        } else {
            let out = header::seal_vmess_aead_header(id.cmd_key, buf.freeze().to_vec(), now)
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
            stream.write_all(&out).await?;
        }

        stream.flush().await?;

        Ok(())
    }
}

impl<S> AsyncRead for VmessStream<S>
where
    S: AsyncRead + Unpin + Send,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            match self.read_state {
                ReadState::AeadWaitingHeaderSize => {
                    let this = &mut *self;
                    let resp_body_key = this.resp_body_key.clone();
                    let resp_body_iv = this.resp_body_iv.clone();
                    let resp_v = this.resp_v;

                    if !this.is_aead {
                        ready!(poll_read_exact(&mut this.stream, cx, 4, &mut this.read_buf))?;
                        let mut buf = this.read_buf.split().freeze().to_vec();
                        aes_cfb_decrypt(&resp_body_key, &resp_body_iv, &mut buf)
                            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
                        if buf[0] != resp_v {
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                "invalid response - non aead invalid resp_v",
                            )));
                        }

                        if buf[2] != 0 {
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                "invalid response - dynamic port not supported",
                            )));
                        }

                        this.read_state = ReadState::StreamWaitingLength;
                    } else {
                        ready!(poll_read_exact(
                            &mut this.stream,
                            cx,
                            18,
                            &mut this.read_buf
                        ))?;

                        let aead_response_header_length_encryption_key = &kdf::vmess_kdf_1_one_shot(
                            &resp_body_key,
                            KDF_SALT_CONST_AEAD_RESP_HEADER_LEN_KEY,
                        )[..16];
                        let aead_response_header_length_encryption_iv = &kdf::vmess_kdf_1_one_shot(
                            &resp_body_iv,
                            KDF_SALT_CONST_AEAD_RESP_HEADER_LEN_IV,
                        )[..12];

                        let decrypted_response_header_len = aes_gcm_decrypt(
                            aead_response_header_length_encryption_key,
                            aead_response_header_length_encryption_iv,
                            this.read_buf.split().as_ref(),
                            None,
                        )
                        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;

                        if decrypted_response_header_len.len() < 2 {
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                "invalid response header length",
                            )));
                        }

                        this.read_state = ReadState::AeadWaitingHeader(u16::from_be_bytes(
                            decrypted_response_header_len[..2].try_into().unwrap(),
                        )
                            as usize);
                    }
                }

                ReadState::AeadWaitingHeader(header_size) => {
                    let this = &mut *self;
                    ready!(poll_read_exact(
                        &mut this.stream,
                        cx,
                        header_size + 16,
                        &mut this.read_buf
                    ))?;

                    let resp_body_key = this.resp_body_key.clone();
                    let resp_body_iv = this.resp_body_iv.clone();

                    let aead_response_header_payload_encryption_key = &kdf::vmess_kdf_1_one_shot(
                        &resp_body_key,
                        KDF_SALT_CONST_AEAD_RESP_HEADER_PAYLOAD_KEY,
                    )[..16];
                    let aead_response_header_payload_encryption_iv = &kdf::vmess_kdf_1_one_shot(
                        &resp_body_iv,
                        KDF_SALT_CONST_AEAD_RESP_HEADER_PAYLOAD_IV,
                    )[..12];

                    let buf = aes_gcm_decrypt(
                        aead_response_header_payload_encryption_key,
                        aead_response_header_payload_encryption_iv,
                        this.read_buf.split().as_ref(),
                        None,
                    )
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;

                    if buf.len() < 4 {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "invalid response - header too short",
                        )));
                    }

                    if buf[0] != this.resp_v {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "invalid response - version mismatch",
                        )));
                    }

                    if buf[2] != 0 {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "invalid response - dynamic port not supported",
                        )));
                    }

                    this.read_state = ReadState::StreamWaitingLength;
                }

                ReadState::StreamWaitingLength => {
                    let this = &mut *self;
                    ready!(poll_read_exact(&mut this.stream, cx, 2, &mut this.read_buf))?;
                    let len = u16::from_be_bytes(this.read_buf.split().as_ref().try_into().unwrap())
                        as usize;

                    if len > MAX_CHUNK_SIZE {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "invalid response - chunk size too large",
                        )));
                    }

                    this.read_state = ReadState::StreamWaitingData(len);
                }

                ReadState::StreamWaitingData(size) => {
                    let this = &mut *self;
                    ready!(poll_read_exact(
                        &mut this.stream,
                        cx,
                        size,
                        &mut this.read_buf
                    ))?;

                    match this.aead_read_cipher {
                        Some(ref mut cipher) => {
                            cipher.decrypt_inplace(&mut this.read_buf)?;
                            let data_len = size - cipher.security.overhead_len();
                            this.read_buf.truncate(data_len);
                            this.read_state = ReadState::StreamFlushingData(data_len);
                        }
                        _ => {
                            this.read_state = ReadState::StreamFlushingData(size);
                        }
                    }
                }

                ReadState::StreamFlushingData(size) => {
                    let to_read = std::cmp::min(buf.remaining(), size);
                    let payload = self.read_buf.split_to(to_read);
                    buf.put_slice(&payload);
                    if to_read < size {
                        self.read_state = ReadState::StreamFlushingData(size - to_read);
                    } else {
                        self.read_state = ReadState::StreamWaitingLength;
                    }

                    return Poll::Ready(Ok(()));
                }
            }
        }
    }
}

impl<S> AsyncWrite for VmessStream<S>
where
    S: AsyncWrite + Unpin + Send,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        loop {
            match self.write_state {
                WriteState::BuildingData => {
                    let this = &mut *self;
                    let mut overhead_len = 0;
                    if let Some(ref mut cipher) = this.aead_write_cipher {
                        overhead_len = cipher.security.overhead_len();
                    }

                    let max_payload_size = CHUNK_SIZE - overhead_len;
                    let consume_len = std::cmp::min(buf.len(), max_payload_size);
                    let payload_len = consume_len + overhead_len;

                    let size_bytes = 2;
                    this.write_buf.reserve(size_bytes + payload_len);
                    this.write_buf.put_u16(payload_len as u16);

                    let mut piece2 = this.write_buf.split_off(size_bytes);
                    piece2.put_slice(&buf[..consume_len]);
                    if let Some(ref mut cipher) = this.aead_write_cipher {
                        piece2
                            .extend_from_slice(vec![0u8; cipher.security.overhead_len()].as_ref());
                    }

                    let _cur_len = piece2.len();
                    if let Some(ref mut cipher) = this.aead_write_cipher {
                        cipher.encrypt_inplace(&mut piece2)?;
                    }
                    this.write_buf.unsplit(piece2);
                    this.write_state =
                        WriteState::FlushingData(consume_len, (0, this.write_buf.len()));
                }

                WriteState::FlushingData(consume_len, (written, total)) => {
                    let this = &mut *self;

                    let slice_to_write = &this.write_buf[written..total];
                    let n = ready!(Pin::new(&mut this.stream).poll_write(cx, slice_to_write))?;

                    if n == 0 {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::WriteZero,
                            "write zero",
                        )));
                    }

                    let new_written = written + n;
                    if new_written < total {
                        this.write_state =
                            WriteState::FlushingData(consume_len, (new_written, total));
                        cx.waker().wake_by_ref();
                        return Poll::Pending;
                    }

                    this.write_buf.clear();
                    this.write_state = WriteState::BuildingData;

                    return Poll::Ready(Ok(consume_len));
                }
            }
        }
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

fn poll_read_exact<S: AsyncRead + Unpin>(
    stream: &mut S,
    cx: &mut std::task::Context<'_>,
    count: usize,
    buf: &mut BytesMut,
) -> Poll<io::Result<()>> {
    let start = buf.len();
    buf.resize(start + count, 0);

    let mut read_buf = ReadBuf::new(&mut buf[start..]);
    let result = Pin::new(stream).poll_read(cx, &mut read_buf);

    match result {
        Poll::Ready(Ok(())) => {
            if read_buf.filled().len() != count {
                buf.truncate(start);
                Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "unexpected EOF",
                )))
            } else {
                buf.truncate(start + count);
                Poll::Ready(Ok(()))
            }
        }
        Poll::Ready(Err(e)) => {
            buf.truncate(start);
            Poll::Ready(Err(e))
        }
        Poll::Pending => {
            buf.truncate(start);
            Poll::Pending
        }
    }
}

fn aes_gcm_decrypt(
    key: &[u8],
    nonce: &[u8],
    ciphertext: &[u8],
    associated_data: Option<&[u8]>,
) -> Result<Vec<u8>, aes_gcm::Error> {
    use aes_gcm::aead::Aead;

    let cipher = aes_gcm::Aes128Gcm::new_from_slice(key).map_err(|_| aes_gcm::Error)?;

    let nonce = aes_gcm::Nonce::from_slice(nonce);
    cipher.decrypt(
        nonce,
        aes_gcm::aead::Payload {
            msg: ciphertext,
            aad: associated_data.unwrap_or_default(),
        },
    )
}

fn aes_cfb_encrypt(key: &[u8], iv: &[u8], data: &mut [u8]) -> Result<(), anyhow::Error> {
    use aes::cipher::{AsyncStreamCipher, KeyIvInit};
    match key.len() {
        16 => {
            let cipher = cfb_mode::Encryptor::<aes::Aes128>::new(key.into(), iv.into());
            cipher.encrypt(data);
            Ok(())
        }
        _ => anyhow::bail!("invalid key length for aes-cfb"),
    }
}

fn aes_cfb_decrypt(key: &[u8], iv: &[u8], data: &mut [u8]) -> Result<(), anyhow::Error> {
    use aes::cipher::{AsyncStreamCipher, KeyIvInit};
    match key.len() {
        16 => {
            let cipher = cfb_mode::Decryptor::<aes::Aes128>::new(key.into(), iv.into());
            cipher.decrypt(data);
            Ok(())
        }
        _ => anyhow::bail!("invalid key length for aes-cfb"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proxy::TargetAddr;
    use crate::proxy::outbound::vmess::vmess_impl::client::{Builder, VmessOption};

    #[test]
    fn test_vmess_builder_new_valid() {
        let opt = VmessOption {
            uuid: "b831381d-6324-4d53-ad4f-8cda48b30811".to_string(),
            alter_id: 0,
            security: "auto".to_string(),
            udp: false,
            dst: TargetAddr::from_str2("example.com", 443).unwrap(),
        };
        let builder = Builder::new(&opt);
        assert!(builder.is_ok());
        let b = builder.unwrap();
        assert!(b.is_aead);
        assert!(!b.is_udp);
    }

    #[test]
    fn test_vmess_builder_new_udp() {
        let opt = VmessOption {
            uuid: "b831381d-6324-4d53-ad4f-8cda48b30811".to_string(),
            alter_id: 0,
            security: "auto".to_string(),
            udp: true,
            dst: TargetAddr::from_str2("example.com", 443).unwrap(),
        };
        let builder = Builder::new(&opt);
        assert!(builder.is_ok());
        assert!(builder.unwrap().is_udp);
    }

    #[test]
    fn test_vmess_builder_with_alter_id() {
        let opt = VmessOption {
            uuid: "b831381d-6324-4d53-ad4f-8cda48b30811".to_string(),
            alter_id: 1,
            security: "auto".to_string(),
            udp: false,
            dst: TargetAddr::from_str2("example.com", 443).unwrap(),
        };
        let builder = Builder::new(&opt);
        assert!(builder.is_ok());
        let b = builder.unwrap();
        assert!(!b.is_aead); // alter_id > 0 means legacy mode
        assert_eq!(b.user.len(), 2); // alter_id_list length
    }

    #[test]
    fn test_vmess_builder_invalid_uuid() {
        let opt = VmessOption {
            uuid: "not-a-valid-uuid".to_string(),
            alter_id: 0,
            security: "auto".to_string(),
            udp: false,
            dst: TargetAddr::from_str2("example.com", 443).unwrap(),
        };
        let builder = Builder::new(&opt);
        assert!(builder.is_err());
    }

    #[test]
    fn test_vmess_builder_invalid_security() {
        let opt = VmessOption {
            uuid: "b831381d-6324-4d53-ad4f-8cda48b30811".to_string(),
            alter_id: 0,
            security: "invalid-algo".to_string(),
            udp: false,
            dst: TargetAddr::from_str2("example.com", 443).unwrap(),
        };
        let builder = Builder::new(&opt);
        assert!(builder.is_err());
    }

    #[test]
    fn test_vmess_builder_security_options() {
        for sec in &["chacha20-poly1305", "aes-128-gcm", "none", "auto"] {
            let opt = VmessOption {
                uuid: "b831381d-6324-4d53-ad4f-8cda48b30811".to_string(),
                alter_id: 0,
                security: sec.to_string(),
                udp: false,
                dst: TargetAddr::from_str2("example.com", 443).unwrap(),
            };
            let builder = Builder::new(&opt);
            assert!(builder.is_ok(), "security '{}' should be valid", sec);
        }
    }

    #[test]
    fn test_hash_timestamp() {
        let result = hash_timestamp(1234567890);
        assert_eq!(result.len(), 16);
        // Same input should produce same output
        assert_eq!(hash_timestamp(1234567890), result);
        // Different input should produce different output
        assert_ne!(hash_timestamp(1234567891), result);
    }

    #[test]
    fn test_hmac_md5() {
        let key = b"test-key-123456";
        let data = b"test-data-789";
        let result = hmac_md5(key, data);
        assert_eq!(result.len(), 16);
        // Same inputs produce same output
        assert_eq!(hmac_md5(key, data), result);
        // Different data produces different output
        assert_ne!(hmac_md5(key, b"different"), result);
    }

    #[tokio::test]
    async fn test_vmess_stream_handshake_timeout() {
        // Test that connecting to a non-responsive peer times out
        let (client, _server) = tokio::io::duplex(1024);
        drop(_server); // server side is dropped, simulating no response

        let dst = TargetAddr::from_str2("example.com", 443).unwrap();
        let id = crate::proxy::outbound::vmess::vmess_impl::user::new_id(
            &uuid::Uuid::parse_str("b831381d-6324-4d53-ad4f-8cda48b30811").unwrap(),
        );

        // The handshake will attempt to write/read but the server side is dropped
        let result = VmessStream::new(client, &id, &dst, &SECURITY_AES_128_GCM, true, false).await;
        // Should fail because server side is closed
        assert!(result.is_err());
    }
}
