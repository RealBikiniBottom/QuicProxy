use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use aes_gcm::{Aes128Gcm, KeyInit};
use anyhow::{Context as _, bail};
use arc_swap::ArcSwap;
use async_trait::async_trait;
use bytes::{Buf, BufMut, Bytes, BytesMut};
use chacha20poly1305::ChaCha20Poly1305;
use futures::ready;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::sync::Mutex;
use tracing::{Instrument, error, field, info, info_span};

use crate::config::{AuthUser, InboundConfig};
use crate::proxy::inbound::{AnyInbound, create_tcp_listener};
use crate::proxy::observe::{UserAccount, get_observer};
use crate::proxy::outbound::vmess::vmess_impl::{
    AeadCipher, AeadCipherHelper, CHUNK_SIZE, COMMAND_UDP, ID,
    KDF_SALT_CONST_AEAD_RESP_HEADER_LEN_IV, KDF_SALT_CONST_AEAD_RESP_HEADER_LEN_KEY,
    KDF_SALT_CONST_AEAD_RESP_HEADER_PAYLOAD_IV, KDF_SALT_CONST_AEAD_RESP_HEADER_PAYLOAD_KEY,
    KDF_SALT_CONST_VMESS_HEADER_PAYLOAD_AEAD_IV, KDF_SALT_CONST_VMESS_HEADER_PAYLOAD_AEAD_KEY,
    KDF_SALT_CONST_VMESS_HEADER_PAYLOAD_LENGTH_AEAD_IV,
    KDF_SALT_CONST_VMESS_HEADER_PAYLOAD_LENGTH_AEAD_KEY, MAX_CHUNK_SIZE, OPTION_CHUNK_STREAM,
    SECURITY_AES_128_GCM, SECURITY_CHACHA20_POLY1305, VERSION, VmessSecurity, new_id,
    vmess_kdf_1_one_shot, vmess_kdf_3_one_shot,
};
use crate::proxy::outbound::{AnyPacket, PacketInfo};
use crate::proxy::router::get_router;
use crate::proxy::{SourceAddr, TargetAddr};

pub struct VmessInbound {
    tag: String,
    address: SocketAddr,
    idle_timeout: Duration,
    users: Arc<ArcSwap<Vec<AuthUser>>>,
}

impl VmessInbound {
    pub fn new(tag: String, cfg: &InboundConfig, users: Vec<AuthUser>) -> anyhow::Result<Self> {
        if users.is_empty() {
            bail!("vmess inbound '{}' requires at least one uuid", tag);
        }
        for user in &users {
            if uuid::Uuid::parse_str(&user.username).is_err() {
                bail!(
                    "vmess inbound '{}' user '{}' is not a valid uuid",
                    tag,
                    user.username
                );
            }
        }

        Ok(Self {
            tag,
            address: cfg.socket_addr()?,
            idle_timeout: cfg.idle_timeout(),
            users: Arc::new(ArcSwap::from_pointee(users)),
        })
    }

    fn users_snapshot(&self) -> Vec<AuthUser> {
        self.users.load().as_ref().clone()
    }
}

#[async_trait]
impl AnyInbound for VmessInbound {
    fn protocol(&self) -> &str {
        "vmess"
    }

    fn idle_timeout(&self) -> Duration {
        self.idle_timeout
    }

    async fn listen(&self) -> anyhow::Result<()> {
        let listener = create_tcp_listener(self.address)?;
        info!("VMess Inbound listening on {}", self.address);

        loop {
            let (socket, peer_addr) = listener.accept().await?;
            let router = get_router()?;
            let tag = self.tag.clone();
            let users = self.users_snapshot();
            let idle_timeout = self.idle_timeout;

            tokio::spawn(async move {
                let result = tokio::time::timeout(
                    Duration::from_secs(10),
                    handle_client(socket, &tag, &users, idle_timeout),
                )
                .await;
                match result {
                    Ok(Ok(())) => {}
                    Ok(Err(e)) => error!("VMess inbound error from {}: {}", peer_addr, e),
                    Err(_) => error!("VMess handshake timeout from {}", peer_addr),
                }
                let _ = router;
            });
        }
    }

    fn supports_users(&self) -> bool {
        true
    }

    async fn add_user(&self, user: &AuthUser) -> anyhow::Result<()> {
        if uuid::Uuid::parse_str(&user.username).is_err() {
            bail!("vmess user must be a valid uuid: '{}'", user.username);
        }
        let mut users = self.users.load().as_ref().clone();
        match users.iter_mut().find(|u| u.username == user.username) {
            Some(existing) => existing.password = user.password.clone(),
            None => users.push(user.clone()),
        }
        self.users.store(Arc::new(users));
        Ok(())
    }

    async fn remove_user(&self, username: &str) -> anyhow::Result<()> {
        let users: Vec<AuthUser> = self
            .users
            .load()
            .iter()
            .filter(|u| u.username != username)
            .cloned()
            .collect();
        self.users.store(Arc::new(users));
        Ok(())
    }
}

/// Perform the VMess handshake on `stream`: authenticate against `users`, decode
/// the request header and send the response header. The authenticated user is
/// resolved through the Observer (None when the Observer is disabled).
async fn accept<S>(
    mut stream: S,
    tag: &str,
    users: &[AuthUser],
) -> anyhow::Result<(VmessServerStream<S>, Option<UserAccount>)>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    // The header's auth_id binds the payload to a specific uuid's cmd_key, so
    // re-reading after a failed decrypt is impossible; read the fixed prefix
    // once, then try every candidate key against the buffered bytes.
    let mut prefix = BytesMut::new();
    prefix.resize(42, 0); // auth_id(16) + enc_len(18) + nonce(8)
    stream.read_exact(&mut prefix).await?;

    let auth_id: [u8; 16] = prefix[..16].try_into().unwrap();
    let enc_len: [u8; 18] = prefix[16..34].try_into().unwrap();
    let connection_nonce: [u8; 8] = prefix[34..42].try_into().unwrap();

    let mut authenticated: Option<(ID, u16)> = None;
    for user in users {
        let Ok(uuid) = uuid::Uuid::parse_str(&user.username) else {
            continue;
        };
        let id = new_id(&uuid);
        let len_key = &vmess_kdf_3_one_shot(
            &id.cmd_key,
            KDF_SALT_CONST_VMESS_HEADER_PAYLOAD_LENGTH_AEAD_KEY,
            &auth_id,
            &connection_nonce,
        )[..16];
        let len_iv = &vmess_kdf_3_one_shot(
            &id.cmd_key,
            KDF_SALT_CONST_VMESS_HEADER_PAYLOAD_LENGTH_AEAD_IV,
            &auth_id,
            &connection_nonce,
        )[..12];
        if let Ok(plain) = aes_gcm_decrypt(len_key, len_iv, &enc_len, Some(&auth_id))
            && let Some(len) = plain.get(..2)
        {
            authenticated = Some((id, u16::from_be_bytes([len[0], len[1]])));
            break;
        }
    }

    let Some((id, header_len)) = authenticated else {
        bail!("VMess authentication failed");
    };

    let key = &vmess_kdf_3_one_shot(
        &id.cmd_key,
        KDF_SALT_CONST_VMESS_HEADER_PAYLOAD_AEAD_KEY,
        &auth_id,
        &connection_nonce,
    )[..16];
    let iv = &vmess_kdf_3_one_shot(
        &id.cmd_key,
        KDF_SALT_CONST_VMESS_HEADER_PAYLOAD_AEAD_IV,
        &auth_id,
        &connection_nonce,
    )[..12];
    let mut enc_header = vec![0u8; header_len as usize + 16];
    stream.read_exact(&mut enc_header).await?;
    let header = aes_gcm_decrypt(key, iv, &enc_header, Some(&auth_id))
        .context("vmess header payload decrypt")?;

    let request = parse_request(&header)?;
    let user = get_observer().and_then(|o| {
        o.authenticate(tag, &id.cmd_key)
            .map(|(username, stats)| UserAccount {
                username: Arc::from(username.as_str()),
                stats,
            })
    });

    let mut server_stream = VmessServerStream::new(stream, request);
    server_stream.send_response_header().await?;
    Ok((server_stream, user))
}

async fn handle_client(
    socket: tokio::net::TcpStream,
    tag: &str,
    users: &[AuthUser],
    idle_timeout: Duration,
) -> anyhow::Result<()> {
    let peer_addr = socket.peer_addr()?;

    let (stream, user) = accept(socket, tag, users).await?;
    let is_udp = stream.is_udp;

    let router = get_router()?;
    let target = stream.dst.clone();
    if is_udp {
        let in_packet = Arc::new(VmessInboundPacket::new(stream, TargetAddr::Ip(peer_addr)));
        router
            .dispatch_packet(
                in_packet,
                &target,
                &TargetAddr::Ip(peer_addr),
                tag,
                user,
                None,
                idle_timeout,
                None,
            )
            .await
    } else {
        let span = info_span!(
            "tcp",
            i = tag,
            s = peer_addr.to_string(),
            d = field::Empty,
            r = field::Empty,
            o = field::Empty
        );
        router
            .dispatch_stream(Box::new(stream), &target, tag, user)
            .instrument(span)
            .await
    }
}

struct VmessRequest {
    dst: TargetAddr,
    security: u8,
    is_udp: bool,
    req_body_iv: Vec<u8>,
    req_body_key: Vec<u8>,
    resp_v: u8,
}

fn parse_request(header: &[u8]) -> anyhow::Result<VmessRequest> {
    if header.len() < 41 {
        bail!("vmess header too short");
    }
    let mut cur = header;
    let version = cur.get_u8();
    if version != VERSION {
        bail!("unsupported vmess version: {version}");
    }
    let mut req_body_iv = vec![0u8; 16];
    cur.copy_to_slice(&mut req_body_iv);
    let mut req_body_key = vec![0u8; 16];
    cur.copy_to_slice(&mut req_body_key);
    let resp_v = cur.get_u8();
    let _option = cur.get_u8();
    let pad_security = cur.get_u8();
    let padding_len = (pad_security >> 4) as usize;
    let security = pad_security & 0x0F;
    let _reserved = cur.get_u8();
    let cmd = cur.get_u8();

    let end = cur.len().saturating_sub(4 + padding_len);
    let dst = read_vmess_addr(&cur[..end])?;

    Ok(VmessRequest {
        dst,
        security,
        is_udp: cmd == COMMAND_UDP,
        req_body_iv,
        req_body_key,
        resp_v,
    })
}

fn read_vmess_addr(mut buf: &[u8]) -> anyhow::Result<TargetAddr> {
    if buf.len() < 3 {
        bail!("vmess addr too short");
    }
    let port = u16::from_be_bytes([buf[0], buf[1]]);
    let atyp = buf[2];
    buf = &buf[3..];
    let host = match atyp {
        0x01 => {
            if buf.len() < 4 {
                bail!("short ipv4");
            }
            std::net::IpAddr::V4(std::net::Ipv4Addr::new(buf[0], buf[1], buf[2], buf[3]))
        }
        0x02 => {
            if buf.is_empty() {
                bail!("short domain");
            }
            let len = buf[0] as usize;
            if buf.len() < 1 + len {
                bail!("short domain bytes");
            }
            let domain = String::from_utf8_lossy(&buf[1..1 + len]).to_string();
            return Ok(TargetAddr::Domain(domain, port));
        }
        0x03 => {
            if buf.len() < 16 {
                bail!("short ipv6");
            }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&buf[..16]);
            std::net::IpAddr::V6(std::net::Ipv6Addr::from(octets))
        }
        other => bail!("unsupported vmess atyp: {other}"),
    };
    Ok(TargetAddr::Ip(SocketAddr::new(host, port)))
}

// ─── Server stream ───

enum ReadState {
    WaitingLength,
    WaitingData(usize),
    FlushingData(usize),
    Closed,
}

enum WriteState {
    BuildingData,
    FlushingData(usize, (usize, usize)),
}

pub struct VmessServerStream<S> {
    stream: S,
    dst: TargetAddr,
    resp_v: u8,
    is_udp: bool,
    is_aead: bool,

    read_cipher: Option<AeadCipher>,
    write_cipher: Option<AeadCipher>,
    resp_body_key: Vec<u8>,
    resp_body_iv: Vec<u8>,

    read_state: ReadState,
    read_buf: BytesMut,
    write_state: WriteState,
    write_buf: BytesMut,
}

impl<S> VmessServerStream<S> {
    fn new(inner: S, request: VmessRequest) -> Self {
        let VmessRequest {
            dst,
            resp_v,
            req_body_iv,
            req_body_key,
            is_udp,
            security,
        } = request;

        let is_aead = true;
        let (resp_body_key, resp_body_iv) = (
            crate::utils::sha256(req_body_key.as_slice())[0..16].to_vec(),
            crate::utils::sha256(req_body_iv.as_slice())[0..16].to_vec(),
        );

        let (read_cipher, write_cipher) = match security {
            SECURITY_AES_128_GCM => (
                Some(AeadCipher::new(
                    &req_body_iv,
                    VmessSecurity::Aes128Gcm(Aes128Gcm::new_with_slice(&req_body_key)),
                )),
                Some(AeadCipher::new(
                    &resp_body_iv,
                    VmessSecurity::Aes128Gcm(Aes128Gcm::new_with_slice(&resp_body_key)),
                )),
            ),
            SECURITY_CHACHA20_POLY1305 => (
                Some(AeadCipher::new(
                    &req_body_iv,
                    VmessSecurity::ChaCha20Poly1305(ChaCha20Poly1305::new_with_slice(&chacha_key(
                        &req_body_key,
                    ))),
                )),
                Some(AeadCipher::new(
                    &resp_body_iv,
                    VmessSecurity::ChaCha20Poly1305(ChaCha20Poly1305::new_with_slice(&chacha_key(
                        &resp_body_key,
                    ))),
                )),
            ),
            _ => (None, None),
        };

        Self {
            stream: inner,
            dst,
            resp_v,
            is_udp,
            is_aead,
            read_cipher,
            write_cipher,
            resp_body_key,
            resp_body_iv,
            read_state: ReadState::WaitingLength,
            read_buf: BytesMut::new(),
            write_state: WriteState::BuildingData,
            write_buf: BytesMut::new(),
        }
    }
}

impl<S> VmessServerStream<S>
where
    S: AsyncWrite + Unpin,
{
    async fn send_response_header(&mut self) -> anyhow::Result<()> {
        let payload = [self.resp_v, OPTION_CHUNK_STREAM, 0, 0];
        let mut buf = BytesMut::new();
        if self.is_aead {
            let len_key =
                &vmess_kdf_1_one_shot(&self.resp_body_key, KDF_SALT_CONST_AEAD_RESP_HEADER_LEN_KEY)
                    [..16];
            let len_iv =
                &vmess_kdf_1_one_shot(&self.resp_body_iv, KDF_SALT_CONST_AEAD_RESP_HEADER_LEN_IV)
                    [..12];
            buf.put_slice(&aes_gcm_encrypt(
                len_key,
                len_iv,
                &(payload.len() as u16).to_be_bytes(),
                None,
            )?);
            let key = &vmess_kdf_1_one_shot(
                &self.resp_body_key,
                KDF_SALT_CONST_AEAD_RESP_HEADER_PAYLOAD_KEY,
            )[..16];
            let iv = &vmess_kdf_1_one_shot(
                &self.resp_body_iv,
                KDF_SALT_CONST_AEAD_RESP_HEADER_PAYLOAD_IV,
            )[..12];
            buf.put_slice(&aes_gcm_encrypt(key, iv, &payload, None)?);
        } else {
            buf.put_slice(&payload);
        }
        self.stream.write_all(&buf).await?;
        self.stream.flush().await?;
        Ok(())
    }
}

fn chacha_key(key16: &[u8]) -> [u8; 32] {
    let mut key = [0u8; 32];
    key[..16].copy_from_slice(&crate::utils::md5(key16));
    let tmp = crate::utils::md5(&key[..16]);
    key[16..].copy_from_slice(&tmp);
    key
}

impl<S> AsyncRead for VmessServerStream<S>
where
    S: AsyncRead + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            let this = &mut *self;
            match this.read_state {
                ReadState::WaitingLength => {
                    if !ready!(poll_read_exact(
                        &mut this.stream,
                        cx,
                        2,
                        &mut this.read_buf,
                        true
                    ))? {
                        this.read_state = ReadState::Closed;
                        return Poll::Ready(Ok(()));
                    }
                    let len = u16::from_be_bytes(this.read_buf.split().as_ref().try_into().unwrap())
                        as usize;
                    if len > MAX_CHUNK_SIZE {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "vmess chunk too large",
                        )));
                    }
                    this.read_state = ReadState::WaitingData(len);
                }
                ReadState::WaitingData(size) => {
                    ready!(poll_read_exact(
                        &mut this.stream,
                        cx,
                        size,
                        &mut this.read_buf,
                        false
                    ))?;
                    let overhead = this
                        .read_cipher
                        .as_ref()
                        .map(|c| c.security.overhead_len())
                        .unwrap_or(0);
                    if overhead > 0 {
                        if size < overhead {
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                "vmess chunk shorter than tag",
                            )));
                        }
                        let cipher = this.read_cipher.as_mut().unwrap();
                        cipher.decrypt_inplace(&mut this.read_buf).map_err(|e| {
                            io::Error::new(io::ErrorKind::InvalidData, e.to_string())
                        })?;
                        let data_len = size - overhead;
                        this.read_buf.truncate(data_len);
                        this.read_state = ReadState::FlushingData(data_len);
                    } else {
                        this.read_state = ReadState::FlushingData(size);
                    }
                }
                ReadState::FlushingData(size) => {
                    let to_read = std::cmp::min(buf.remaining(), size);
                    let payload = this.read_buf.split_to(to_read);
                    buf.put_slice(&payload);
                    if to_read < size {
                        this.read_state = ReadState::FlushingData(size - to_read);
                    } else {
                        this.read_state = ReadState::WaitingLength;
                    }
                    return Poll::Ready(Ok(()));
                }
                ReadState::Closed => return Poll::Ready(Ok(())),
            }
        }
    }
}

impl<S> AsyncWrite for VmessServerStream<S>
where
    S: AsyncWrite + Unpin,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        loop {
            let this = &mut *self;
            match this.write_state {
                WriteState::BuildingData => {
                    let overhead = this
                        .write_cipher
                        .as_ref()
                        .map(|c| c.security.overhead_len())
                        .unwrap_or(0);
                    let max_payload = CHUNK_SIZE - overhead;
                    let consume = std::cmp::min(buf.len(), max_payload);
                    let payload_len = consume + overhead;

                    this.write_buf.reserve(2 + payload_len);
                    this.write_buf.put_u16(payload_len as u16);
                    let mut piece = this.write_buf.split_off(2);
                    piece.put_slice(&buf[..consume]);
                    if overhead > 0 {
                        piece.extend_from_slice(&vec![0u8; overhead]);
                    }
                    if overhead > 0 {
                        let cipher = this.write_cipher.as_mut().unwrap();
                        cipher
                            .encrypt_inplace(&mut piece)
                            .map_err(io::Error::other)?;
                    }
                    this.write_buf.unsplit(piece);
                    this.write_state = WriteState::FlushingData(consume, (0, this.write_buf.len()));
                }
                WriteState::FlushingData(consume, (written, total)) => {
                    let slice = &this.write_buf[written..total];
                    let n = ready!(Pin::new(&mut this.stream).poll_write(cx, slice))?;
                    if n == 0 {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::WriteZero,
                            "write zero",
                        )));
                    }
                    let new_written = written + n;
                    if new_written < total {
                        this.write_state = WriteState::FlushingData(consume, (new_written, total));
                        cx.waker().wake_by_ref();
                        return Poll::Pending;
                    }
                    this.write_buf.clear();
                    this.write_state = WriteState::BuildingData;
                    return Poll::Ready(Ok(consume));
                }
            }
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

// ─── UDP ───

/// VMess UDP: each session is one stream carrying a single destination's
/// datagrams, so send/recv just move raw payloads on the underlying stream.
struct VmessInboundPacket<S> {
    stream: Mutex<VmessServerStream<S>>,
    client_addr: TargetAddr,
}

impl<S> VmessInboundPacket<S> {
    fn new(stream: VmessServerStream<S>, client_addr: TargetAddr) -> Self {
        Self {
            stream: Mutex::new(stream),
            client_addr,
        }
    }
}

#[async_trait]
impl<S> AnyPacket for VmessInboundPacket<S>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    async fn send_to(
        &self,
        buf: Bytes,
        _from: &SourceAddr,
        _target: &TargetAddr,
    ) -> anyhow::Result<usize> {
        let len = buf.len();
        let mut stream = self.stream.lock().await;
        stream.write_all(&buf).await?;
        stream.flush().await?;
        Ok(len)
    }

    async fn recv_from(&self) -> anyhow::Result<PacketInfo> {
        let mut stream = self.stream.lock().await;
        let mut buf = vec![0u8; 65535];
        let n = stream.read(&mut buf).await?;
        if n == 0 {
            bail!("vmess udp stream closed");
        }
        buf.truncate(n);
        let target = stream.dst.clone();
        Ok((self.client_addr.clone(), target, Bytes::from(buf)))
    }
}

fn poll_read_exact<S: AsyncRead + Unpin>(
    stream: &mut S,
    cx: &mut Context<'_>,
    count: usize,
    buf: &mut BytesMut,
    allow_eof: bool,
) -> Poll<io::Result<bool>> {
    while buf.len() < count {
        let filled = buf.len();
        buf.resize(count, 0);
        let mut read_buf = ReadBuf::new(&mut buf[filled..]);
        match Pin::new(&mut *stream).poll_read(cx, &mut read_buf) {
            Poll::Ready(Ok(())) => {
                let read = read_buf.filled().len();
                buf.truncate(filled + read);
                if read == 0 {
                    if allow_eof && filled == 0 {
                        return Poll::Ready(Ok(false));
                    }
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "unexpected EOF in VMess frame",
                    )));
                }
            }
            Poll::Ready(Err(e)) => {
                buf.truncate(filled);
                return Poll::Ready(Err(e));
            }
            Poll::Pending => {
                buf.truncate(filled);
                return Poll::Pending;
            }
        }
    }
    Poll::Ready(Ok(true))
}

fn aes_gcm_encrypt(
    key: &[u8],
    nonce: &[u8],
    plaintext: &[u8],
    aad: Option<&[u8]>,
) -> anyhow::Result<Vec<u8>> {
    use aes_gcm::aead::Aead;
    let cipher = Aes128Gcm::new_from_slice(key).map_err(|e| anyhow::anyhow!("{e}"))?;
    cipher
        .encrypt(
            aes_gcm::Nonce::from_slice(nonce),
            aes_gcm::aead::Payload {
                msg: plaintext,
                aad: aad.unwrap_or_default(),
            },
        )
        .map_err(|e| anyhow::anyhow!("{e}"))
}

fn aes_gcm_decrypt(
    key: &[u8],
    nonce: &[u8],
    ciphertext: &[u8],
    aad: Option<&[u8]>,
) -> anyhow::Result<Vec<u8>> {
    use aes_gcm::aead::Aead;
    let cipher = Aes128Gcm::new_from_slice(key).map_err(|e| anyhow::anyhow!("{e}"))?;
    cipher
        .decrypt(
            aes_gcm::Nonce::from_slice(nonce),
            aes_gcm::aead::Payload {
                msg: ciphertext,
                aad: aad.unwrap_or_default(),
            },
        )
        .map_err(|e| anyhow::anyhow!("{e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proxy::outbound::vmess::vmess_impl::{Builder, VmessOption};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn user(uuid: &str) -> AuthUser {
        AuthUser {
            username: uuid.to_string(),
            password: uuid.to_string(),
        }
    }

    /// Round-trip a payload through the client handshake + server accept, then
    /// echo it back through both sides' stream ciphers.
    async fn round_trip(uuid: &str, security: &str, payload: &[u8]) {
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let (client_rd, client_wr) = tokio::io::split(client_io);
        let (server_rd, server_wr) = tokio::io::split(server_io);

        let users = vec![user(uuid)];

        let client = async {
            let stream: crate::proxy::outbound::AnyStream = Box::new(DuplexHalf {
                rd: client_rd,
                wr: client_wr,
            });
            let opt = VmessOption {
                uuid: uuid.to_string(),
                alter_id: 0,
                security: security.to_string(),
                udp: false,
                dst: TargetAddr::Domain("example.com".to_string(), 443),
            };
            let builder = Builder::new(&opt).unwrap();
            let mut vmess = builder.proxy_stream(stream).await.unwrap();
            vmess.write_all(payload).await.unwrap();
            vmess.flush().await.unwrap();
            let mut echo = vec![0u8; payload.len()];
            vmess.read_exact(&mut echo).await.unwrap();
            assert_eq!(&echo, payload);
        };

        let server = async {
            let stream = DuplexHalf {
                rd: server_rd,
                wr: server_wr,
            };
            let (mut server_stream, _user) = accept(stream, "vmess-in", &users).await.unwrap();
            assert_eq!(server_stream.dst.to_string(), "example.com:443");
            let mut buf = vec![0u8; payload.len()];
            server_stream.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, payload);
            server_stream.write_all(payload).await.unwrap();
            server_stream.flush().await.unwrap();
        };

        tokio::join!(client, server);
    }

    /// A duplex half that implements `AnyStream` (AsyncRead + AsyncWrite).
    struct DuplexHalf {
        rd: tokio::io::ReadHalf<tokio::io::DuplexStream>,
        wr: tokio::io::WriteHalf<tokio::io::DuplexStream>,
    }

    impl AsyncRead for DuplexHalf {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Pin::new(&mut self.rd).poll_read(cx, buf)
        }
    }

    impl AsyncWrite for DuplexHalf {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            Pin::new(&mut self.wr).poll_write(cx, buf)
        }
        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.wr).poll_flush(cx)
        }
        fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.wr).poll_shutdown(cx)
        }
    }

    const UUID: &str = "b831381d-6324-4d53-ad4f-8cda48b30811";

    #[tokio::test]
    async fn aes_gcm_round_trip() {
        round_trip(UUID, "aes-128-gcm", b"hello vmess").await;
    }

    #[tokio::test]
    async fn chacha20_round_trip() {
        round_trip(UUID, "chacha20-poly1305", b"hello vmess").await;
    }

    #[tokio::test]
    async fn none_security_round_trip() {
        round_trip(UUID, "none", b"hello vmess").await;
    }

    #[tokio::test]
    async fn wrong_uuid_is_rejected() {
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let (client_rd, client_wr) = tokio::io::split(client_io);
        let (server_rd, server_wr) = tokio::io::split(server_io);

        // Server only knows a different uuid.
        let users = vec![user("11111111-1111-1111-1111-111111111111")];

        let client = async {
            let stream: crate::proxy::outbound::AnyStream = Box::new(DuplexHalf {
                rd: client_rd,
                wr: client_wr,
            });
            let opt = VmessOption {
                uuid: UUID.to_string(),
                alter_id: 0,
                security: "aes-128-gcm".to_string(),
                udp: false,
                dst: TargetAddr::Domain("example.com".to_string(), 443),
            };
            let builder = Builder::new(&opt).unwrap();
            // Handshake write succeeds; the server rejects it.
            let _ = builder.proxy_stream(stream).await;
        };

        let server = async {
            let stream = DuplexHalf {
                rd: server_rd,
                wr: server_wr,
            };
            let result = accept(stream, "vmess-in", &users).await;
            assert!(result.is_err(), "unknown uuid must not authenticate");
        };

        tokio::join!(client, server);
    }

    #[tokio::test]
    async fn second_configured_user_authenticates() {
        let other = "11111111-1111-1111-1111-111111111111";
        let users = vec![user(other), user(UUID)];
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let (client_rd, client_wr) = tokio::io::split(client_io);
        let (server_rd, server_wr) = tokio::io::split(server_io);

        let client = async {
            let stream: crate::proxy::outbound::AnyStream = Box::new(DuplexHalf {
                rd: client_rd,
                wr: client_wr,
            });
            let opt = VmessOption {
                uuid: UUID.to_string(),
                alter_id: 0,
                security: "aes-128-gcm".to_string(),
                udp: false,
                dst: TargetAddr::Domain("example.com".to_string(), 443),
            };
            let builder = Builder::new(&opt).unwrap();
            let mut vmess = builder.proxy_stream(stream).await.unwrap();
            vmess.write_all(b"x").await.unwrap();
            vmess.flush().await.unwrap();
        };

        let server = async {
            let stream = DuplexHalf {
                rd: server_rd,
                wr: server_wr,
            };
            let (mut server_stream, _) = accept(stream, "vmess-in", &users).await.unwrap();
            let mut b = [0u8; 1];
            server_stream.read_exact(&mut b).await.unwrap();
            assert_eq!(&b, b"x");
        };

        tokio::join!(client, server);
    }

    #[test]
    fn parse_request_decodes_domain_target() {
        // version | iv(16) | key(16) | resp_v | option | pad<<4|security | 0 | cmd | addr | pad | crc
        let mut h = Vec::new();
        h.push(VERSION);
        h.extend_from_slice(&[0u8; 16]);
        h.extend_from_slice(&[0u8; 16]);
        h.push(7); // resp_v
        h.push(OPTION_CHUNK_STREAM);
        h.push(SECURITY_AES_128_GCM); // padding 0
        h.push(0);
        h.push(1); // COMMAND_TCP
        // domain addr: port(2) | atyp(1) | len(1) | bytes
        h.extend_from_slice(&443u16.to_be_bytes());
        h.push(0x02); // domain
        h.push(11);
        h.extend_from_slice(b"example.com");
        h.extend_from_slice(&[0u8; 4]); // crc

        let req = parse_request(&h).unwrap();
        assert_eq!(req.dst.to_string(), "example.com:443");
        assert!(req.dst.port() == 443);
        assert!(!req.is_udp);
    }
}
