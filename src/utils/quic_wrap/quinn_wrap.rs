use anyhow::{Context as _, bail};
use quinn::rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::net::{IpAddr, SocketAddr};
use std::pin::{Pin, pin};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;
use quinn::{
    ClientConfig, MtuDiscoveryConfig, RecvStream, SendStream, ServerConfig, TransportConfig, VarInt,
};
use std::io;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::mpsc;

use tracing::{debug, error, info, trace, warn};

use crate::utils::new_io_other_error;
use crate::utils::socket::socket_helpers::try_create_dualstack_udpsocket;

use super::{QuicBistream, QuicConnection, QuicUnistream};

// 300Mbps has a bandwidth-delay product of about 3.75MB at 100ms RTT. These
// windows leave enough headroom for that workload while keeping each QUIC
// connection's stream buffering bounded under the Network Extension budget.
#[cfg(target_os = "ios")]
const STREAM_RECEIVE_WINDOW: u32 = 4 * 1024 * 1024;
#[cfg(target_os = "ios")]
const CONNECTION_RECEIVE_WINDOW: u32 = 8 * 1024 * 1024;
#[cfg(target_os = "ios")]
const SEND_WINDOW: u64 = 8 * 1024 * 1024;

#[cfg(target_os = "ios")]
const ACCEPT_CONNECTION_QUEUE_CAPACITY: usize = 64;
#[cfg(not(target_os = "ios"))]
const ACCEPT_CONNECTION_QUEUE_CAPACITY: usize = 200;

/// Advertised limit for concurrent QUIC streams (unidirectional and
/// bidirectional), on the client and the server alike. ShadowQUIC's
/// UDP-over-stream mode opens one uni-directional stream per distinct UDP peer
/// on a connection and keeps it cached, so the quinn default (100) is far too
/// small: Connection::open_uni then blocks forever once the peer's advertised
/// budget is exhausted, stalling the whole UDP session. A stream limit is only
/// a number advertised in the transport parameters -- memory is consumed per
/// actually-opened stream -- so it can be generous.
const DEFAULT_MAX_CONCURRENT_STREAMS: u32 = 1000;

fn keep_alive_interval_for(idle_timeout: Duration) -> Option<Duration> {
    if idle_timeout.is_zero() {
        return None;
    }

    Some(std::cmp::max(idle_timeout / 2, Duration::from_secs(1)))
}

fn make_transport_config(
    idle_timeout: Duration,
    congestion_controller: Option<&str>,
    enable_gso: bool,
    enable_mtudis: bool,
    initial_mtu: u16,
    min_mtu: u16,
) -> TransportConfig {
    let mut transport_config = TransportConfig::default();

    if idle_timeout.is_zero() {
        transport_config.max_idle_timeout(None);
        transport_config.keep_alive_interval(None);
    } else {
        let timeout_ms = u32::try_from(idle_timeout.as_millis()).unwrap_or(u32::MAX);
        transport_config.max_idle_timeout(Some(VarInt::from_u32(timeout_ms).into()));
        transport_config.keep_alive_interval(keep_alive_interval_for(idle_timeout));
    }

    transport_config.enable_segmentation_offload(enable_gso);
    transport_config.initial_mtu(initial_mtu);
    transport_config.min_mtu(min_mtu);

    #[cfg(target_os = "ios")]
    {
        transport_config.stream_receive_window(VarInt::from_u32(STREAM_RECEIVE_WINDOW));
        transport_config.receive_window(VarInt::from_u32(CONNECTION_RECEIVE_WINDOW));
        transport_config.send_window(SEND_WINDOW);
    }

    transport_config.max_concurrent_bidi_streams(DEFAULT_MAX_CONCURRENT_STREAMS.into());
    transport_config.max_concurrent_uni_streams(DEFAULT_MAX_CONCURRENT_STREAMS.into());

    let mtudis = if enable_mtudis {
        let mut config = MtuDiscoveryConfig::default();
        config.black_hole_cooldown(Duration::from_secs(120));
        config.interval(Duration::from_secs(90));
        Some(config)
    } else {
        None
    };
    transport_config.mtu_discovery_config(mtudis);

    let cc_name = congestion_controller.unwrap_or("bbr").to_ascii_lowercase();
    let cc_factory: Arc<dyn quinn::congestion::ControllerFactory + Send + Sync> =
        match cc_name.as_str() {
            "bbr" => Arc::new(quinn::congestion::BbrConfig::default()),
            "cubic" => Arc::new(quinn::congestion::CubicConfig::default()),
            "newreno" => Arc::new(quinn::congestion::NewRenoConfig::default()),
            other => {
                warn!("unknown congestion controller '{}', falling back to bbr", other);
                Arc::new(quinn::congestion::BbrConfig::default())
            }
        };
    transport_config.congestion_controller_factory(cc_factory);

    transport_config
}

pub struct QuinnUnistream {
    pub send: SendStream,
}

impl QuinnUnistream {
    pub fn new(send: SendStream) -> Self {
        QuinnUnistream { send }
    }
}

impl AsyncWrite for QuinnUnistream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        pin!(&mut self.send).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        pin!(&mut self.send).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        pin!(&mut self.send).poll_shutdown(cx)
    }
}

#[async_trait]
impl QuicUnistream for QuinnUnistream {}

pub struct QuinnBistream {
    pub send: SendStream,
    pub recv: RecvStream,
}

impl QuinnBistream {
    pub fn new(send: SendStream, recv: RecvStream) -> Self {
        QuinnBistream { send, recv }
    }
}

impl AsyncRead for QuinnBistream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        Pin::new(&mut self.as_mut().recv).poll_read(cx, buf)
    }
}

impl AsyncWrite for QuinnBistream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<Result<usize, std::io::Error>> {
        Pin::new(&mut self.as_mut().send)
            .poll_write(cx, buf)
            .map_err(io::Error::from)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.as_mut().send).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.as_mut().send).poll_shutdown(cx)
    }
}

#[async_trait]
impl QuicBistream for QuinnBistream {}

#[derive(Clone)]
pub struct QuinnConnection {
    pub connection: Box<quinn::Connection>,
}

impl QuinnConnection {
    pub fn new(connection: Box<quinn::Connection>) -> Self {
        QuinnConnection { connection }
    }
}

#[async_trait]
impl QuicConnection for QuinnConnection {
    async fn packet_loss_rate(&self) -> f32 {
        let stats = self.connection.stats();
        stats.path.lost_packets as f32 / (stats.path.sent_packets + 1) as f32
    }

    async fn rtt(&self) -> Option<Duration> {
        Some(self.connection.rtt())
    }

    async fn mtu(&self) -> u16 {
        let stats = self.connection.stats();
        stats.path.current_mtu
    }

    fn peer_addr(&self) -> SocketAddr {
        self.connection.remote_address()
    }

    fn local_ip(&self) -> Option<IpAddr> {
        self.connection.local_ip()
    }

    async fn shutdown(&self) -> io::Result<()> {
        self.connection.close(0u32.into(), b"");
        Ok(())
    }

    async fn is_closed(&self) -> io::Result<bool> {
        Ok(self.connection.close_reason().is_some())
    }

    async fn accept_unistream(&self) -> io::Result<Box<dyn QuicUnistream>> {
        let (send, _recv) = self.connection.accept_bi().await?;
        Ok(Box::new(QuinnUnistream::new(send)))
    }

    async fn open_unistream(&self) -> io::Result<Box<dyn QuicUnistream>> {
        let send = self.connection.open_uni().await?;
        Ok(Box::new(QuinnUnistream::new(send)))
    }

    async fn accept_bistream(&self) -> io::Result<Box<dyn QuicBistream>> {
        let (send, recv) = self.connection.accept_bi().await?;
        let bistream = QuinnBistream::new(send, recv);
        Ok(Box::new(bistream))
    }

    async fn open_bistream(&self) -> io::Result<Box<dyn QuicBistream>> {
        let (send, recv) = self.connection.open_bi().await?;
        let bistream = QuinnBistream::new(send, recv);
        Ok(Box::new(bistream))
    }

    async fn read_datagram(&self) -> io::Result<Bytes> {
        Ok(self.connection.read_datagram().await?)
    }

    async fn send_datagram(&self, data: Bytes) -> io::Result<bool> {
        self.connection
            .send_datagram(data)
            .map_err(io::Error::other)?;
        Ok(true)
    }
}

pub struct QuinnServer {
    accept_connection_rx: mpsc::Receiver<Arc<quinn::Connection>>,
    // The accept task holds its own endpoint clone; keeping one here lets Drop
    // close the endpoint, which stops the listener and ends the accept task.
    endpoint: quinn::Endpoint,
}

impl QuinnServer {
    pub fn new(
        addr: SocketAddr,
        idle_timeout: Duration,
        cert_path: Option<&str>,
        key_path: Option<&str>,
        congestion_controller: Option<String>,
        sni: Option<String>,
        alpn: Option<Vec<String>>,
        zero_rtt: bool,
        jls_username: String,
        jls_password: String,
        is_jls: bool,
        enable_gso: bool,
        enable_mtudis: bool,
        initial_mtu: u16,
        min_mtu: u16,
    ) -> anyhow::Result<Self> {
        let server_name = sni.as_deref().unwrap_or("apple.com");
        let mut server_config = if is_jls {
            let mut jls_config = quinn::rustls::jls::JlsServerConfig::default();
            jls_config = jls_config
                .enable(true)
                .add_user(jls_password, jls_username)
                .with_server_name(server_name.to_string());

            // JLS encrypts the handshake with a PSK, so the certificate only
            // satisfies rustls' structure and a self-signed one is fine.
            let (cert_chain, private_key) = generate_self_signed_cert()?;

            let mut config = quinn::rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(cert_chain, private_key)?;
            config.jls_config = jls_config.into();

            config.alpn_protocols = alpn
                .unwrap_or_default()
                .into_iter()
                .map(|s| s.into_bytes())
                .collect();
            config.max_early_data_size = if zero_rtt { u32::MAX } else { 0 };
            config.send_half_rtt_data = zero_rtt;
            let quic_server_config = quinn::crypto::rustls::QuicServerConfig::try_from(config)?;
            ServerConfig::with_crypto(Arc::new(quic_server_config))
        } else {
            let (certs, key) = if let (Some(cp), Some(kp)) = (cert_path, key_path) {
                (load_certs(cp)?, load_keys(kp)?)
            } else {
                tracing::info!(
                    "No TLS cert configured for QUIC, generating default self-signed certificate"
                );
                generate_self_signed_cert()?
            };

            ServerConfig::with_single_cert(certs, key)?
        };
        let transport_config = make_transport_config(
            idle_timeout,
            congestion_controller.as_deref(),
            enable_gso,
            enable_mtudis,
            initial_mtu,
            min_mtu,
        );

        server_config.transport_config(Arc::new(transport_config));

        let socket = try_create_dualstack_udpsocket(addr)?;
        let runtime =
            quinn::default_runtime().ok_or_else(|| io::Error::other("no async runtime found"))?;
        let endpoint = quinn::Endpoint::new(
            quinn::EndpointConfig::default(),
            Some(server_config),
            socket,
            runtime,
        )?;

        let (tx, rx): (
            mpsc::Sender<Arc<quinn::Connection>>,
            mpsc::Receiver<Arc<quinn::Connection>>,
        ) = mpsc::channel(ACCEPT_CONNECTION_QUEUE_CAPACITY);

        let accept_endpoint = endpoint.clone();
        tokio::spawn(async move {
            while let Some(incoming) = accept_endpoint.accept().await {
                let tx = tx.clone();
                tokio::spawn(async move {
                    match incoming.await {
                        Ok(connection) => {
                            let _ = tx.send(Arc::new(connection)).await;
                        }
                        Err(e) => {
                            debug!("incoming handshake failed: {}", e);
                        }
                    }
                });
            }
            info!("quic server endpoint quit");
        });

        Ok(Self {
            accept_connection_rx: rx,
            endpoint,
        })
    }

    // accept new connection.
    pub async fn accept(&mut self) -> io::Result<Arc<quinn::Connection>> {
        self.accept_connection_rx
            .recv()
            .await
            .ok_or(new_io_other_error("Listener closed"))
    }
}

impl Drop for QuinnServer {
    fn drop(&mut self) {
        self.endpoint.close(0u32.into(), b"");
    }
}

fn generate_self_signed_cert(
) -> io::Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
        .map_err(|e| new_io_other_error(format!("Failed to generate cert: {}", e)))?;
    let cert_der = cert.cert.der().to_vec();
    let key_der = cert.signing_key.serialize_der();
    let cert_chain = vec![CertificateDer::from(cert_der)];
    let private_key = PrivateKeyDer::try_from(key_der)
        .map_err(|e| new_io_other_error(format!("Invalid private key: {}", e)))?;
    Ok((cert_chain, private_key))
}

// Helpers for certs
fn load_certs(path: &str) -> io::Result<Vec<quinn::rustls::pki_types::CertificateDer<'static>>> {
    let file = std::fs::File::open(path)?;
    let mut reader = std::io::BufReader::new(file);
    rustls_pemfile::certs(&mut reader)
        .map(|result| result.map(|c| c.into_owned()))
        .collect()
}

fn load_keys(path: &str) -> io::Result<PrivateKeyDer<'static>> {
    let file = std::fs::File::open(path)?;
    let mut reader = std::io::BufReader::new(file);
    let key = rustls_pemfile::private_key(&mut reader)?;
    key.ok_or(new_io_other_error("No private key found"))
}

#[derive(Clone)]
pub struct QuinnClient {
    endpoint: quinn::Endpoint,
    is_jls: bool,
    zero_rtt: bool,
    sni: String,
}

impl QuinnClient {
    /// Build the crypto + transport client configuration.
    ///
    /// This is the expensive part of client creation (cert loading, rustls
    /// setup). It does not depend on the local UDP socket, so callers that
    /// reconnect repeatedly should build it once and reuse it across
    /// reconnects via [`QuinnClient::from_config`].
    ///
    /// Returns the config plus the resolved server name (SNI with the default
    /// fallback applied).
    pub fn build_client_config(
        idle_timeout: Duration,
        verify_peer: bool,
        zero_rtt: bool,
        ca_cert_path: Option<&str>,
        sni: Option<String>,
        alpn: Option<Vec<String>>,
        congestion_controller: Option<String>,
        username: String,
        password: String,
        is_jls: bool,
        enable_gso: bool,
        enable_mtudis: bool,
        initial_mtu: u16,
        min_mtu: u16,
    ) -> anyhow::Result<(Arc<ClientConfig>, String)> {
        let server_name = sni.unwrap_or_else(|| "apple.com".to_string());
        let mut client_crypto = if is_jls {
            let mut config = quinn::rustls::ClientConfig::builder()
                .with_root_certificates(quinn::rustls::RootCertStore::empty())
                .with_no_client_auth();

            config.jls_config.enable = true;
            config.jls_config.user = quinn::rustls::jls::JlsUser::new(&password, &username);
            config
        } else {
            let mut root_store = quinn::rustls::RootCertStore::empty();
            if verify_peer {
                root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
                if let Some(cert_path) = ca_cert_path {
                    for cert in load_certs(cert_path)
                        .with_context(|| format!("Failed to load CA cert from {}", cert_path))?
                    {
                        root_store
                            .add(cert)
                            .context("Failed to add CA cert to root store")?;
                    }
                }
            }

            let mut config = quinn::rustls::ClientConfig::builder()
                .with_root_certificates(root_store)
                .with_no_client_auth();

            if !verify_peer {
                config
                    .dangerous()
                    .set_certificate_verifier(Arc::new(SkipServerVerification));
            }
            config
        };

        client_crypto.enable_early_data = zero_rtt;
        client_crypto.alpn_protocols = alpn
            .unwrap_or_default()
            .into_iter()
            .map(|s| s.into_bytes())
            .collect();

        let quic_client_config = quinn::crypto::rustls::QuicClientConfig::try_from(client_crypto)
            .context("Failed to build QUIC client TLS config")?;
        let mut client_config = ClientConfig::new(Arc::new(quic_client_config));
        let transport_config = make_transport_config(
            idle_timeout,
            congestion_controller.as_deref(),
            enable_gso,
            enable_mtudis,
            initial_mtu,
            min_mtu,
        );

        client_config.transport_config(Arc::new(transport_config));

        Ok((Arc::new(client_config), server_name))
    }

    /// Create a client on a fresh UDP socket from a config previously built by
    /// [`QuinnClient::build_client_config`].
    pub fn from_config(
        socket: std::net::UdpSocket,
        client_config: Arc<ClientConfig>,
        sni: String,
        zero_rtt: bool,
        is_jls: bool,
    ) -> anyhow::Result<Self> {
        let runtime =
            quinn::default_runtime().ok_or_else(|| io::Error::other("no async runtime found"))?;
        let endpoint =
            quinn::Endpoint::new(quinn::EndpointConfig::default(), None, socket, runtime)
                .context("Failed to create QUIC endpoint")?;
        endpoint.set_default_client_config((*client_config).clone());

        Ok(Self {
            endpoint,
            is_jls,
            sni,
            zero_rtt,
        })
    }

    pub fn new(
        socket: std::net::UdpSocket,
        idle_timeout: Duration,
        verify_peer: bool,
        zero_rtt: bool,
        ca_cert_path: Option<&str>,
        sni: Option<String>,
        alpn: Option<Vec<String>>,
        congestion_controller: Option<String>,
        username: String,
        password: String,
        is_jls: bool,
        enable_gso: bool,
        enable_mtudis: bool,
        initial_mtu: u16,
        min_mtu: u16,
    ) -> anyhow::Result<Self> {
        let (client_config, server_name) = Self::build_client_config(
            idle_timeout,
            verify_peer,
            zero_rtt,
            ca_cert_path,
            sni,
            alpn,
            congestion_controller,
            username,
            password,
            is_jls,
            enable_gso,
            enable_mtudis,
            initial_mtu,
            min_mtu,
        )?;
        Self::from_config(socket, client_config, server_name, zero_rtt, is_jls)
    }

    pub async fn connect(&self, remote_addr: SocketAddr) -> anyhow::Result<Arc<quinn::Connection>> {
        let conn = self.endpoint.connect(remote_addr, &self.sni)?;
        let raw_conn = if self.zero_rtt {
            match conn.into_0rtt() {
                Ok((x, accepted)) => {
                    let conn_clone = x.clone();
                    let is_jls_clone = self.is_jls;
                    tokio::spawn(async move {
                        info!("zero rtt accepted: {}", accepted.await);
                        if is_jls_clone && conn_clone.is_jls() == Some(false) {
                            error!("JLS hijacked or wrong pwd/iv");
                            conn_clone.close(0u8.into(), b"");
                        }
                    });
                    trace!("trying 0-rtt quic connection");
                    x
                }
                Err(e) => {
                    let x = e.await?;
                    info!("1-rtt quic connection established");
                    x
                }
            }
        } else {
            let x = conn.await?;
            info!("1-rtt quic connection established");
            x
        };

        if self.is_jls && raw_conn.is_jls() == Some(false) {
            raw_conn.close(0u8.into(), b"");
            bail!("JLS hijacked or wrong pwd/iv");
        }

        Ok(Arc::new(raw_conn))
    }
}

#[derive(Debug)]
struct SkipServerVerification;

impl quinn::rustls::client::danger::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &quinn::rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[quinn::rustls::pki_types::CertificateDer<'_>],
        _server_name: &quinn::rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: quinn::rustls::pki_types::UnixTime,
    ) -> Result<quinn::rustls::client::danger::ServerCertVerified, quinn::rustls::Error> {
        Ok(quinn::rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &quinn::rustls::pki_types::CertificateDer<'_>,
        _dss: &quinn::rustls::DigitallySignedStruct,
    ) -> Result<quinn::rustls::client::danger::HandshakeSignatureValid, quinn::rustls::Error> {
        Ok(quinn::rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &quinn::rustls::pki_types::CertificateDer<'_>,
        _signature: &quinn::rustls::DigitallySignedStruct,
    ) -> Result<quinn::rustls::client::danger::HandshakeSignatureValid, quinn::rustls::Error> {
        Ok(quinn::rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<quinn::rustls::SignatureScheme> {
        vec![
            quinn::rustls::SignatureScheme::RSA_PSS_SHA256,
            quinn::rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            quinn::rustls::SignatureScheme::ED25519,
        ]
    }
}
