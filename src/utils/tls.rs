//! TLS setup shared by the TCP-based protocols (Trojan, AnyTLS) and the QUIC wrapper.

use std::fs::File;
use std::io::{self, BufReader};
use std::sync::Arc;

use anyhow::Result;
use tokio_rustls::rustls;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};

use crate::proxy::{TlsConfig, configure_jls_client, configure_jls_server};
use crate::utils::new_io_other_error;

pub fn load_certs(path: &str) -> io::Result<Vec<CertificateDer<'static>>> {
    let file = File::open(path).map_err(|e| {
        io::Error::new(
            e.kind(),
            format!("failed to open certificate file {path}: {e}"),
        )
    })?;
    rustls_pemfile::certs(&mut BufReader::new(file))
        .map(|cert| cert.map(|c| c.into_owned()))
        .collect()
}

pub fn load_key(path: &str) -> io::Result<PrivateKeyDer<'static>> {
    let file = File::open(path)
        .map_err(|e| io::Error::new(e.kind(), format!("failed to open key file {path}: {e}")))?;
    rustls_pemfile::private_key(&mut BufReader::new(file))?
        .ok_or_else(|| new_io_other_error(format!("no private key found in {path}")))
}

/// A throwaway certificate for `localhost`, for servers configured without one.
pub fn self_signed_localhost() -> io::Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)>
{
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
        .map_err(|e| new_io_other_error(format!("Failed to generate cert: {}", e)))?;
    let key = PrivateKeyDer::try_from(cert.signing_key.serialize_der())
        .map_err(|e| new_io_other_error(format!("Invalid private key: {}", e)))?;
    Ok((vec![CertificateDer::from(cert.cert.der().to_vec())], key))
}

/// Client config for a TLS outbound: the configured CA (or the webpki roots), or no
/// verification at all when `insecure` is set, plus JLS when enabled.
pub fn client_config(tls: &TlsConfig) -> Result<rustls::ClientConfig> {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let mut config = if tls.insecure {
        let mut config = crate::utils::ntp::tls::client_builder()
            .with_root_certificates(rustls::RootCertStore::empty())
            .with_no_client_auth();
        config
            .dangerous()
            .set_certificate_verifier(Arc::new(SkipServerVerification));
        config
    } else {
        let mut root_store = rustls::RootCertStore::empty();
        match tls.cert.as_deref() {
            Some(cert_path) => {
                for cert in load_certs(cert_path)? {
                    root_store.add(cert).map_err(new_io_other_error)?;
                }
            }
            None => root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned()),
        }
        crate::utils::ntp::tls::client_builder()
            .with_root_certificates(root_store)
            .with_no_client_auth()
    };
    configure_jls_client(&mut config, tls);
    Ok(config)
}

/// Server config for a TLS inbound: the configured cert and key, or a self-signed
/// `localhost` certificate when either is missing, plus JLS when enabled.
pub fn server_config(tls: &TlsConfig, protocol: &str) -> Result<rustls::ServerConfig> {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let (certs, key) = match (&tls.cert, &tls.key) {
        (Some(cert_path), Some(key_path)) => (load_certs(cert_path)?, load_key(key_path)?),
        _ => {
            tracing::info!("{protocol} inbound: no TLS cert configured, using a self-signed one");
            self_signed_localhost()?
        }
    };
    let mut config = crate::utils::ntp::tls::server_builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| new_io_other_error(format!("TLS config error: {}", e)))?;
    configure_jls_server(&mut config, tls);
    Ok(config)
}

/// Accepts any server certificate. Only for outbounds configured as `insecure`.
#[derive(Debug)]
pub struct SkipServerVerification;

impl rustls::client::danger::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ED25519,
        ]
    }
}
