use anyhow::Context;
use std::sync::{Arc, LazyLock};
use std::time::{Duration, Instant};

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::client::conn::http1;
use hyper::header::LOCATION;
use hyper::http::{Method, Request, StatusCode};
use hyper::{HeaderMap, Response};
use hyper_util::rt::TokioIo;
use tokio_rustls::TlsConnector;
use tokio_rustls::rustls;
use tracing::debug;

use crate::dns::{get_default_dns, get_dns_by_tag};
use crate::proxy::TargetAddr;
use crate::proxy::outbound::{AnyOutbound, AnyStream};

pub struct OutboundHttpResponse {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub body: Bytes,
}

async fn maybe_wrap_tls(
    url: &reqwest::Url,
    host: &str,
    stream: AnyStream,
) -> anyhow::Result<AnyStream> {
    if url.scheme() != "https" {
        return Ok(stream);
    }

    let server_name = rustls::pki_types::ServerName::try_from(host)
        .map_err(|e| anyhow::anyhow!("{e}"))?
        .to_owned();
    let tls_stream = HTTPS_CONNECTOR.connect(server_name, stream).await?;
    Ok(Box::new(tls_stream))
}

/// Shared by every request, so the root store is built once and TLS sessions can resume.
static HTTPS_CONNECTOR: LazyLock<TlsConnector> = LazyLock::new(|| {
    let mut root_store = rustls::RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    TlsConnector::from(Arc::new(https_client_config(root_store)))
});

fn https_client_config(root_store: rustls::RootCertStore) -> rustls::ClientConfig {
    crate::utils::ntp::tls::client_builder()
        .with_root_certificates(root_store)
        .with_no_client_auth()
}

async fn request_once_with_body(
    outbound: Arc<dyn AnyOutbound>,
    dns: Option<&str>,
    method: Method,
    url: reqwest::Url,
    user_agent: Option<&str>,
    headers: Option<&HeaderMap>,
    body: Bytes,
) -> anyhow::Result<(OutboundHttpResponse, reqwest::Url)> {
    debug!("sending http request to {} via {}", url, outbound.tag());
    let host = url.host_str().context("URL missing host")?;
    let port = url
        .port_or_known_default()
        .context("URL missing known port")?;

    let target = {
        let dns_server = match dns {
            Some(tag) => get_dns_by_tag(tag)?,
            None => get_default_dns()?,
        };
        let ip = dns_server
            .lookup(host, false, &outbound)
            .await?
            .into_iter()
            .next()
            .context("DNS lookup returned no results")?;
        TargetAddr::Ip(std::net::SocketAddr::new(ip, port))
    };
    let stream = outbound
        .connect_stream(&target)
        .await
        .context("http connect_stream")?;
    let stream = maybe_wrap_tls(&url, host, stream).await?;

    let (mut sender, connection) = http1::handshake(TokioIo::new(stream))
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?;

    tokio::spawn(async move {
        let _ = connection.await;
    });

    let mut path = url.path().to_string();
    if path.is_empty() {
        path.push('/');
    }
    if let Some(query) = url.query() {
        path.push('?');
        path.push_str(query);
    }

    let mut request_builder = Request::builder()
        .method(method)
        .uri(path)
        .header("Host", host)
        .header(
            "User-Agent",
            user_agent.unwrap_or("quicproxy/sing-box/clash"),
        )
        .header("Accept", "*/*")
        .header("Accept-Encoding", "identity")
        .header("Connection", "close")
        .header("Content-Length", body.len().to_string());

    // Add custom headers if provided
    if let Some(custom_headers) = headers {
        for (key, value) in custom_headers.iter() {
            request_builder = request_builder.header(key, value);
        }
    }

    let request = request_builder
        .body(Full::new(body))
        .map_err(|e| anyhow::anyhow!("{e}"))?;

    let response = sender
        .send_request(request)
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    let status = response.status();
    let headers = response.headers().clone();
    let body = collect_body(response).await?;

    Ok((
        OutboundHttpResponse {
            status,
            headers,
            body,
        },
        url,
    ))
}

async fn request_once(
    outbound: Arc<dyn AnyOutbound>,
    method: Method,
    url: reqwest::Url,
    user_agent: Option<&str>,
    headers: Option<&HeaderMap>,
) -> anyhow::Result<(OutboundHttpResponse, reqwest::Url)> {
    request_once_with_body(
        outbound.clone(),
        outbound.dns_server_name(),
        method,
        url,
        user_agent,
        headers,
        Bytes::new(),
    )
    .await
}

async fn collect_body(response: Response<Incoming>) -> anyhow::Result<Bytes> {
    response
        .into_body()
        .collect()
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))
        .map(|c| c.to_bytes())
}

pub async fn request_via_outbound_with_dns(
    outbound: Arc<dyn AnyOutbound>,
    dns: Option<&str>,
    method: Method,
    url: &str,
    timeout: Duration,
    max_redirects: usize,
    headers: Option<&HeaderMap>,
) -> anyhow::Result<OutboundHttpResponse> {
    tokio::time::timeout(timeout, async move {
        let mut current = reqwest::Url::parse(url).context("Invalid URL")?;
        let mut current_method = method.clone();

        for _ in 0..=max_redirects {
            let (response, base_url) = request_once_with_body(
                outbound.clone(),
                dns.or_else(|| outbound.dns_server_name()),
                current_method.clone(),
                current.clone(),
                None,
                headers,
                Bytes::new(),
            )
            .await?;

            if !response.status.is_redirection() {
                return Ok(response);
            }

            // Switch to GET for 301/302/303 redirects
            if matches!(
                response.status,
                StatusCode::MOVED_PERMANENTLY | StatusCode::FOUND | StatusCode::SEE_OTHER
            ) {
                current_method = Method::GET;
            }

            let location = response
                .headers
                .get(LOCATION)
                .and_then(|v| v.to_str().ok())
                .ok_or_else(|| {
                    anyhow::anyhow!("HTTP redirect without valid Location: {}", base_url)
                })?;

            let redirect_url = base_url.join(location).context("Invalid redirect URL")?;
            current = redirect_url;
        }

        Err(anyhow::anyhow!("Too many HTTP redirects"))
    })
    .await
    .context("HTTP request timeout")?
}

pub async fn request_via_outbound_with_ua(
    outbound: Arc<dyn AnyOutbound>,
    method: Method,
    url: &str,
    timeout: Duration,
    max_redirects: usize,
    user_agent: Option<&str>,
    headers: Option<&HeaderMap>,
) -> anyhow::Result<OutboundHttpResponse> {
    tokio::time::timeout(timeout, async move {
        let mut current = reqwest::Url::parse(url).context("Invalid URL")?;
        let mut current_method = method.clone();

        for _ in 0..=max_redirects {
            let (response, base_url) = request_once(
                outbound.clone(),
                current_method.clone(),
                current.clone(),
                user_agent,
                headers,
            )
            .await?;

            if !response.status.is_redirection() {
                return Ok(response);
            }

            // Switch to GET for 301/302/303 redirects
            if matches!(
                response.status,
                StatusCode::MOVED_PERMANENTLY | StatusCode::FOUND | StatusCode::SEE_OTHER
            ) {
                current_method = Method::GET;
            }

            let location = response
                .headers
                .get(LOCATION)
                .and_then(|v| v.to_str().ok())
                .ok_or_else(|| {
                    anyhow::anyhow!("HTTP redirect without valid Location: {}", base_url)
                })?;

            let redirect_url = base_url.join(location).context("Invalid redirect URL")?;
            current = redirect_url;
        }

        Err(anyhow::anyhow!("Too many HTTP redirects"))
    })
    .await
    .context("HTTP request timeout")?
}

pub async fn request_post_via_outbound(
    outbound: Arc<dyn AnyOutbound>,
    dns: Option<&str>,
    url: &str,
    timeout: Duration,
    headers: Option<&HeaderMap>,
    body: Bytes,
) -> anyhow::Result<OutboundHttpResponse> {
    tokio::time::timeout(timeout, async move {
        let current = reqwest::Url::parse(url).context("Invalid URL")?;
        // DoH POST请求不需要跟随重定向，直接发起一次请求即可
        let (response, _) = request_once_with_body(
            outbound.clone(),
            dns,
            Method::POST,
            current,
            None,
            headers,
            body,
        )
        .await?;

        if response.status.is_redirection() {
            return Err(anyhow::anyhow!(
                "DoH request redirected, which is not allowed",
            ));
        }

        Ok(response)
    })
    .await
    .context("HTTP request timeout")?
}

pub async fn test_latency_via_outbound(
    outbound: Arc<dyn AnyOutbound>,
    url: &str,
    timeout: Duration,
) -> Option<u64> {
    let start = Instant::now();
    let response = request_via_outbound_with_dns(
        outbound.clone(),
        outbound.dns_server_name(),
        Method::HEAD,
        url,
        timeout,
        2,
        None,
    )
    .await
    .ok()?;

    if response.status.is_success() || response.status.is_redirection() {
        Some(start.elapsed().as_micros() as u64)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::ntp::test_clock;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio_rustls::TlsAcceptor;

    /// A localhost certificate that is only valid during 2040.
    fn cert_valid_in_2040() -> (rustls::ServerConfig, rustls::RootCertStore) {
        let mut params = rcgen::CertificateParams::new(vec!["localhost".to_string()]).unwrap();
        params.not_before = rcgen::date_time_ymd(2040, 1, 1);
        params.not_after = rcgen::date_time_ymd(2041, 1, 1);
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = params.self_signed(&key).unwrap();
        let cert_der = rustls::pki_types::CertificateDer::from(cert.der().to_vec());
        let key_der = rustls::pki_types::PrivateKeyDer::try_from(key.serialize_der()).unwrap();

        let server_config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der.clone()], key_der)
            .unwrap();
        let mut roots = rustls::RootCertStore::empty();
        roots.add(cert_der).unwrap();
        (server_config, roots)
    }

    async fn https_handshake() -> std::io::Result<()> {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let (server_config, roots) = cert_valid_in_2040();
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);

        let server = async move {
            let mut tls = TlsAcceptor::from(Arc::new(server_config))
                .accept(server_io)
                .await?;
            tls.write_all(b"ok").await?;
            tls.flush().await
        };
        let client = async move {
            let connector = TlsConnector::from(Arc::new(https_client_config(roots)));
            let name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
            let mut tls = connector.connect(name, client_io).await?;
            let mut buf = [0u8; 2];
            tls.read_exact(&mut buf).await?;
            assert_eq!(&buf, b"ok");
            Ok::<_, std::io::Error>(())
        };

        let (server, client) = tokio::join!(server, client);
        client?;
        server
    }

    #[tokio::test]
    async fn https_rejects_certificate_outside_system_time() {
        let err = https_handshake().await.unwrap_err();
        assert!(err.to_string().contains("not valid yet"), "{err}");
    }

    #[tokio::test]
    async fn https_validates_certificate_with_ntp_time() {
        let _clock = test_clock::set_now(UNIX_EPOCH + Duration::from_secs(2_222_000_000));
        assert!(crate::utils::ntp::system_time() > SystemTime::now());
        https_handshake().await.unwrap();
    }
}
