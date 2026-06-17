use anyhow::Context;
use std::sync::Arc;
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

    let mut root_store = rustls::RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let client_config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(client_config));

    let server_name = rustls::pki_types::ServerName::try_from(host)
        .map_err(|e| anyhow::anyhow!("{e}"))?
        .to_owned();
    let tls_stream = connector.connect(server_name, stream).await?;
    Ok(Box::new(tls_stream))
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
    let stream = outbound.connect_stream(&target).await?;
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
        .header("User-Agent", user_agent.unwrap_or("clash/sing-box/0.1"))
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
