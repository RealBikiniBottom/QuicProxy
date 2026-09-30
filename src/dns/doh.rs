use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use bytes::Bytes;
use dashmap::DashMap;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::client::conn::{http1, http2};
use hyper::header::{ACCEPT, CONTENT_TYPE, HOST};
use hyper::{Method, Request, Response, Uri};
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::sync::Mutex as AsyncMutex;
use tokio::time::{Instant, timeout, timeout_at};
use tokio_rustls::TlsConnector;
use tokio_rustls::rustls;
use tracing::debug;

use crate::dns::{get_default_dns, get_dns_by_tag};
use crate::proxy::TargetAddr;
use crate::proxy::outbound::AnyOutbound;

const DNS_MESSAGE: &str = "application/dns-message";
const MAX_IDLE_H1: usize = 8;

type ReqBody = Full<Bytes>;

static NEXT_CONN_ID: AtomicU64 = AtomicU64::new(1);

/// DNS-over-HTTPS client that negotiates HTTP/2 via ALPN and multiplexes all
/// queries over one shared connection per outbound. Servers that only speak
/// HTTP/1.1 fall back to a small keep-alive pool.
pub struct DohClient {
    uri: Uri,
    path: String,
    host: String,
    port: u16,
    dns_server: Option<String>,
    tls: TlsConnector,
    pools: DashMap<String, Arc<ConnPool>>,
}

#[derive(Default)]
struct ConnPool {
    h2: AsyncMutex<Option<H2Conn>>,
    h1_idle: StdMutex<Vec<http1::SendRequest<ReqBody>>>,
    h1_only: AtomicBool,
}

#[derive(Clone)]
struct H2Conn {
    id: u64,
    sender: http2::SendRequest<ReqBody>,
}

enum Conn {
    H2(H2Conn),
    H1(http1::SendRequest<ReqBody>),
}

impl ConnPool {
    fn take_idle_h1(&self) -> Option<http1::SendRequest<ReqBody>> {
        let mut idle = self.h1_idle.lock().unwrap_or_else(|e| e.into_inner());
        while let Some(sender) = idle.pop() {
            if !sender.is_closed() {
                return Some(sender);
            }
        }
        None
    }

    fn put_idle_h1(&self, sender: http1::SendRequest<ReqBody>) {
        if sender.is_closed() {
            return;
        }
        let mut idle = self.h1_idle.lock().unwrap_or_else(|e| e.into_inner());
        if idle.len() < MAX_IDLE_H1 {
            idle.push(sender);
        }
    }

    async fn invalidate_h2(&self, id: u64) {
        let mut slot = self.h2.lock().await;
        if slot.as_ref().is_some_and(|c| c.id == id) {
            *slot = None;
        }
    }
}

impl DohClient {
    pub fn new(host: &str, port: u16, path: &str, dns_server: Option<String>) -> Result<Self> {
        let uri: Uri = format!("https://{host}:{port}{path}")
            .parse()
            .with_context(|| format!("invalid DoH url for {host}:{port}{path}"))?;

        let mut root_store = rustls::RootCertStore::empty();
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let mut tls_config = rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();
        tls_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

        Ok(Self {
            uri,
            path: path.to_string(),
            host: host.to_string(),
            port,
            dns_server,
            tls: TlsConnector::from(Arc::new(tls_config)),
            pools: DashMap::new(),
        })
    }

    /// Sends one DNS wire-format query. A pooled connection gets half of the
    /// budget; if it fails or stalls (e.g. a silently dropped tunnel), the
    /// query is retried once on a fresh connection within the same deadline.
    pub async fn query(
        &self,
        outbound: &Arc<dyn AnyOutbound>,
        body: Bytes,
        budget: Duration,
    ) -> Result<Bytes> {
        let deadline = Instant::now() + budget;
        let pool = self
            .pools
            .entry(outbound.tag().to_string())
            .or_default()
            .clone();

        let (conn, reused) = timeout_at(deadline, self.acquire(&pool, outbound))
            .await
            .map_err(|_| anyhow!("DoH connect to {} timed out", self.uri))??;

        if !reused {
            return timeout_at(deadline, self.send(conn, &pool, body))
                .await
                .map_err(|_| anyhow!("DoH query to {} timed out", self.uri))?;
        }

        let h2_id = match &conn {
            Conn::H2(c) => Some(c.id),
            Conn::H1(_) => None,
        };
        let first = timeout(budget / 2, self.send(conn, &pool, body.clone()))
            .await
            .unwrap_or_else(|_| Err(anyhow!("DoH query on pooled connection timed out")));

        match first {
            Ok(resp) => Ok(resp),
            Err(e) => {
                debug!(
                    "DoH pooled connection to {} failed, reconnecting: {e:#}",
                    self.uri
                );
                if let Some(id) = h2_id {
                    pool.invalidate_h2(id).await;
                }
                timeout_at(deadline, async {
                    let conn = self.acquire_fresh(&pool, outbound).await?;
                    self.send(conn, &pool, body).await
                })
                .await
                .map_err(|_| anyhow!("DoH query to {} timed out", self.uri))?
            }
        }
    }

    async fn acquire(
        &self,
        pool: &ConnPool,
        outbound: &Arc<dyn AnyOutbound>,
    ) -> Result<(Conn, bool)> {
        if pool.h1_only.load(Ordering::Relaxed) {
            if let Some(sender) = pool.take_idle_h1() {
                return Ok((Conn::H1(sender), true));
            }
            return Ok((self.acquire_fresh(pool, outbound).await?, false));
        }

        // Hold the slot lock while dialing so concurrent queries share the
        // new connection instead of each opening their own.
        let mut slot = pool.h2.lock().await;
        if let Some(conn) = slot.as_ref().filter(|c| !c.sender.is_closed()) {
            return Ok((Conn::H2(conn.clone()), true));
        }
        *slot = None;
        let conn = self.connect(outbound).await?;
        match &conn {
            Conn::H2(c) => *slot = Some(c.clone()),
            Conn::H1(_) => pool.h1_only.store(true, Ordering::Relaxed),
        }
        Ok((conn, false))
    }

    async fn acquire_fresh(
        &self,
        pool: &ConnPool,
        outbound: &Arc<dyn AnyOutbound>,
    ) -> Result<Conn> {
        let conn = self.connect(outbound).await?;
        match &conn {
            Conn::H2(c) => {
                *pool.h2.lock().await = Some(c.clone());
                pool.h1_only.store(false, Ordering::Relaxed);
            }
            Conn::H1(_) => pool.h1_only.store(true, Ordering::Relaxed),
        }
        Ok(conn)
    }

    async fn connect(&self, outbound: &Arc<dyn AnyOutbound>) -> Result<Conn> {
        let resolver = match self.dns_server.as_deref() {
            Some(tag) => get_dns_by_tag(tag)?,
            None => get_default_dns()?,
        };
        let ip = resolver
            .lookup(&self.host, false, outbound)
            .await?
            .into_iter()
            .next()
            .with_context(|| format!("DNS lookup returned no results for {}", self.host))?;

        let stream = outbound
            .connect_stream(&TargetAddr::Ip(SocketAddr::new(ip, self.port)))
            .await
            .context("DoH connect_stream")?;

        let server_name = rustls::pki_types::ServerName::try_from(self.host.as_str())
            .map_err(|e| anyhow!("invalid DoH server name {}: {e}", self.host))?
            .to_owned();
        let tls_stream = self
            .tls
            .connect(server_name, stream)
            .await
            .context("DoH TLS handshake")?;
        let is_h2 = tls_stream.get_ref().1.alpn_protocol() == Some(b"h2".as_slice());
        let io = TokioIo::new(tls_stream);

        if is_h2 {
            let (sender, connection) = http2::handshake(TokioExecutor::new(), io)
                .await
                .context("DoH h2 handshake")?;
            let id = NEXT_CONN_ID.fetch_add(1, Ordering::Relaxed);
            let uri = self.uri.clone();
            tokio::spawn(async move {
                if let Err(e) = connection.await {
                    debug!("DoH h2 connection #{id} to {uri} closed: {e}");
                }
            });
            debug!("DoH h2 connection #{id} established to {}", self.uri);
            Ok(Conn::H2(H2Conn { id, sender }))
        } else {
            let (sender, connection) = http1::handshake(io)
                .await
                .context("DoH http/1.1 handshake")?;
            tokio::spawn(async move {
                let _ = connection.await;
            });
            debug!(
                "DoH server {} did not negotiate h2, using http/1.1",
                self.uri
            );
            Ok(Conn::H1(sender))
        }
    }

    async fn send(&self, conn: Conn, pool: &ConnPool, body: Bytes) -> Result<Bytes> {
        match conn {
            Conn::H2(mut conn) => {
                conn.sender
                    .ready()
                    .await
                    .context("DoH h2 connection not ready")?;
                let request = self.build_request(self.uri.clone(), None, body)?;
                let response = conn.sender.send_request(request).await?;
                read_response(response).await
            }
            Conn::H1(mut sender) => {
                sender
                    .ready()
                    .await
                    .context("DoH http/1.1 connection not ready")?;
                let request =
                    self.build_request(Uri::try_from(self.path.as_str())?, Some(&self.host), body)?;
                let response = sender.send_request(request).await?;
                let result = read_response(response).await;
                if result.is_ok() {
                    pool.put_idle_h1(sender);
                }
                result
            }
        }
    }

    fn build_request(&self, uri: Uri, host: Option<&str>, body: Bytes) -> Result<Request<ReqBody>> {
        let mut builder = Request::builder()
            .method(Method::POST)
            .uri(uri)
            .header(CONTENT_TYPE, DNS_MESSAGE)
            .header(ACCEPT, DNS_MESSAGE);
        if let Some(host) = host {
            builder = builder.header(HOST, host);
        }
        builder
            .body(Full::new(body))
            .context("failed to build DoH request")
    }
}

async fn read_response(response: Response<Incoming>) -> Result<Bytes> {
    let status = response.status();
    let body = response
        .into_body()
        .collect()
        .await
        .context("failed to read DoH response body")?
        .to_bytes();
    if !status.is_success() {
        bail!("DoH server returned error: {status}");
    }
    Ok(body)
}
