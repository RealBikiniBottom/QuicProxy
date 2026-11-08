//! DNS-over-HTTPS inbound (RFC 8484), served over HTTP/1.1 and HTTP/2 on TLS (JLS optional)
//! or, with `tls.enable = false`, on plain TCP behind a reverse proxy.

use crate::config::InboundConfig;
use crate::dns::dns_server_for;
use crate::dns::ecs::{self, ClientSubnet};
use crate::proxy::TlsConfig;
use crate::proxy::inbound::AnyInbound;
use crate::utils::error::Context;
use anyhow::{Result, bail};
use async_trait::async_trait;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited};
use hyper::body::Incoming;
use hyper::header::{CACHE_CONTROL, CONTENT_LENGTH, CONTENT_TYPE, HeaderName, HeaderValue};
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto;
use simple_dns::{Packet, RCODE};
use std::convert::Infallible;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls::TlsAcceptor;
use tracing::{debug, error, info, warn};

pub const DNS_MESSAGE: &str = "application/dns-message";
pub const DEFAULT_PATH: &str = "/dns-query";
/// A DNS message over TCP-style framing cannot exceed this (RFC 8484 section 6).
const MAX_MESSAGE_LEN: usize = 65535;

pub struct DohInbound {
    tag: String,
    address: SocketAddr,
    idle_timeout: Duration,
    tls: TlsConfig,
    handler: Arc<DohHandler>,
}

#[derive(Debug)]
struct DohHandler {
    path: String,
    dns: Option<String>,
    client_subnet: SubnetMode,
    client_subnet_header: Option<HeaderName>,
}

/// How the inbound sets the ECS option of a query before it goes to the DNS server.
#[derive(Debug, Clone, Copy, PartialEq)]
enum SubnetMode {
    Passthrough,
    Strip,
    Fixed(ClientSubnet),
    Auto { ipv4_prefix: u8, ipv6_prefix: u8 },
}

impl SubnetMode {
    fn from_config(cfg: &InboundConfig) -> Result<Self> {
        let prefix = cfg.client_subnet_prefix.as_ref();
        let ipv4_prefix = prefix
            .and_then(|p| p.ipv4)
            .unwrap_or(ecs::DEFAULT_IPV4_PREFIX);
        let ipv6_prefix = prefix
            .and_then(|p| p.ipv6)
            .unwrap_or(ecs::DEFAULT_IPV6_PREFIX);
        if ipv4_prefix > 32 || ipv6_prefix > 128 {
            bail!("client_subnet_prefix out of range: ipv4 {ipv4_prefix}, ipv6 {ipv6_prefix}");
        }
        Ok(match cfg.client_subnet.as_deref() {
            None | Some("") => Self::Passthrough,
            Some(v) if v.eq_ignore_ascii_case("strip") => Self::Strip,
            Some(v) if v.eq_ignore_ascii_case("auto") => Self::Auto {
                ipv4_prefix,
                ipv6_prefix,
            },
            Some(v) => Self::Fixed(ClientSubnet::parse(v)?),
        })
    }

    /// The subnet to send upstream; `Err(())` keeps the query as it is. A client that sent
    /// a /0 subnet opted out (RFC 7871 section 7.1.2) and is never given its address.
    fn resolve(
        self,
        sent: Option<ClientSubnet>,
        client: IpAddr,
    ) -> Result<Option<ClientSubnet>, ()> {
        let opted_out = sent.is_some_and(|s| s.net().prefix_len() == 0);
        match self {
            Self::Passthrough => Err(()),
            Self::Strip => Ok(None),
            _ if opted_out => Err(()),
            Self::Fixed(subnet) => Ok(Some(subnet)),
            Self::Auto {
                ipv4_prefix,
                ipv6_prefix,
            } => Ok(ClientSubnet::from_ip(client, ipv4_prefix, ipv6_prefix).ok()),
        }
    }
}

impl DohInbound {
    pub fn new(tag: String, cfg: &InboundConfig) -> Result<Self> {
        let path = cfg.path.clone().unwrap_or_else(|| DEFAULT_PATH.to_string());
        if !path.starts_with('/') {
            bail!("dns inbound '{tag}': path must start with '/', got {path:?}");
        }
        Ok(Self {
            address: cfg.socket_addr()?,
            idle_timeout: cfg.idle_timeout(),
            tls: TlsConfig::from_inbound(cfg)?,
            handler: Arc::new(DohHandler {
                path,
                dns: cfg.dns.clone(),
                client_subnet: SubnetMode::from_config(cfg)
                    .with_context(|| format!("dns inbound '{tag}'"))?,
                client_subnet_header: cfg
                    .client_subnet_header
                    .as_deref()
                    .map(HeaderName::try_from)
                    .transpose()
                    .with_context(|| {
                        format!("dns inbound '{tag}': invalid client_subnet_header")
                    })?,
            }),
            tag,
        })
    }

    fn tls_acceptor(&self) -> Result<Option<TlsAcceptor>> {
        if !self.tls.enable {
            return Ok(None);
        }
        let mut config = crate::utils::tls::server_config(&self.tls, "DNS")?;
        config.alpn_protocols = match &self.tls.alpns {
            Some(alpns) => alpns.iter().map(|a| a.as_bytes().to_vec()).collect(),
            None => vec![b"h2".to_vec(), b"http/1.1".to_vec()],
        };
        Ok(Some(TlsAcceptor::from(Arc::new(config))))
    }
}

#[async_trait]
impl AnyInbound for DohInbound {
    fn protocol(&self) -> &str {
        "dns"
    }

    fn idle_timeout(&self) -> Duration {
        self.idle_timeout
    }

    async fn listen(&self) -> Result<()> {
        let listener = super::create_tcp_listener(self.address)?;
        let acceptor = self.tls_acceptor()?;
        info!(
            "DNS inbound '{}' serving {}{} on {}",
            self.tag,
            if acceptor.is_some() { "https" } else { "http" },
            self.handler.path,
            self.address
        );

        loop {
            let (socket, peer) = match listener.accept().await {
                Ok(conn) => conn,
                Err(e) => {
                    error!("DNS inbound accept error: {e}");
                    continue;
                }
            };
            let _ = socket.set_nodelay(true);
            let handler = self.handler.clone();
            let acceptor = acceptor.clone();
            let tls = self.tls.clone();
            let handshake_timeout = self.idle_timeout;
            tokio::spawn(async move {
                let Some(acceptor) = acceptor else {
                    serve_connection(socket, handler, peer).await;
                    return;
                };
                let stream =
                    match tokio::time::timeout(handshake_timeout, acceptor.accept(socket)).await {
                        Ok(Ok(stream)) => stream,
                        Ok(Err(e)) => {
                            debug!("DNS inbound TLS handshake error from {peer}: {e}");
                            return;
                        }
                        Err(_) => {
                            debug!("DNS inbound TLS handshake timeout from {peer}");
                            return;
                        }
                    };
                if let Err(e) =
                    crate::proxy::verify_jls_connection(&tls, stream.get_ref().1.jls_state())
                {
                    error!("DNS inbound JLS error from {peer}: {e}");
                    return;
                }
                serve_connection(stream, handler, peer).await;
            });
        }
    }
}

async fn serve_connection<S>(stream: S, handler: Arc<DohHandler>, peer: SocketAddr)
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let service = service_fn(move |req| {
        let handler = handler.clone();
        async move { Ok::<_, Infallible>(handler.handle(req, peer.ip()).await) }
    });
    if let Err(e) = auto::Builder::new(TokioExecutor::new())
        .serve_connection(TokioIo::new(stream), service)
        .await
    {
        debug!("DNS inbound connection from {peer} ended: {e}");
    }
}

impl DohHandler {
    async fn handle(&self, req: Request<Incoming>, peer: IpAddr) -> Response<Full<Bytes>> {
        if req.uri().path() != self.path {
            return status(StatusCode::NOT_FOUND);
        }
        let client = self.client_ip(&req).unwrap_or(peer);
        let query = match self.read_query(req).await {
            Ok(query) => query,
            Err(code) => return status(code),
        };
        let Ok(parsed) = Packet::parse(&query) else {
            return status(StatusCode::BAD_REQUEST);
        };
        let sent = ecs::get(&parsed);
        match self.client_subnet.resolve(sent, client) {
            Err(()) => self.answer(&query, &query).await,
            Ok(subnet) => {
                let mut upstream = parsed;
                ecs::set(&mut upstream, subnet);
                let Ok(upstream) = upstream.build_bytes_vec() else {
                    return status(StatusCode::BAD_REQUEST);
                };
                self.answer(&query, &upstream).await
            }
        }
    }

    /// The first address of the configured forwarding header, e.g. the original client in
    /// `X-Forwarded-For: client, proxy1, proxy2`.
    fn client_ip(&self, req: &Request<Incoming>) -> Option<IpAddr> {
        let value = req.headers().get(self.client_subnet_header.as_ref()?)?;
        let first = value.to_str().ok()?.split(',').next()?.trim();
        first
            .parse::<IpAddr>()
            .or_else(|_| first.parse::<SocketAddr>().map(|a| a.ip()))
            .ok()
    }

    /// Sends `upstream` to the DNS server and shapes the answer for the client's `query`.
    async fn answer(&self, query: &[u8], upstream: &[u8]) -> Response<Full<Bytes>> {
        let result = self.exchange(upstream).await.and_then(|response| {
            if query == upstream {
                return Ok(response);
            }
            let sent = Packet::parse(query)?;
            let mut response = Packet::parse(&response)?;
            ecs::restore_response(&mut response, ecs::get(&sent), sent.opt().is_some());
            Ok(response.build_bytes_vec()?)
        });
        match result {
            Ok(response) => dns_response(response),
            Err(e) => {
                warn!("DNS inbound query failed: {e:#}");
                match servfail(query) {
                    Some(response) => dns_response(response),
                    None => status(StatusCode::BAD_GATEWAY),
                }
            }
        }
    }

    async fn read_query(&self, req: Request<Incoming>) -> Result<Vec<u8>, StatusCode> {
        match *req.method() {
            Method::GET => {
                let encoded = req
                    .uri()
                    .query()
                    .and_then(|q| q.split('&').find_map(|kv| kv.strip_prefix("dns=")))
                    .ok_or(StatusCode::BAD_REQUEST)?;
                if encoded.len() > MAX_MESSAGE_LEN.div_ceil(3) * 4 {
                    return Err(StatusCode::URI_TOO_LONG);
                }
                URL_SAFE_NO_PAD
                    .decode(encoded.trim_end_matches('='))
                    .map_err(|_| StatusCode::BAD_REQUEST)
            }
            Method::POST => {
                let content_type = req
                    .headers()
                    .get(CONTENT_TYPE)
                    .and_then(|v| v.to_str().ok());
                if !content_type.is_some_and(is_dns_message) {
                    return Err(StatusCode::UNSUPPORTED_MEDIA_TYPE);
                }
                let body = Limited::new(req.into_body(), MAX_MESSAGE_LEN)
                    .collect()
                    .await
                    .map_err(|_| StatusCode::PAYLOAD_TOO_LARGE)?;
                Ok(body.to_bytes().to_vec())
            }
            _ => Err(StatusCode::METHOD_NOT_ALLOWED),
        }
    }

    async fn exchange(&self, query: &[u8]) -> Result<Vec<u8>> {
        dns_server_for(self.dns.as_deref())?
            .hijack_exchange(query)
            .await
    }
}

fn is_dns_message(content_type: &str) -> bool {
    content_type
        .split(';')
        .next()
        .is_some_and(|mime| mime.trim().eq_ignore_ascii_case(DNS_MESSAGE))
}

fn status(code: StatusCode) -> Response<Full<Bytes>> {
    let mut response = Response::new(Full::new(Bytes::new()));
    *response.status_mut() = code;
    if code == StatusCode::METHOD_NOT_ALLOWED {
        response
            .headers_mut()
            .insert("allow", HeaderValue::from_static("GET, POST"));
    }
    response
}

fn dns_response(message: Vec<u8>) -> Response<Full<Bytes>> {
    let max_age = min_ttl(&message);
    let len = message.len();
    let mut response = Response::new(Full::new(Bytes::from(message)));
    let headers = response.headers_mut();
    headers.insert(CONTENT_TYPE, HeaderValue::from_static(DNS_MESSAGE));
    headers.insert(CONTENT_LENGTH, HeaderValue::from(len));
    if let Some(ttl) = max_age {
        headers.insert(
            CACHE_CONTROL,
            HeaderValue::from_str(&format!("max-age={ttl}")).expect("ascii header"),
        );
    }
    response
}

/// The HTTP freshness lifetime must not outlive the smallest record TTL (RFC 8484 section 5.1).
fn min_ttl(message: &[u8]) -> Option<u32> {
    let packet = Packet::parse(message).ok()?;
    packet
        .answers
        .iter()
        .chain(packet.name_servers.iter())
        .chain(packet.additional_records.iter())
        .filter(|r| r.rdata.type_code() != simple_dns::TYPE::OPT)
        .map(|r| r.ttl)
        .min()
}

fn servfail(query: &[u8]) -> Option<Vec<u8>> {
    let query = Packet::parse(query).ok()?;
    let mut reply = Packet::new_reply(query.id());
    reply.questions = query.questions.clone();
    *reply.rcode_mut() = RCODE::ServerFailure;
    reply.build_bytes_vec().ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use simple_dns::rdata::{A, RData};
    use simple_dns::{CLASS, Name, ResourceRecord};

    #[test]
    fn content_type_matching_ignores_parameters_and_case() {
        assert!(is_dns_message("application/dns-message"));
        assert!(is_dns_message("Application/DNS-Message; charset=binary"));
        assert!(!is_dns_message("application/json"));
        assert!(!is_dns_message("application/dns-message-x"));
    }

    #[test]
    fn cache_control_uses_smallest_record_ttl() {
        let mut packet = Packet::new_reply(0);
        for ttl in [300, 42, 600] {
            packet.answers.push(ResourceRecord::new(
                Name::new_unchecked("example.com"),
                CLASS::IN,
                ttl,
                RData::A(A {
                    address: 0x01020304,
                }),
            ));
        }
        let bytes = packet.build_bytes_vec().unwrap();
        assert_eq!(min_ttl(&bytes), Some(42));

        let response = dns_response(bytes);
        assert_eq!(response.headers()[CACHE_CONTROL], "max-age=42");
        assert_eq!(response.headers()[CONTENT_TYPE], DNS_MESSAGE);
    }

    #[test]
    fn empty_answer_has_no_cache_control() {
        let bytes = Packet::new_reply(7).build_bytes_vec().unwrap();
        assert_eq!(min_ttl(&bytes), None);
        assert!(dns_response(bytes).headers().get(CACHE_CONTROL).is_none());
    }

    #[test]
    fn servfail_echoes_id_and_question() {
        let query = crate::dns::build_dns_query_packet(
            "example.com",
            simple_dns::QTYPE::TYPE(simple_dns::TYPE::A),
        )
        .unwrap()
        .build_bytes_vec()
        .unwrap();
        let reply = servfail(&query).unwrap();
        let reply = Packet::parse(&reply).unwrap();
        let query = Packet::parse(&query).unwrap();
        assert_eq!(reply.id(), query.id());
        assert_eq!(reply.rcode(), RCODE::ServerFailure);
        assert_eq!(reply.questions.len(), 1);
        assert_eq!(reply.questions[0].qname, query.questions[0].qname);
    }

    #[test]
    fn subnet_modes_parse_and_resolve() {
        let cfg = |extra: serde_json::Value| -> InboundConfig {
            let mut base = serde_json::json!({ "type": "dns", "address": "127.0.0.1", "port": 0 });
            base.as_object_mut()
                .unwrap()
                .extend(extra.as_object().unwrap().clone());
            serde_json::from_value(base).unwrap()
        };
        let mode = |extra| SubnetMode::from_config(&cfg(extra)).unwrap();
        let client: IpAddr = "203.0.113.77".parse().unwrap();
        let sent = ClientSubnet::parse("198.51.100.0/24").ok();
        let opt_out = ClientSubnet::parse("0.0.0.0/0").ok();

        assert_eq!(mode(serde_json::json!({})).resolve(sent, client), Err(()));
        assert_eq!(
            mode(serde_json::json!({ "client_subnet": "strip" })).resolve(sent, client),
            Ok(None)
        );

        let fixed = mode(serde_json::json!({ "client_subnet": "192.0.2.0/24" }));
        assert_eq!(
            fixed.resolve(None, client),
            Ok(ClientSubnet::parse("192.0.2.0/24").ok())
        );
        assert_eq!(fixed.resolve(opt_out, client), Err(()));

        let auto = mode(serde_json::json!({
            "client_subnet": "auto", "client_subnet_prefix": { "ipv4": 16 }
        }));
        assert_eq!(
            auto.resolve(sent, client),
            Ok(ClientSubnet::parse("203.0.0.0/16").ok())
        );
        let v6: IpAddr = "2001:db8:aa:bb::1".parse().unwrap();
        assert_eq!(
            auto.resolve(None, v6),
            Ok(ClientSubnet::parse("2001:db8:aa::/56").ok())
        );

        assert!(
            SubnetMode::from_config(&cfg(serde_json::json!({ "client_subnet": "bogus" }))).is_err()
        );
        assert!(
            SubnetMode::from_config(&cfg(serde_json::json!({
                "client_subnet": "auto", "client_subnet_prefix": { "ipv4": 33 }
            })))
            .is_err()
        );
    }

    #[test]
    fn rejects_relative_path() {
        let cfg: InboundConfig = serde_json::from_value(serde_json::json!({
            "type": "dns", "address": "127.0.0.1", "port": 0, "path": "dns-query"
        }))
        .unwrap();
        assert!(DohInbound::new("doh".into(), &cfg).is_err());
    }
}
