//! DNS-over-HTTPS inbound (RFC 8484) end to end, plus interop with third-party DoH clients:
//! hickory-resolver, curl `--doh-url` and a Go client built on miekg/dns + net/http.
//! curl and Go tests skip when the tool is missing.

mod common;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use common::{TestContext, Watchdog};
use ipnet::IpNet;
use quicproxy::dns::ecs::{self, ClientSubnet};
use quicproxy::proxy::TlsConfig;
use simple_dns::rdata::{A, AAAA, RData, TXT};
use simple_dns::{CLASS, Name, Packet, PacketFlag, QTYPE, RCODE, ResourceRecord, TYPE};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::net::UdpSocket;

const TEST_TIMEOUT: Duration = Duration::from_secs(120);
const DNS_MESSAGE: &str = "application/dns-message";
const JLS_USER: &str = "doh-jls-user";
const JLS_PASSWORD: &str = "doh-jls-password";

/// The ECS subnet of every query the upstream received, `None` for queries without one.
type SeenSubnets = Arc<Mutex<Vec<Option<String>>>>;

/// Upstream answering `*.doh.test`: A 127.0.0.1 (ttl 120), AAAA ::1 (ttl 60),
/// TXT "quicproxy-doh" (ttl 30), and NXDOMAIN for names under `nx.doh.test`.
/// A query carrying an IPv4 client subnet like a geo-aware resolver: the A answer is the
/// subnet's first host, and the subnet is echoed back with scope 24.
async fn spawn_upstream() -> (SocketAddr, SeenSubnets) {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = socket.local_addr().unwrap();
    let seen = SeenSubnets::default();
    let log = seen.clone();
    tokio::spawn(async move {
        let mut buf = [0u8; 4096];
        loop {
            let Ok((len, peer)) = socket.recv_from(&mut buf).await else {
                continue;
            };
            if let Some(reply) = upstream_reply(&buf[..len], &log) {
                let _ = socket.send_to(&reply, peer).await;
            }
        }
    });
    (addr, seen)
}

fn upstream_reply(query: &[u8], seen: &SeenSubnets) -> Option<Vec<u8>> {
    let query = Packet::parse(query).ok()?;
    let subnet = ecs::get(&query);
    seen.lock().unwrap().push(subnet.map(|s| s.to_string()));
    let geo_answer = match subnet.map(|s| s.net()) {
        Some(IpNet::V4(net)) if net.prefix_len() > 0 => {
            Some(Ipv4Addr::from(u32::from(net.network()) + 1))
        }
        _ => None,
    };
    let mut reply = Packet::new_reply(query.id());
    if query.opt().is_some() {
        let echoed = subnet.map(|s| {
            let mut data = s.encode();
            data[3] = 24;
            ClientSubnet::decode(&data).unwrap()
        });
        ecs::set(&mut reply, echoed);
        if reply.opt().is_none() {
            *reply.opt_mut() = query.opt().cloned();
        }
    }
    reply.set_flags(PacketFlag::RECURSION_AVAILABLE | PacketFlag::RECURSION_DESIRED);
    for question in &query.questions {
        reply.questions.push(question.clone());
        let qname = question.qname.to_string();
        if qname.ends_with("nx.doh.test") {
            *reply.rcode_mut() = RCODE::NameError;
            continue;
        }
        let name = Name::new_unchecked(&qname).into_owned();
        let record = |ttl, rdata| ResourceRecord::new(name.clone(), CLASS::IN, ttl, rdata);
        match question.qtype {
            QTYPE::TYPE(TYPE::A) => reply.answers.push(record(
                120,
                RData::A(A {
                    address: u32::from(geo_answer.unwrap_or(Ipv4Addr::LOCALHOST)),
                }),
            )),
            QTYPE::TYPE(TYPE::AAAA) => reply.answers.push(record(
                60,
                RData::AAAA(AAAA {
                    address: u128::from(Ipv6Addr::LOCALHOST),
                }),
            )),
            QTYPE::TYPE(TYPE::TXT) => {
                let txt = TXT::new().with_string("quicproxy-doh").ok()?.into_owned();
                reply.answers.push(record(30, RData::TXT(txt)));
            }
            _ => {}
        }
    }
    reply.build_bytes_vec().ok()
}

struct DohServer {
    _context: TestContext,
    addr: SocketAddr,
    cert: PathBuf,
    seen: SeenSubnets,
}

impl DohServer {
    fn url(&self) -> String {
        format!("https://localhost:{}/dns-query", self.addr.port())
    }
}

async fn start_doh(name: &str, jls: bool) -> DohServer {
    start_doh_with(name, jls, true).await
}

async fn start_doh_with(name: &str, jls: bool, tls_enabled: bool) -> DohServer {
    start_doh_custom(
        name,
        jls,
        tls_enabled,
        serde_json::json!({}),
        serde_json::json!({}),
    )
    .await
}

/// `inbound` and `upstream` fields are merged into the DNS inbound and the upstream DNS
/// server; an `upstream.cache` path also declares that cache.
async fn start_doh_custom(
    name: &str,
    jls: bool,
    tls_enabled: bool,
    inbound: serde_json::Value,
    upstream_extra: serde_json::Value,
) -> DohServer {
    let mut context = TestContext::new().await;
    let (upstream, seen) = spawn_upstream().await;
    let (cert, key) = TestContext::generate_tls_files();

    let mut tls = serde_json::json!({
        "enable": tls_enabled,
        "cert": cert,
        "key": key,
    });
    if jls {
        tls["enable_jls"] = true.into();
        tls["jls_username"] = JLS_USER.into();
        tls["jls_password"] = JLS_PASSWORD.into();
    }
    let mut config = serde_json::json!({
        "inbounds": {
            name: { "type": "dns", "dns": "upstream", "tls": tls }
        },
        "outbounds": {
            "default_server": "direct_out",
            "servers": { "direct_out": { "type": "direct" } }
        },
        "dns": {
            "default_server": "upstream",
            "servers": {
                "upstream": {
                    "type": "udp",
                    "address": upstream.ip().to_string(),
                    "port": upstream.port(),
                    "outbound": "direct_out"
                }
            }
        },
        "router": { "default_mode": "direct" },
        "log": { "level": "info" }
    });
    merge(&mut config["inbounds"][name], inbound);
    let cache = upstream_extra.get("cache").cloned();
    merge(&mut config["dns"]["servers"]["upstream"], upstream_extra);
    if let Some(cache) = cache {
        let path = tempfile::tempdir().unwrap().keep().join("dns-cache.db");
        config["cache"] = serde_json::json!({ cache.as_str().unwrap(): { "path": path } });
    }
    let idx = context.start_proxy(config, name).await;
    let addr = context.proxies[idx].addr;
    DohServer {
        _context: context,
        addr,
        cert,
        seen,
    }
}

fn merge(target: &mut serde_json::Value, extra: serde_json::Value) {
    if let (Some(target), serde_json::Value::Object(extra)) = (target.as_object_mut(), extra) {
        target.extend(extra);
    }
}

fn client_tls(cert: &Path, jls: Option<(&str, &str)>, alpn: &[&[u8]]) -> rustls::ClientConfig {
    let mut tls = TlsConfig {
        enable: true,
        cert: Some(cert.to_string_lossy().into_owned()),
        ..TlsConfig::default()
    };
    if let Some((user, password)) = jls {
        tls.enable_jls = true;
        tls.jls_username = user.to_string();
        tls.jls_password = password.to_string();
    }
    let mut config = quicproxy::utils::tls::client_config(&tls).unwrap();
    config.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    config
}

fn http_client(server: &DohServer, tls: rustls::ClientConfig, http1: bool) -> reqwest::Client {
    let mut builder = reqwest::Client::builder()
        .use_preconfigured_tls(tls)
        .resolve("localhost", server.addr)
        .timeout(Duration::from_secs(10));
    if http1 {
        builder = builder.http1_only();
    }
    builder.build().unwrap()
}

fn query(id: u16, name: &str, qtype: TYPE) -> Vec<u8> {
    let mut packet = Packet::new_query(id);
    packet.set_flags(PacketFlag::RECURSION_DESIRED);
    packet.questions.push(simple_dns::Question::new(
        Name::new_unchecked(name),
        QTYPE::TYPE(qtype),
        simple_dns::QCLASS::CLASS(CLASS::IN),
        false,
    ));
    packet.build_bytes_vec().unwrap()
}

fn answer_ips(message: &[u8]) -> Vec<IpAddr> {
    Packet::parse(message)
        .unwrap()
        .answers
        .iter()
        .filter_map(|r| match &r.rdata {
            RData::A(a) => Some(IpAddr::V4(Ipv4Addr::from(a.address))),
            RData::AAAA(a) => Some(IpAddr::V6(Ipv6Addr::from(a.address))),
            _ => None,
        })
        .collect()
}

async fn get(client: &reqwest::Client, url: &str, message: &[u8]) -> reqwest::Response {
    client
        .get(format!("{url}?dns={}", URL_SAFE_NO_PAD.encode(message)))
        .header("accept", DNS_MESSAGE)
        .send()
        .await
        .unwrap()
}

async fn post(client: &reqwest::Client, url: &str, message: &[u8]) -> reqwest::Response {
    client
        .post(url)
        .header("content-type", DNS_MESSAGE)
        .header("accept", DNS_MESSAGE)
        .body(message.to_vec())
        .send()
        .await
        .unwrap()
}

async fn assert_answer(response: reqwest::Response, id: u16, version: reqwest::Version) {
    assert_eq!(response.status(), 200);
    assert_eq!(response.version(), version);
    assert_eq!(response.headers()["content-type"], DNS_MESSAGE);
    assert_eq!(response.headers()["cache-control"], "max-age=120");
    let body = response.bytes().await.unwrap();
    assert_eq!(Packet::parse(&body).unwrap().id(), id);
    assert_eq!(answer_ips(&body), vec![IpAddr::V4(Ipv4Addr::LOCALHOST)]);
}

#[tokio::test]
async fn doh_get_and_post_over_http2_and_http1() {
    let _watchdog = Watchdog::new("doh_get_and_post_over_http2_and_http1", TEST_TIMEOUT);
    let server = start_doh("doh_in", false).await;
    let url = server.url();

    for (http1, version) in [
        (false, reqwest::Version::HTTP_2),
        (true, reqwest::Version::HTTP_11),
    ] {
        let alpn: &[&[u8]] = if http1 {
            &[b"http/1.1"]
        } else {
            &[b"h2", b"http/1.1"]
        };
        let client = http_client(&server, client_tls(&server.cert, None, alpn), http1);

        // RFC 8484 recommends id 0 for cache friendliness; any other id must be echoed.
        for id in [0, 0x1234] {
            let message = query(id, "www.doh.test", TYPE::A);
            assert_answer(get(&client, &url, &message).await, id, version).await;
            assert_answer(post(&client, &url, &message).await, id, version).await;
        }
    }
}

#[tokio::test]
async fn doh_passes_through_rcode_and_other_types() {
    let _watchdog = Watchdog::new("doh_passes_through_rcode_and_other_types", TEST_TIMEOUT);
    let server = start_doh("doh_in", false).await;
    let url = server.url();
    let client = http_client(&server, client_tls(&server.cert, None, &[b"h2"]), false);

    let body = post(&client, &url, &query(0, "missing.nx.doh.test", TYPE::A))
        .await
        .bytes()
        .await
        .unwrap();
    assert_eq!(Packet::parse(&body).unwrap().rcode(), RCODE::NameError);

    let body = get(&client, &url, &query(0, "www.doh.test", TYPE::AAAA))
        .await
        .bytes()
        .await
        .unwrap();
    assert_eq!(answer_ips(&body), vec![IpAddr::V6(Ipv6Addr::LOCALHOST)]);

    let response = post(&client, &url, &query(0, "www.doh.test", TYPE::TXT)).await;
    assert_eq!(response.headers()["cache-control"], "max-age=30");
    let body = response.bytes().await.unwrap();
    let packet = Packet::parse(&body).unwrap();
    let RData::TXT(txt) = &packet.answers[0].rdata else {
        panic!("expected TXT, got {:?}", packet.answers[0].rdata);
    };
    assert_eq!(
        String::try_from(txt.clone()).unwrap(),
        "quicproxy-doh".to_string()
    );
}

#[tokio::test]
async fn doh_rejects_malformed_requests() {
    let _watchdog = Watchdog::new("doh_rejects_malformed_requests", TEST_TIMEOUT);
    let server = start_doh("doh_in", false).await;
    let url = server.url();
    let client = http_client(&server, client_tls(&server.cert, None, &[b"h2"]), false);
    let message = query(0, "www.doh.test", TYPE::A);

    let status = |r: reqwest::Response| r.status().as_u16();
    assert_eq!(status(client.get(&url).send().await.unwrap()), 400);
    assert_eq!(
        status(client.get(format!("{url}?dns=!!!")).send().await.unwrap()),
        400
    );
    assert_eq!(
        status(
            client
                .post(&url)
                .header("content-type", "application/json")
                .body(message.clone())
                .send()
                .await
                .unwrap()
        ),
        415
    );
    assert_eq!(status(post(&client, &url, b"not dns").await), 400);
    assert_eq!(
        status(client.put(&url).body(message.clone()).send().await.unwrap()),
        405
    );
    let other_path = url.replace("/dns-query", "/resolve");
    assert_eq!(status(post(&client, &other_path, &message).await), 404);
    assert_eq!(status(post(&client, &url, &vec![0u8; 70_000]).await), 413);
}

#[tokio::test]
async fn doh_over_jls_requires_jls_credentials() {
    let _watchdog = Watchdog::new("doh_over_jls_requires_jls_credentials", TEST_TIMEOUT);
    let server = start_doh("doh_jls_in", true).await;
    let url = server.url();
    let message = query(0, "www.doh.test", TYPE::A);

    let client = http_client(
        &server,
        client_tls(&server.cert, Some((JLS_USER, JLS_PASSWORD)), &[b"h2"]),
        false,
    );
    assert_answer(
        post(&client, &url, &message).await,
        0,
        reqwest::Version::HTTP_2,
    )
    .await;

    for jls in [None, Some((JLS_USER, "wrong-password"))] {
        let client = http_client(&server, client_tls(&server.cert, jls, &[b"h2"]), false);
        let result = client
            .post(&url)
            .header("content-type", DNS_MESSAGE)
            .body(message.clone())
            .send()
            .await;
        assert!(
            result.is_err(),
            "JLS inbound answered a client with jls={jls:?}: {result:?}"
        );
    }
}

#[tokio::test]
async fn hickory_resolver_interop() {
    use hickory_resolver::Resolver;
    use hickory_resolver::config::{NameServerConfig, ResolverConfig};
    use hickory_resolver::name_server::TokioConnectionProvider;
    use hickory_resolver::proto::rr::RecordType;
    use hickory_resolver::proto::xfer::Protocol;

    let _watchdog = Watchdog::new("hickory_resolver_interop", TEST_TIMEOUT);
    let server = start_doh("doh_in", false).await;

    let mut ns = NameServerConfig::new(server.addr, Protocol::Https);
    ns.tls_dns_name = Some("localhost".to_string());
    ns.http_endpoint = Some("/dns-query".to_string());
    let mut config = ResolverConfig::new();
    config.add_name_server(ns);
    let mut builder = Resolver::builder_with_config(config, TokioConnectionProvider::default());
    builder.options_mut().tls_config = client_tls(&server.cert, None, &[]);
    builder.options_mut().cache_size = 0;
    builder.options_mut().ip_strategy = hickory_resolver::config::LookupIpStrategy::Ipv4AndIpv6;
    let resolver = builder.build();

    let ips: Vec<IpAddr> = resolver
        .lookup_ip("www.doh.test.")
        .await
        .unwrap()
        .iter()
        .collect();
    assert!(ips.contains(&IpAddr::V4(Ipv4Addr::LOCALHOST)), "{ips:?}");
    assert!(ips.contains(&IpAddr::V6(Ipv6Addr::LOCALHOST)), "{ips:?}");

    let txt = resolver.txt_lookup("www.doh.test.").await.unwrap();
    assert_eq!(txt.iter().next().unwrap().to_string(), "quicproxy-doh");

    let lookup = resolver
        .lookup("api.doh.test.", RecordType::AAAA)
        .await
        .unwrap();
    assert_eq!(lookup.iter().count(), 1);

    let err = resolver.lookup_ip("gone.nx.doh.test.").await.unwrap_err();
    assert!(err.is_nx_domain(), "{err:?}");
}

#[tokio::test]
async fn curl_doh_url_interop() {
    let _watchdog = Watchdog::new("curl_doh_url_interop", TEST_TIMEOUT);
    if Command::new("curl").arg("--version").output().is_err() {
        eprintln!("skipping: curl not found");
        return;
    }
    let server = start_doh("doh_in", false).await;
    let http_port = server._context.mock_server_http_addr.port();
    let doh_port = server.addr.port();

    // curl resolves www.doh.test through the DoH inbound (POST over HTTP/2), then fetches
    // the mock HTTP server at the 127.0.0.1 it got back.
    let output = tokio::task::spawn_blocking(move || {
        Command::new("curl")
            .args(["-sS", "--max-time", "15", "--ipv4"])
            .args([
                "--doh-url",
                &format!("https://localhost:{doh_port}/dns-query"),
            ])
            .arg("--doh-insecure")
            .args(["--resolve", &format!("localhost:{doh_port}:127.0.0.1")])
            .arg(format!("http://www.doh.test:{http_port}/"))
            .output()
            .unwrap()
    })
    .await
    .unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    if stderr.contains("doh-url") && stderr.contains("unknown") {
        eprintln!("skipping: curl has no DoH support: {stderr}");
        return;
    }
    assert!(output.status.success(), "curl failed: {stderr}");
    assert_eq!(String::from_utf8_lossy(&output.stdout), "Hello World!");
}

fn build_go_client() -> Option<PathBuf> {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let out = manifest.join("target/doh-compat/doh_go_client");
    std::fs::create_dir_all(out.parent().unwrap()).unwrap();
    let result = Command::new("go")
        .current_dir(manifest.join("tests/doh_go_client"))
        .args(["build", "-o"])
        .arg(&out)
        .arg(".")
        .output();
    match result {
        Ok(output) if output.status.success() => Some(out),
        Ok(output) => {
            eprintln!(
                "skipping: go build failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            None
        }
        Err(_) => {
            eprintln!("skipping: go not found");
            None
        }
    }
}

#[tokio::test]
async fn go_miekg_dns_interop() {
    let _watchdog = Watchdog::new("go_miekg_dns_interop", TEST_TIMEOUT);
    let Some(client) = tokio::task::spawn_blocking(build_go_client).await.unwrap() else {
        return;
    };
    let server = start_doh("doh_in", false).await;
    let url = format!("https://127.0.0.1:{}/dns-query", server.addr.port());

    let cases = [
        ("www.doh.test", "A", "A 127.0.0.1"),
        ("www.doh.test", "AAAA", "AAAA ::1"),
        ("www.doh.test", "TXT", "TXT quicproxy-doh"),
        ("x.nx.doh.test", "A", "RCODE NXDOMAIN"),
    ];
    for method in ["GET", "POST"] {
        for (http1, proto) in [(false, "PROTO HTTP/2.0"), (true, "PROTO HTTP/1.1")] {
            for (name, qtype, expected) in cases {
                let client = client.clone();
                let url = url.clone();
                let output = tokio::task::spawn_blocking(move || {
                    Command::new(&client)
                        .args(["-url", &url, "-name", name, "-type", qtype])
                        .args(["-method", method])
                        .arg(format!("-http1={http1}"))
                        .output()
                        .unwrap()
                })
                .await
                .unwrap();
                let stdout = String::from_utf8_lossy(&output.stdout);
                assert!(
                    output.status.success(),
                    "{method} http1={http1} {name} {qtype}: {}",
                    String::from_utf8_lossy(&output.stderr)
                );
                assert!(stdout.contains(proto), "{stdout}");
                assert!(
                    stdout.contains(expected),
                    "{method} {name} {qtype}: {stdout}"
                );
            }
        }
    }
}

#[tokio::test]
async fn doh_without_tls_serves_plain_http() {
    let _watchdog = Watchdog::new("doh_without_tls_serves_plain_http", TEST_TIMEOUT);
    let server = start_doh_with("doh_in", false, false).await;
    let url = format!("http://{}/dns-query", server.addr);
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap();
    let message = query(0, "www.doh.test", TYPE::A);
    assert_answer(
        get(&client, &url, &message).await,
        0,
        reqwest::Version::HTTP_11,
    )
    .await;
}

fn query_with_subnet(id: u16, name: &str, subnet: Option<&str>) -> Vec<u8> {
    let bytes = query(id, name, TYPE::A);
    let mut packet = Packet::parse(&bytes).unwrap();
    if let Some(subnet) = subnet {
        ecs::set(&mut packet, Some(ClientSubnet::parse(subnet).unwrap()));
    }
    packet.build_bytes_vec().unwrap()
}

async fn ecs_exchange(
    server: &DohServer,
    message: &[u8],
    forwarded_for: Option<&str>,
) -> Packet<'static> {
    let client = http_client(server, client_tls(&server.cert, None, &[b"h2"]), false);
    let mut request = client
        .post(server.url())
        .header("content-type", DNS_MESSAGE)
        .body(message.to_vec());
    if let Some(ip) = forwarded_for {
        request = request.header("x-forwarded-for", ip);
    }
    let response = request.send().await.unwrap();
    assert_eq!(response.status(), 200);
    let body = response.bytes().await.unwrap();
    let packet = Packet::parse(&body).unwrap();
    let mut owned = Packet::new_reply(packet.id());
    *owned.opt_mut() = packet.opt().cloned().map(|o| o.into_owned());
    owned.answers = packet.answers.into_iter().map(|r| r.into_owned()).collect();
    owned
}

fn seen(server: &DohServer) -> Vec<Option<String>> {
    std::mem::take(&mut server.seen.lock().unwrap())
}

fn a_answer(packet: &Packet<'_>) -> Ipv4Addr {
    match packet.answers.first().map(|r| &r.rdata) {
        Some(RData::A(a)) => Ipv4Addr::from(a.address),
        other => panic!("expected an A answer, got {other:?}"),
    }
}

#[tokio::test]
async fn ecs_dns_client_adds_configured_subnet() {
    let _watchdog = Watchdog::new("ecs_dns_client_adds_configured_subnet", TEST_TIMEOUT);
    let server = start_doh_custom(
        "doh_in",
        false,
        true,
        serde_json::json!({}),
        serde_json::json!({ "client_subnet": "192.0.2.0/24" }),
    )
    .await;

    // Without ECS from the client the server's subnet goes upstream, and the client gets
    // back neither ECS nor an OPT record it never asked for.
    let response = ecs_exchange(&server, &query(0, "www.doh.test", TYPE::A), None).await;
    assert_eq!(seen(&server), vec![Some("192.0.2.0/24".to_string())]);
    assert_eq!(a_answer(&response), Ipv4Addr::new(192, 0, 2, 1));
    assert!(response.opt().is_none());

    // A client subnet wins without override, and is echoed back with the upstream scope.
    let message = query_with_subnet(0, "www.doh.test", Some("198.51.100.0/24"));
    let response = ecs_exchange(&server, &message, None).await;
    assert_eq!(seen(&server), vec![Some("198.51.100.0/24".to_string())]);
    assert_eq!(a_answer(&response), Ipv4Addr::new(198, 51, 100, 1));
    let echoed = ecs::get(&response).unwrap();
    assert_eq!(echoed.to_string(), "198.51.100.0/24");
    assert_eq!(echoed.scope(), 24);
}

#[tokio::test]
async fn ecs_dns_client_override_replaces_client_subnet() {
    let _watchdog = Watchdog::new(
        "ecs_dns_client_override_replaces_client_subnet",
        TEST_TIMEOUT,
    );
    let server = start_doh_custom(
        "doh_in",
        false,
        true,
        serde_json::json!({}),
        serde_json::json!({ "client_subnet": "192.0.2.9", "client_subnet_override": true }),
    )
    .await;

    let message = query_with_subnet(0, "www.doh.test", Some("198.51.100.0/24"));
    let response = ecs_exchange(&server, &message, None).await;
    assert_eq!(seen(&server), vec![Some("192.0.2.0/24".to_string())]);
    assert_eq!(a_answer(&response), Ipv4Addr::new(192, 0, 2, 1));
    // The client still sees its own subnet in the reply.
    assert_eq!(ecs::get(&response).unwrap().to_string(), "198.51.100.0/24");
}

#[tokio::test]
async fn ecs_inbound_auto_uses_client_address_and_forwarded_header() {
    let _watchdog = Watchdog::new(
        "ecs_inbound_auto_uses_client_address_and_forwarded_header",
        TEST_TIMEOUT,
    );
    let server = start_doh_custom(
        "doh_in",
        false,
        true,
        serde_json::json!({
            "client_subnet": "auto",
            "client_subnet_prefix": { "ipv4": 16 },
            "client_subnet_header": "X-Forwarded-For"
        }),
        serde_json::json!({}),
    )
    .await;
    let message = query(0, "www.doh.test", TYPE::A);

    let response = ecs_exchange(&server, &message, None).await;
    assert_eq!(seen(&server), vec![Some("127.0.0.0/16".to_string())]);
    assert!(response.opt().is_none());

    let response = ecs_exchange(&server, &message, Some("203.0.113.9, 10.0.0.1")).await;
    assert_eq!(seen(&server), vec![Some("203.0.0.0/16".to_string())]);
    assert_eq!(a_answer(&response), Ipv4Addr::new(203, 0, 0, 1));

    // A /0 subnet means the client opted out; its address must not be sent.
    let opt_out = query_with_subnet(0, "www.doh.test", Some("0.0.0.0/0"));
    ecs_exchange(&server, &opt_out, Some("203.0.113.9")).await;
    assert_eq!(seen(&server), vec![Some("0.0.0.0/0".to_string())]);
}

#[tokio::test]
async fn ecs_inbound_fixed_and_strip() {
    let _watchdog = Watchdog::new("ecs_inbound_fixed_and_strip", TEST_TIMEOUT);
    let message = query_with_subnet(0, "www.doh.test", Some("198.51.100.0/24"));

    let fixed = start_doh_custom(
        "doh_in",
        false,
        true,
        serde_json::json!({ "client_subnet": "192.0.2.0/24" }),
        serde_json::json!({}),
    )
    .await;
    let response = ecs_exchange(&fixed, &message, None).await;
    assert_eq!(seen(&fixed), vec![Some("192.0.2.0/24".to_string())]);
    assert_eq!(ecs::get(&response).unwrap().to_string(), "198.51.100.0/24");
    drop(fixed);

    let strip = start_doh_custom(
        "doh_in",
        false,
        true,
        serde_json::json!({ "client_subnet": "strip" }),
        serde_json::json!({}),
    )
    .await;
    let response = ecs_exchange(&strip, &message, None).await;
    assert_eq!(seen(&strip), vec![None]);
    assert_eq!(a_answer(&response), Ipv4Addr::LOCALHOST);
}

#[tokio::test]
async fn ecs_cache_is_keyed_by_subnet() {
    let _watchdog = Watchdog::new("ecs_cache_is_keyed_by_subnet", TEST_TIMEOUT);
    let server = start_doh_custom(
        "doh_in",
        false,
        true,
        serde_json::json!({ "client_subnet": "auto", "client_subnet_header": "X-Forwarded-For" }),
        serde_json::json!({ "cache": "dns_cache" }),
    )
    .await;
    let message = query(0, "geo.doh.test", TYPE::A);

    let first = ecs_exchange(&server, &message, Some("203.0.113.9")).await;
    let other = ecs_exchange(&server, &message, Some("198.51.100.9")).await;
    let again = ecs_exchange(&server, &message, Some("203.0.113.200")).await;

    assert_eq!(a_answer(&first), Ipv4Addr::new(203, 0, 113, 1));
    assert_eq!(a_answer(&other), Ipv4Addr::new(198, 51, 100, 1));
    assert_eq!(a_answer(&again), Ipv4Addr::new(203, 0, 113, 1));
    assert_eq!(
        seen(&server),
        vec![
            Some("203.0.113.0/24".to_string()),
            Some("198.51.100.0/24".to_string())
        ],
        "the third query must be served from the 203.0.113.0/24 cache entry"
    );
}

#[tokio::test]
async fn ecs_go_miekg_dns_interop() {
    let _watchdog = Watchdog::new("ecs_go_miekg_dns_interop", TEST_TIMEOUT);
    let Some(client) = tokio::task::spawn_blocking(build_go_client).await.unwrap() else {
        return;
    };
    let server = start_doh_custom(
        "doh_in",
        false,
        true,
        serde_json::json!({}),
        serde_json::json!({ "client_subnet": "192.0.2.0/24" }),
    )
    .await;
    let url = format!("https://127.0.0.1:{}/dns-query", server.addr.port());

    let run = |ecs: &'static str| {
        let client = client.clone();
        let url = url.clone();
        tokio::task::spawn_blocking(move || {
            let output = Command::new(&client)
                .args(["-url", &url, "-name", "www.doh.test", "-type", "A"])
                .args(["-ecs", ecs])
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            String::from_utf8_lossy(&output.stdout).into_owned()
        })
    };

    // miekg/dns encodes the client subnet; quicproxy must pass it upstream intact and
    // miekg/dns must parse the echoed option.
    let stdout = run("198.51.100.0/24").await.unwrap();
    assert_eq!(seen(&server), vec![Some("198.51.100.0/24".to_string())]);
    assert!(stdout.contains("A 198.51.100.1"), "{stdout}");
    assert!(stdout.contains("ECS 198.51.100.0/24/24"), "{stdout}");

    let stdout = run("2001:db8:1234::/48").await.unwrap();
    assert_eq!(seen(&server), vec![Some("2001:db8:1234::/48".to_string())]);
    assert!(stdout.contains("ECS 2001:db8:1234::/48/24"), "{stdout}");

    let stdout = run("").await.unwrap();
    assert_eq!(seen(&server), vec![Some("192.0.2.0/24".to_string())]);
    assert!(!stdout.contains("ECS"), "{stdout}");
}
