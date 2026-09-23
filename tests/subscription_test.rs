//! Core API subscription and QR endpoints.
//!
//! Boots a real core (core API + observe cache + trojan inbound) and verifies
//! that the public `/sub` endpoint renders node links with unlimited
//! `subscription-userinfo`, while `/qr` renders a plain-text QR behind auth.

use quicproxy::bootstrap;
use quicproxy::config::Config;
use serde_json::json;
use std::io::Write;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;

const API_PASSWORD: &str = "api-secret";
const USERNAME: &str = "seed";
const PASSWORD: &str = "seed-pw";

struct Core {
    shutdown: oneshot::Sender<()>,
    handle: JoinHandle<()>,
    api_base: String,
}

async fn free_port() -> u16 {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    listener.local_addr().unwrap().port()
}

async fn wait_for_port(port: u16) {
    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    loop {
        if TcpStream::connect(addr).await.is_ok() {
            return;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "core did not start listening on {addr}"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

async fn start_core(config_path: &Path, api_port: u16) -> Core {
    let config = Config::load(Some(config_path.to_path_buf())).expect("load config");
    let (shutdown, rx) = oneshot::channel();
    let handle = tokio::spawn(async move {
        let signal = async move {
            let _ = rx.await;
            Ok(())
        };
        if let Err(error) = bootstrap::run_with_signal(config, signal).await {
            eprintln!("core exited with error: {error:#}");
        }
    });
    wait_for_port(api_port).await;
    Core {
        shutdown,
        handle,
        api_base: format!("http://127.0.0.1:{api_port}"),
    }
}

impl Core {
    async fn stop(self) {
        let _ = self.shutdown.send(());
        tokio::time::timeout(Duration::from_secs(20), self.handle)
            .await
            .expect("core shutdown timed out")
            .expect("core task panicked");
    }

    fn client(&self) -> reqwest::Client {
        reqwest::Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap()
    }
}

fn write_config(api_port: u16, inbound_port: u16, db_path: &Path) -> PathBuf {
    let config = json!({
        "users": [{ "username": USERNAME, "password": PASSWORD }],
        "inbounds": {
            "trojan_in": {
                "type": "trojan",
                "address": "127.0.0.1",
                "port": inbound_port,
                "username": USERNAME,
                "password": PASSWORD,
                "tls": { "enable": true, "sni": "cdn.example.com" }
            }
        },
        "outbounds": {
            "default_server": "direct_out",
            "servers": { "direct_out": { "type": "direct" } }
        },
        "dns": {
            "default_server": "local_dns",
            "servers": {
                "local_dns": {
                    "type": "udp",
                    "address": "8.8.8.8",
                    "port": 53,
                    "outbound": "direct_out"
                }
            }
        },
        "router": { "default_mode": "direct" },
        "log": { "level": "warn" },
        "cache": { "obs_cache": { "path": db_path.to_string_lossy() } },
        "observe": { "enabled": true, "cache": "obs_cache", "log_interval": 30 },
        "api": { "address": "127.0.0.1", "port": api_port, "password": API_PASSWORD },
        "subscription": {
            "host": ["203.0.113.7", "2001:db8::1"],
            "name": "TestNode",
            "update_interval": 24,
            "web_page_url": "https://example.com"
        }
    });

    let mut file = tempfile::NamedTempFile::new().unwrap();
    file.write_all(config.to_string().as_bytes()).unwrap();
    let (_file, path) = file.keep().unwrap();
    path
}

#[tokio::test]
async fn subscription_and_qr_endpoints() {
    let db_path =
        std::env::temp_dir().join(format!("quicproxy-subscription-{}.db", std::process::id()));
    let _ = std::fs::remove_file(&db_path);

    let api_port = free_port().await;
    let inbound_port = free_port().await;
    let config_path = write_config(api_port, inbound_port, &db_path);

    let core = start_core(&config_path, api_port).await;
    let client = core.client();

    // Public subscription with valid user credentials.
    let response = client
        .get(format!("{}/sub", core.api_base))
        .query(&[("username", USERNAME), ("password", PASSWORD)])
        .send()
        .await
        .expect("GET /sub");
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get("subscription-userinfo")
            .and_then(|v| v.to_str().ok()),
        Some("upload=0; download=0; total=0; expire=0")
    );
    assert_eq!(
        response
            .headers()
            .get("profile-update-interval")
            .and_then(|v| v.to_str().ok()),
        Some("24")
    );
    let body = response.text().await.expect("sub body");
    let lines: Vec<&str> = body.lines().collect();
    assert_eq!(
        lines.first().copied(),
        Some(
            format!(
                "trojan://{PASSWORD}@[2001:db8::1]:{inbound_port}?sni=cdn.example.com&type=tcp&insecure=true#TestNode-trojan-IPv6"
            )
            .as_str()
        ),
        "IPv6 node should lead the subscription body: {body}"
    );
    assert_eq!(
        lines.get(1).copied(),
        Some(
            format!(
                "trojan://{PASSWORD}@203.0.113.7:{inbound_port}?sni=cdn.example.com&type=tcp&insecure=true#TestNode-trojan-IPv4"
            )
            .as_str()
        ),
        "IPv4 node should follow: {body}"
    );
    assert!(
        body.contains("sni=cdn.example.com"),
        "subscription should carry the inbound SNI: {body}"
    );

    // Wrong password must be rejected.
    let response = client
        .get(format!("{}/sub", core.api_base))
        .query(&[("username", USERNAME), ("password", "nope")])
        .send()
        .await
        .expect("GET /sub wrong password");
    assert_eq!(response.status(), reqwest::StatusCode::UNAUTHORIZED);

    // QR requires the API password.
    let unauthorized = client
        .get(format!("{}/qr", core.api_base))
        .query(&[("text", "hello")])
        .send()
        .await
        .expect("GET /qr unauthorized");
    assert_eq!(unauthorized.status(), reqwest::StatusCode::UNAUTHORIZED);

    let authorized = client
        .get(format!("{}/qr", core.api_base))
        .query(&[("text", "hello")])
        .bearer_auth(API_PASSWORD)
        .send()
        .await
        .expect("GET /qr");
    assert_eq!(authorized.status(), reqwest::StatusCode::OK);
    let qr = authorized.text().await.expect("qr body");
    assert!(
        qr.contains('\u{2588}'),
        "QR should contain dark modules: {qr:?}"
    );

    core.stop().await;
    let _ = std::fs::remove_file(&db_path);
    let _ = std::fs::remove_file(&config_path);
}
