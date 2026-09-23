//! User management persistence across core restarts.
//!
//! Boots a real core (core API + observe cache + trojan inbound), adds a user
//! through the core API, restarts the core and verifies the user is restored
//! both as an inbound credential and with its accumulated traffic counters.
//! Deleting a user must keep it gone after the next restart.

use quicproxy::bootstrap;
use quicproxy::config::Config;
use quicproxy::proxy::observe::{credential_hash, get_observer};
use serde_json::json;
use std::io::Write;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;

const API_PASSWORD: &str = "api-secret";
const INBOUND_TAG: &str = "trojan_in";

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

    async fn add_user(&self, username: &str, password: &str) -> reqwest::StatusCode {
        self.client()
            .post(format!("{}/users", self.api_base))
            .bearer_auth(API_PASSWORD)
            .json(&json!({ "username": username, "password": password }))
            .send()
            .await
            .expect("POST /users")
            .status()
    }

    async fn delete_user(&self, username: &str) -> reqwest::StatusCode {
        self.client()
            .delete(format!("{}/users", self.api_base))
            .query(&[("username", username)])
            .bearer_auth(API_PASSWORD)
            .send()
            .await
            .expect("DELETE /users")
            .status()
    }

    async fn list_users(&self) -> Vec<String> {
        let users: Vec<serde_json::Value> = self
            .client()
            .get(format!("{}/users", self.api_base))
            .bearer_auth(API_PASSWORD)
            .send()
            .await
            .expect("GET /users")
            .json()
            .await
            .expect("GET /users json");
        users
            .into_iter()
            .filter_map(|user| user["username"].as_str().map(str::to_owned))
            .collect()
    }
}

fn trojan_credential(username: &str, password: &str) -> Vec<u8> {
    credential_hash("trojan", username, password).expect("trojan credential")
}

/// The trojan inbound authenticates against the observer's credentials, so this
/// proves the user is usable through the inbound after a restart.
fn assert_user_authenticates(username: &str, password: &str) {
    let observer = get_observer().expect("observer should be initialized");
    let credential = trojan_credential(username, password);
    let (authenticated, _) = observer
        .authenticate(INBOUND_TAG, &credential)
        .unwrap_or_else(|| panic!("user '{username}' should authenticate on {INBOUND_TAG}"));
    assert_eq!(authenticated, username);
}

fn assert_user_rejected(username: &str, password: &str) {
    let observer = get_observer().expect("observer should be initialized");
    let credential = trojan_credential(username, password);
    assert!(
        observer.authenticate(INBOUND_TAG, &credential).is_none(),
        "user '{username}' should not authenticate on {INBOUND_TAG}"
    );
}

fn user_traffic(username: &str) -> Option<(u64, u64)> {
    let observer = get_observer().expect("observer should be initialized");
    observer
        .collect_user_stats(Some(username), false)
        .into_iter()
        .next()
        .map(|stats| (stats.upload, stats.download))
}

fn write_config(api_port: u16, inbound_port: u16, db_path: &Path) -> PathBuf {
    let config = json!({
        "users": [{ "username": "seed", "password": "seed-pw" }],
        "inbounds": {
            INBOUND_TAG: {
                "type": "trojan",
                "address": "127.0.0.1",
                "port": inbound_port,
                "tls": { "enable": true }
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
        "api": { "address": "127.0.0.1", "port": api_port, "password": API_PASSWORD }
    });

    let mut file = tempfile::NamedTempFile::new().unwrap();
    file.write_all(config.to_string().as_bytes()).unwrap();
    let (_file, path) = file.keep().unwrap();
    path
}

#[tokio::test]
async fn users_survive_restart_and_deletion_stays_deleted() {
    let db_path = std::env::temp_dir().join(format!(
        "quicproxy-user-persist-{}.db",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&db_path);

    let api_port = free_port().await;
    let inbound_port = free_port().await;
    let config_path = write_config(api_port, inbound_port, &db_path);

    // First boot: only the config-seeded user exists.
    let core = start_core(&config_path, api_port).await;
    assert_user_authenticates("seed", "seed-pw");
    assert_eq!(user_traffic("seed"), Some((0, 0)));

    // Add alice through the API, give her traffic and persist it.
    assert_eq!(
        core.add_user("alice", "alice-pw").await,
        reqwest::StatusCode::OK
    );
    assert_user_authenticates("alice", "alice-pw");
    {
        let observer = get_observer().unwrap();
        observer
            .user_stats("alice")
            .expect("alice stats")
            .add_traffic(1_234, 5_678);
        observer.log_statistics();
    }
    assert_eq!(user_traffic("alice"), Some((1_234, 5_678)));
    core.stop().await;

    // Second boot: alice must come back with credential and traffic intact.
    let core = start_core(&config_path, api_port).await;
    assert_user_authenticates("alice", "alice-pw");
    assert_eq!(user_traffic("alice"), Some((1_234, 5_678)));
    assert!(
        core.list_users().await.iter().any(|user| user == "alice"),
        "GET /users should list the restored user"
    );

    // Delete alice and restart: she must not reappear.
    assert_eq!(
        core.delete_user("alice").await,
        reqwest::StatusCode::NO_CONTENT
    );
    assert!(user_traffic("alice").is_none());
    assert_user_rejected("alice", "alice-pw");
    core.stop().await;

    let core = start_core(&config_path, api_port).await;
    assert!(user_traffic("alice").is_none());
    assert_user_rejected("alice", "alice-pw");
    assert!(
        !core.list_users().await.iter().any(|user| user == "alice"),
        "deleted user should stay gone after restart"
    );
    assert_user_authenticates("seed", "seed-pw");

    core.stop().await;
    let _ = std::fs::remove_file(&db_path);
    let _ = std::fs::remove_file(&config_path);
}
