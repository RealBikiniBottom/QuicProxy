mod common;
use common::{TestContext, Watchdog};
use std::io::Write;
use std::time::Duration;
use tempfile::NamedTempFile;

const TEST_TIMEOUT: Duration = Duration::from_secs(30);

#[tokio::test]
async fn test_mix_inbound_direct_outbound() {
    let _watchdog = Watchdog::new("test_mix_inbound_direct_outbound", TEST_TIMEOUT);

    let test_fut = async {
        let mut context = TestContext::new().await;

        let config_json = serde_json::json!({
            "inbounds": {
                "mix_in": {
                    "type": "mix",
                    "address": "127.0.0.1",
                    "port": 0
                }
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
            "outbounds": {
                "default_server": "direct_out",
                "servers": {
                    "direct_out": {
                        "type": "direct"
                    }
                }
            },
            "router": {
                "default_mode": "proxy"
            },
            "log": {
                "level": "debug"
            }
        });

        let mut temp_file = NamedTempFile::new().unwrap();
        write!(temp_file, "{}", config_json.to_string()).unwrap();
        let (_file, path) = temp_file.keep().unwrap();

        context.start_proxy_with_config_file(&path, "mix_in").await;
        context.test_http_get().await;

        let _ = std::fs::remove_file(path);
    };

    tokio::time::timeout(TEST_TIMEOUT, test_fut)
        .await
        .expect("test_mix_inbound_direct_outbound timed out");
}

#[tokio::test]
async fn test_config_file_loading() {
    let _watchdog = Watchdog::new("test_config_file_loading", TEST_TIMEOUT);

    let test_fut = async {
        let mut context = TestContext::new().await;

        let config_path = std::path::PathBuf::from("tests/test_config.json");

        context
            .start_proxy_with_config_file(&config_path, "mix_test")
            .await;
        context.test_http_get().await;
    };

    tokio::time::timeout(TEST_TIMEOUT, test_fut)
        .await
        .expect("test_config_file_loading timed out");
}

#[tokio::test]
async fn test_socks5_inbound_direct_outbound() {
    let _watchdog = Watchdog::new("test_socks5_inbound_direct_outbound", TEST_TIMEOUT);

    let test_fut = async {
        let mut context = TestContext::new().await;

        let config_json = serde_json::json!({
            "inbounds": {
                "socks5_in": {
                    "type": "socks5",
                    "address": "127.0.0.1",
                    "port": 0
                }
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
            "outbounds": {
                "default_server": "direct_out",
                "servers": {
                    "direct_out": {
                        "type": "direct"
                    }
                }
            },
            "router": {
                "default_mode": "proxy"
            },
            "log": {
                "level": "debug"
            }
        });

        let mut temp_file = NamedTempFile::new().unwrap();
        write!(temp_file, "{}", config_json.to_string()).unwrap();
        let (_file, path) = temp_file.keep().unwrap();

        context
            .start_proxy_with_config_file(&path, "socks5_in")
            .await;
        context.test_http_get().await;

        let _ = std::fs::remove_file(path);
    };

    tokio::time::timeout(TEST_TIMEOUT, test_fut)
        .await
        .expect("test_socks5_inbound_direct_outbound timed out");
}
