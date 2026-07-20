mod common;
use common::{TestContext, Watchdog};
use std::net::TcpListener;
use std::time::Duration;

const TEST_TIMEOUT: Duration = Duration::from_secs(60);

fn find_free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("Failed to bind");
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    port
}

// These integration tests use full proxy bootstrap with global OUTBOUNDS_MAP.
// They are ignored by default because running two proxy instances in the same
// process corrupts the global outbound state. The protocol-level tests are in
// the crate's #[cfg(test)] modules (src/proxy/outbound/anytls.rs and
// src/proxy/inbound/anytls.rs).
// Run with: cargo test --test anytls_test -- --ignored --nocapture --test-threads=1

#[tokio::test]
async fn test_anytls_jls_full_chain() {
    let _watchdog = Watchdog::new("test_anytls_jls_full_chain", TEST_TIMEOUT);
    let mut context = TestContext::new().await;
    let jls_username = "anytls-jls-user";
    let jls_password = "anytls-jls-password";

    let server_config = serde_json::json!({
        "inbounds": {
            "anytls_in": {
                "type": "anytls",
                "address": "127.0.0.1",
                "port": 0,
                "password": "anytls-password",
                "transport": { "type": "tcp" },
                "tls": {
                    "enable": true,
                    "server_name": "localhost",
                    "enable_jls": true,
                    "jls_username": jls_username,
                    "jls_password": jls_password
                }
            }
        },
        "outbounds": {
            "default_server": "direct_out",
            "servers": {
                "direct_out": { "type": "direct" }
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
        "router": { "default_mode": "direct" }
    });

    let server_idx = context.start_proxy(server_config, "anytls_in").await;
    let server_port = context.proxies[server_idx].port;

    let client_config = serde_json::json!({
        "inbounds": {
            "socks_in": {
                "type": "socks5",
                "address": "127.0.0.1",
                "port": 0
            }
        },
        "outbounds": {
            "default_server": "anytls_out",
            "servers": {
                "anytls_out": {
                    "type": "anytls",
                    "address": "127.0.0.1",
                    "port": server_port,
                    "password": "anytls-password",
                    "transport": { "type": "tcp" },
                    "tls": {
                        "enable": true,
                        "insecure": true,
                        "server_name": "localhost",
                        "enable_jls": true,
                        "jls_username": jls_username,
                        "jls_password": jls_password
                    }
                },
                "dns_direct": { "type": "direct" }
            }
        },
        "dns": {
            "default_server": "local_dns",
            "servers": {
                "local_dns": {
                    "type": "udp",
                    "address": "8.8.8.8",
                    "port": 53,
                    "outbound": "dns_direct"
                }
            }
        },
        "router": { "default_mode": "proxy" }
    });

    context.start_proxy(client_config, "socks_in").await;

    tokio::time::timeout(Duration::from_secs(15), context.test_http_get())
        .await
        .expect("AnyTLS JLS test timed out");
}

#[tokio::test]
#[ignore = "requires separate process per proxy due to global OUTBOUNDS_MAP"]
async fn test_socks5_to_anytls_chain() {
    let _watchdog = Watchdog::new("test_socks5_to_anytls_chain", TEST_TIMEOUT);
    let test_fut = async {
        let mut context = TestContext::new().await;
        let (cert_path, key_path) = TestContext::generate_tls_files();

        let server_port = find_free_port();
        let socks5_port = find_free_port();
        println!("Server port: {}, Socks5 port: {}", server_port, socks5_port);

        let server_config = serde_json::json!({
            "inbounds": {
                "anytls_in": {
                    "type": "anytls",
                    "address": "127.0.0.1",
                    "port": server_port,
                    "password": "testpassword123",
                    "transport": {"type": "tcp"},
                    "tls": {
                        "enable": true,
                        "cert": cert_path.to_str().unwrap(),
                        "key": key_path.to_str().unwrap()
                    }
                }
            },
            "outbounds": {
                "servers": {
                    "default_server": {
                        "type": "direct"
                    }
                }
            },
            "dns": {
                "default_server": "real_dns",
                "servers": {
                    "real_dns": {
                        "type": "udp",
                        "address": "223.5.5.5",
                        "port": 53,
                        "outbound": "default_server"
                    }
                }
            },
            "router": {"default_mode": "direct"},
            "log": {"level": "debug"}
        });

        context.start_proxy(server_config, "anytls_in").await;
        println!("Server started");

        let client_config = serde_json::json!({
            "inbounds": {
                "socks5_in": {
                    "type": "socks5",
                    "address": "127.0.0.1",
                    "port": socks5_port
                }
            },
            "outbounds": {
                "servers": {
                    "default_server": {
                        "type": "anytls",
                        "address": "127.0.0.1",
                        "port": server_port,
                        "password": "testpassword123",
                        "transport": {"type": "tcp"},
                        "tls": {
                            "enable": true,
                            "insecure": false,
                            "ca": cert_path.to_str().unwrap(),
                            "server_name": "localhost"
                        }
                    },
                    "zzz_dns_direct": {
                        "type": "direct"
                    }
                }
            },
            "dns": {
                "default_server": "real_dns",
                "servers": {
                    "real_dns": {
                        "type": "udp",
                        "address": "223.5.5.5",
                        "port": 53,
                        "outbound": "zzz_dns_direct"
                    }
                }
            },
            "router": {"default_mode": "proxy"},
            "log": {"level": "debug"}
        });

        context.start_proxy(client_config, "socks5_in").await;
        println!("Client started");

        context.test_tcp_echo().await;
        context.test_udp_echo().await;

        let _ = std::fs::remove_file(&cert_path);
        let _ = std::fs::remove_file(&key_path);
    };

    tokio::time::timeout(TEST_TIMEOUT, test_fut)
        .await
        .expect("test_socks5_to_anytls_chain timed out");
}

#[tokio::test]
#[ignore = "requires separate process per proxy due to global OUTBOUNDS_MAP"]
async fn test_anytls_insecure() {
    let _watchdog = Watchdog::new("test_anytls_insecure", TEST_TIMEOUT);
    let test_fut = async {
        let mut context = TestContext::new().await;
        let (cert_path, key_path) = TestContext::generate_tls_files();

        let server_port = find_free_port();
        let socks5_port = find_free_port();
        println!("Server port: {}, Socks5 port: {}", server_port, socks5_port);

        let server_config = serde_json::json!({
            "inbounds": {
                "anytls_in": {
                    "type": "anytls",
                    "address": "127.0.0.1",
                    "port": server_port,
                    "password": "insecure_test",
                    "transport": {"type": "tcp"},
                    "tls": {
                        "enable": true,
                        "cert": cert_path.to_str().unwrap(),
                        "key": key_path.to_str().unwrap()
                    }
                }
            },
            "outbounds": {
                "servers": {
                    "default_server": {
                        "type": "direct"
                    }
                }
            },
            "dns": {
                "default_server": "real_dns",
                "servers": {
                    "real_dns": {
                        "type": "udp",
                        "address": "223.5.5.5",
                        "port": 53,
                        "outbound": "default_server"
                    }
                }
            },
            "router": {"default_mode": "direct"},
            "log": {"level": "debug"}
        });

        context.start_proxy(server_config, "anytls_in").await;
        println!("Server started");

        let client_config = serde_json::json!({
            "inbounds": {
                "socks5_in": {
                    "type": "socks5",
                    "address": "127.0.0.1",
                    "port": socks5_port
                }
            },
            "outbounds": {
                "servers": {
                    "default_server": {
                        "type": "anytls",
                        "address": "127.0.0.1",
                        "port": server_port,
                        "password": "insecure_test",
                        "transport": {"type": "tcp"},
                        "tls": {
                            "enable": true,
                            "insecure": true,
                            "server_name": "localhost"
                        }
                    },
                    "zzz_dns_direct": {
                        "type": "direct"
                    }
                }
            },
            "dns": {
                "default_server": "real_dns",
                "servers": {
                    "real_dns": {
                        "type": "udp",
                        "address": "223.5.5.5",
                        "port": 53,
                        "outbound": "zzz_dns_direct"
                    }
                }
            },
            "router": {"default_mode": "proxy"},
            "log": {"level": "debug"}
        });

        context.start_proxy(client_config, "socks5_in").await;
        println!("Client started");

        context.test_tcp_echo().await;
        context.test_udp_echo().await;

        let _ = std::fs::remove_file(&cert_path);
        let _ = std::fs::remove_file(&key_path);
    };

    tokio::time::timeout(TEST_TIMEOUT, test_fut)
        .await
        .expect("test_anytls_insecure timed out");
}
