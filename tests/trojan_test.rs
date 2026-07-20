mod common;
use common::{TestContext, Watchdog};
use std::time::Duration;
use tokio::io::AsyncWriteExt;

const TEST_TIMEOUT: Duration = Duration::from_secs(60);

#[tokio::test]
async fn test_trojan_jls_full_chain() {
    let _watchdog = Watchdog::new("test_trojan_jls_full_chain", TEST_TIMEOUT);
    let mut context = TestContext::new().await;
    let jls_username = "trojan-jls-user";
    let jls_password = "trojan-jls-password";

    let server_config = serde_json::json!({
        "inbounds": {
            "trojan_in": {
                "type": "trojan",
                "address": "127.0.0.1",
                "port": 0,
                "password": "trojan-password",
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
        "router": { "default_mode": "direct" },
        "log": { "level": "debug" }
    });

    let server_idx = context.start_proxy(server_config, "trojan_in").await;
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
            "default_server": "trojan_out",
            "servers": {
                "trojan_out": {
                    "type": "trojan",
                    "address": "127.0.0.1",
                    "port": server_port,
                    "password": "trojan-password",
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
        "router": { "default_mode": "proxy" },
        "log": { "level": "debug" }
    });

    context.start_proxy(client_config, "socks_in").await;

    tokio::time::timeout(Duration::from_secs(15), context.test_http_get())
        .await
        .expect("Trojan JLS test timed out");
}

#[tokio::test]
#[ignore = "requires separate process per proxy due to global OUTBOUNDS_MAP"]
async fn test_socks5_to_trojan_chain() {
    let _watchdog = Watchdog::new("test_socks5_to_trojan_chain", TEST_TIMEOUT);
    let test_fut = async {
        let mut context = TestContext::new().await;

        let (cert_path, key_path) = TestContext::generate_tls_files();

        println!("Cert path: {:?}", cert_path);

        let server_config = serde_json::json!({
            "inbounds": {
                "trojan_in": {
                    "type": "trojan",
                    "address": "127.0.0.1",
                    "port": 0,
                    "password": "password",
                    "transport": {
                        "type": "tcp"
                    },
                    "tls": {
                        "enable": true,
                        "cert": cert_path.to_str().unwrap(),
                        "key": key_path.to_str().unwrap()
                    }
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
                "default_mode": "direct"
            },
            "log": {
                "level": "debug"
            }
        });

        let server_idx = context.start_proxy(server_config, "trojan_in").await;
        let server_instance = &context.proxies[server_idx];
        let server_port = server_instance.port;
        println!("Trojan Server started on port {}", server_port);

        let client_config = serde_json::json!({
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
                        "outbound": "trojan_out"
                    }
                }
            },
            "outbounds": {
                "default_server": "trojan_out",
                "servers": {
                    "trojan_out": {
                        "type": "trojan",
                        "address": "127.0.0.1",
                        "port": server_port,
                        "password": "password",
                        "transport": {
                            "type": "tcp"
                        },
                        "tls": {
                            "enable": true,
                            "insecure": false,
                            "ca": cert_path.to_str().unwrap(),
                            "server_name": "localhost"
                        }
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

        let client_idx = context.start_proxy(client_config, "socks5_in").await;
        let _client_instance = &context.proxies[client_idx];
        println!("Socks5 Client started on port {}", _client_instance.port);

        context.test_tcp_echo().await;

        context.test_udp_echo().await;

        let client_config_timeout = serde_json::json!({
            "inbounds": {
                "socks5_in_timeout": {
                    "type": "socks5",
                    "address": "127.0.0.1",
                    "port": 0,
                    "timeout": 3
                }
            },
            "dns": {
                "default_server": "local_dns",
                "servers": {
                    "local_dns": {
                        "type": "udp",
                        "address": "8.8.8.8",
                        "port": 53,
                        "outbound": "trojan_out"
                    }
                }
            },
            "outbounds": {
                "default_server": "trojan_out",
                "servers": {
                    "trojan_out": {
                        "type": "trojan",
                        "address": "127.0.0.1",
                        "port": server_port,
                        "password": "password",
                        "transport": {
                            "type": "tcp"
                        },
                        "tls": {
                            "enable": true,
                            "insecure": false,
                            "ca": cert_path.to_str().unwrap(),
                            "server_name": "localhost"
                        }
                    }
                }
            },
            "router": {
                "default_mode": "direct"
            },
            "log": {
                "level": "debug"
            }
        });

        let client_timeout_idx = context
            .start_proxy(client_config_timeout, "socks5_in_timeout")
            .await;
        let _client_timeout_instance = &context.proxies[client_timeout_idx];
        println!(
            "Socks5 Client (Timeout) started on port {}",
            _client_timeout_instance.port
        );

        context.test_udp_timeout().await;

        let _ = std::fs::remove_file(&cert_path);
        let _ = std::fs::remove_file(&key_path);
    };

    tokio::time::timeout(TEST_TIMEOUT, test_fut)
        .await
        .expect("test_socks5_to_trojan_chain timed out");
}

#[tokio::test]
#[ignore = "requires separate process per proxy due to global OUTBOUNDS_MAP"]
async fn test_trojan_udp_to_dns_outbound() {
    let _watchdog = Watchdog::new("test_trojan_udp_to_dns_outbound", TEST_TIMEOUT);
    let test_fut = async {
        let mut context = TestContext::new().await;

        let (cert_path, key_path) = TestContext::generate_tls_files();

        let server_config = serde_json::json!({
            "inbounds": {
                "trojan_in": {
                    "type": "trojan",
                    "address": "127.0.0.1",
                    "port": 0,
                    "password": "password",
                    "transport": {
                        "type": "tcp"
                    },
                    "tls": {
                        "enable": true,
                        "cert": cert_path.to_str().unwrap(),
                        "key": key_path.to_str().unwrap()
                    }
                }
            },
            "outbounds": {
                "default_server": "dns_out",
                "servers": {
                    "dns_out": {
                        "type": "dns",
                        "dns": "real_dns"
                    },
                    "direct_out": {
                        "type": "direct"
                    }
                }
            },
            "dns": {
                "default_server": "real_dns",
                "servers": {
                    "real_dns": {
                        "type": "udp",
                        "address": context.mock_server_dns_addr.ip().to_string(),
                        "port": context.mock_server_dns_addr.port(),
                        "outbound": "direct_out"
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

        let server_idx = context.start_proxy(server_config, "trojan_in").await;
        let server_instance = &context.proxies[server_idx];
        let server_port = server_instance.port;

        let client_config = serde_json::json!({
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
                        "outbound": "trojan_out"
                    }
                }
            },
            "outbounds": {
                "default_server": "trojan_out",
                "servers": {
                    "trojan_out": {
                        "type": "trojan",
                        "address": "127.0.0.1",
                        "port": server_port,
                        "password": "password",
                        "transport": {
                            "type": "tcp"
                        },
                        "tls": {
                            "enable": true,
                            "insecure": true,
                            "server_name": "localhost"
                        }
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

        let client_idx = context.start_proxy(client_config, "socks5_in").await;
        let _proxy = &context.proxies[client_idx];

        let dns_fut = async {
            use simple_dns::{CLASS, Name, Packet, Question, TYPE};
            use std::net::SocketAddr;
            use tokio::net::UdpSocket;

            let (relay_socket_addr, mut stream) = context.create_socks5_udp_association().await;

            let udp_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let dns_dest = SocketAddr::new("8.8.8.8".parse().unwrap(), 53);

            let mut dns_packet = Packet::new_query(1234);
            let name = Name::new("example.com").unwrap();
            dns_packet.questions.push(Question::new(
                name,
                simple_dns::QTYPE::TYPE(TYPE::A),
                simple_dns::QCLASS::CLASS(CLASS::IN),
                false,
            ));
            let dns_query_bytes = dns_packet.build_bytes_vec().unwrap();

            context
                .send_socks5_udp_packet(&udp_socket, relay_socket_addr, dns_dest, &dns_query_bytes)
                .await;

            let mut recv_buf = [0u8; 2048];
            let dns_resp_bytes = context
                .recv_socks5_udp_packet(&udp_socket, &mut recv_buf)
                .await;

            let resp_packet = Packet::parse(&dns_resp_bytes).expect("Failed to parse DNS response");
            assert_eq!(resp_packet.id(), 1234);
            assert!(
                !resp_packet.answers.is_empty(),
                "DNS response should have answers"
            );

            let answer = &resp_packet.answers[0];
            match &answer.rdata {
                simple_dns::rdata::RData::A(_a) => {
                    println!("Received A record from DNS Outbound");
                }
                _ => panic!("Expected A record"),
            }

            tokio::time::sleep(Duration::from_millis(500)).await;

            let mut dns_packet2 = Packet::new_query(5678);
            let name2 = Name::new("example.org").unwrap();
            dns_packet2.questions.push(Question::new(
                name2,
                simple_dns::QTYPE::TYPE(TYPE::A),
                simple_dns::QCLASS::CLASS(CLASS::IN),
                false,
            ));
            let dns_query_bytes2 = dns_packet2.build_bytes_vec().unwrap();

            context
                .send_socks5_udp_packet(&udp_socket, relay_socket_addr, dns_dest, &dns_query_bytes2)
                .await;

            let mut recv_buf2 = [0u8; 2048];
            let recv_result2 = tokio::time::timeout(
                Duration::from_secs(5),
                context.recv_socks5_udp_packet(&udp_socket, &mut recv_buf2),
            )
            .await;

            let dns_resp_bytes2 = recv_result2.expect("2nd DNS response timed out");

            let resp_packet2 =
                Packet::parse(&dns_resp_bytes2).expect("Failed to parse 2nd DNS response");
            assert_eq!(resp_packet2.id(), 5678);
            assert!(
                !resp_packet2.answers.is_empty(),
                "2nd DNS response should have answers"
            );
            println!("Received 2nd A record, proving session can re-establish correctly.");

            stream.shutdown().await.unwrap();
        };

        if let Err(_) = tokio::time::timeout(Duration::from_secs(15), dns_fut).await {
            panic!("DNS sub-test timed out after 15s");
        }

        let _ = std::fs::remove_file(cert_path);
        let _ = std::fs::remove_file(key_path);
    };

    tokio::time::timeout(TEST_TIMEOUT, test_fut)
        .await
        .expect("test_trojan_udp_to_dns_outbound timed out");
}

#[tokio::test]
#[ignore = "requires separate process per proxy due to global OUTBOUNDS_MAP"]
async fn test_socks5_to_trojan_quic_chain() {
    let _watchdog = Watchdog::new("test_socks5_to_trojan_quic_chain", TEST_TIMEOUT);
    let test_fut = async {
        let mut context = TestContext::new().await;

        let (cert_path, key_path) = TestContext::generate_tls_files();

        let server_config = serde_json::json!({
            "inbounds": {
                "trojan_in": {
                    "type": "trojan",
                    "address": "127.0.0.1",
                    "port": 0,
                    "password": "password",
                    "transport": {
                        "type": "quic"
                    },
                    "tls": {
                        "enable": true,
                        "cert": cert_path.to_str().unwrap(),
                        "key": key_path.to_str().unwrap(),
                        "sni": "localhost"
                    }
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
                "default_mode": "direct"
            },
            "log": {
                "level": "debug"
            }
        });

        let server_idx = context.start_proxy(server_config, "trojan_in").await;
        let server_port = context.proxies[server_idx].port;

        let client_config = serde_json::json!({
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
                        "outbound": "trojan_out"
                    }
                }
            },
            "outbounds": {
                "default_server": "trojan_out",
                "servers": {
                    "trojan_out": {
                        "type": "trojan",
                        "address": "127.0.0.1",
                        "port": server_port,
                        "password": "password",
                        "transport": {
                            "type": "quic"
                        },
                        "tls": {
                            "enable": true,
                            "insecure": false,
                            "ca": cert_path.to_str().unwrap(),
                            "sni": "localhost"
                        }
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

        let client_idx = context.start_proxy(client_config, "socks5_in").await;
        let _client_instance = &context.proxies[client_idx];

        context.test_tcp_echo().await;
        context.test_udp_echo().await;

        let _ = std::fs::remove_file(&cert_path);
        let _ = std::fs::remove_file(&key_path);
    };

    tokio::time::timeout(TEST_TIMEOUT, test_fut)
        .await
        .expect("test_socks5_to_trojan_quic_chain timed out");
}
