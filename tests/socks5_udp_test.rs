mod common;
use common::{TestContext, Watchdog};
use std::time::Duration;
use tokio::net::UdpSocket;

const TEST_TIMEOUT: Duration = Duration::from_secs(30);

#[tokio::test]
async fn test_socks5_udp_basic_echo() {
    let _watchdog = Watchdog::new("test_socks5_udp_basic_echo", TEST_TIMEOUT);

    let test_fut = async {
        let mut context = TestContext::new().await;

        let config = serde_json::json!({
            "inbounds": {
                "socks5_in": {
                    "type": "socks5",
                    "address": "127.0.0.1",
                    "port": 0,
                    "timeout": 30
                }
            },
              "dns": {
                "default_server": "local_dns",
                "servers": {
                  "local_dns": {
                    "type": "udp",
                    "address": "8.8.8.8",
                    "outbound": "direct_out",
                    "port": 53,
                  },
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
                "level": "info"
            }
        });

        context.start_proxy(config, "socks5_in").await;
        let proxy = context.last_proxy();
        println!("SOCKS5 proxy started on {}", proxy.addr);

        context.test_udp_echo().await;
        println!("UDP echo test passed");
    };

    tokio::time::timeout(TEST_TIMEOUT, test_fut)
        .await
        .expect("test_socks5_udp_basic_echo timed out");
}

#[tokio::test]
async fn test_socks5_udp_multiple_packets() {
    let _watchdog = Watchdog::new("test_socks5_udp_multiple_packets", TEST_TIMEOUT);

    let test_fut = async {
        let mut context = TestContext::new().await;

        let config = serde_json::json!({
            "inbounds": {
                "socks5_in": {
                    "type": "socks5",
                    "address": "127.0.0.1",
                    "port": 0,
                    "timeout": 30
                }
            },
              "dns": {
                "default_server": "local_dns",
                "servers": {
                  "local_dns": {
                    "type": "udp",
                    "address": "8.8.8.8",
                    "outbound": "direct_out",
                    "port": 53,
                  },
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
            }
        });

        context.start_proxy(config, "socks5_in").await;

        let (relay_addr, _stream) = context.create_socks5_udp_association().await;
        let udp_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let target_addr = context.mock_server_udp_addr;

        const PACKET_COUNT: usize = 10;
        for i in 0..PACKET_COUNT {
            let msg = format!("test-udp-packet-{}", i);
            context
                .send_socks5_udp_packet(&udp_socket, relay_addr, target_addr, msg.as_bytes())
                .await;
        }

        let mut received = vec![false; PACKET_COUNT];
        for _ in 0..PACKET_COUNT {
            match tokio::time::timeout(
                Duration::from_secs(5),
                context.recv_socks5_udp_packet(&udp_socket, &mut [0u8; 2048]),
            )
            .await
            {
                Ok(data) => {
                    let msg = String::from_utf8_lossy(&data);
                    if let Some(idx) = msg
                        .strip_prefix("test-udp-packet-")
                        .and_then(|s| s.parse::<usize>().ok())
                    {
                        if idx < PACKET_COUNT {
                            received[idx] = true;
                        }
                    }
                }
                Err(_) => break,
            }
        }

        let success_count = received.iter().filter(|&&x| x).count();
        assert!(
            success_count >= (PACKET_COUNT * 8 / 10),
            "Too many UDP packets lost: {}/{}",
            success_count,
            PACKET_COUNT
        );

        println!(
            "UDP multiple packets test passed: {}/{} packets received",
            success_count, PACKET_COUNT
        );
    };

    tokio::time::timeout(TEST_TIMEOUT, test_fut)
        .await
        .expect("test_socks5_udp_multiple_packets timed out");
}

#[tokio::test]
async fn test_socks5_udp_concurrent_sessions() {
    let _watchdog = Watchdog::new("test_socks5_udp_concurrent_sessions", TEST_TIMEOUT);

    let test_fut = async {
        let mut context = TestContext::new().await;

        let config = serde_json::json!({
            "inbounds": {
                "socks5_in": {
                    "type": "socks5",
                    "address": "127.0.0.1",
                    "port": 0,
                    "timeout": 30
                }
            },
              "dns": {
                "default_server": "local_dns",
                "servers": {
                  "local_dns": {
                    "type": "udp",
                    "address": "8.8.8.8",
                    "outbound": "direct_out",
                    "port": 53,
                  },
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
            }
        });

        context.start_proxy(config, "socks5_in").await;
        let proxy_addr = context.last_proxy().addr;
        let target_addr = context.mock_server_udp_addr;

        const SESSION_COUNT: usize = 3;
        let mut handles = Vec::with_capacity(SESSION_COUNT);

        for session_id in 0..SESSION_COUNT {
            handles.push(tokio::spawn(async move {
                let (relay_addr, _stream) =
                    TestContext::create_socks5_udp_association_for_proxy(proxy_addr).await;
                let udp_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();

                let msg = format!("session-{}-test", session_id);
                TestContext::send_socks5_udp_packet_static(
                    &udp_socket,
                    relay_addr,
                    target_addr,
                    msg.as_bytes(),
                )
                .await;

                let data = tokio::time::timeout(
                    Duration::from_secs(10),
                    TestContext::recv_socks5_udp_packet_static(&udp_socket, &mut [0u8; 2048]),
                )
                .await
                .unwrap();

                assert_eq!(
                    data,
                    msg.as_bytes(),
                    "Session {} response mismatch",
                    session_id
                );
                println!("Session {} passed", session_id);
            }));
        }

        for handle in handles {
            handle.await.unwrap();
        }

        println!("All {} concurrent UDP sessions passed", SESSION_COUNT);
    };

    tokio::time::timeout(TEST_TIMEOUT, test_fut)
        .await
        .expect("test_socks5_udp_concurrent_sessions timed out");
}

#[tokio::test]
async fn test_socks5_udp_large_datagrams_through_direct() {
    let _watchdog = Watchdog::new(
        "test_socks5_udp_large_datagrams_through_direct",
        TEST_TIMEOUT,
    );

    let test_fut = async {
        let mut context = TestContext::new().await;

        // The shared mock echo server reads into a 2 KiB buffer, so this test
        // runs its own echo server that can hold a full-size datagram.
        let echo = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = echo.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 64 * 1024];
            while let Ok((len, from)) = echo.recv_from(&mut buf).await {
                let _ = echo.send_to(&buf[..len], from).await;
            }
        });

        let config = serde_json::json!({
            "inbounds": {
                "socks5_in": {
                    "type": "socks5",
                    "address": "127.0.0.1",
                    "port": 0,
                    "timeout": 30
                }
            },
            "dns": {
                "default_server": "local_dns",
                "servers": {
                    "local_dns": {
                        "type": "udp",
                        "address": "8.8.8.8",
                        "outbound": "direct_out",
                        "port": 53,
                    },
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
            }
        });

        context.start_proxy(config, "socks5_in").await;

        let (relay_addr, _stream) = context.create_socks5_udp_association().await;
        let udp_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut buf = vec![0u8; 64 * 1024];

        for size in [100usize, 2_000, 2_100, 4_096, 16_000, 60_000] {
            let payload: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
            context
                .send_socks5_udp_packet(&udp_socket, relay_addr, echo_addr, &payload)
                .await;
            let echoed = context.recv_socks5_udp_packet(&udp_socket, &mut buf).await;
            assert_eq!(echoed.len(), size, "datagram of {size} bytes was truncated");
            assert_eq!(echoed, payload);
        }
    };

    tokio::time::timeout(TEST_TIMEOUT, test_fut)
        .await
        .expect("test_socks5_udp_large_datagrams_through_direct timed out");
}
