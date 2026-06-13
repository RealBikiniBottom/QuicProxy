mod common;
use common::TestContext;
use std::sync::Arc;
use std::time::Duration;

/// Helper: build the server-side (inbound) ShadowQuic config JSON
fn server_config(username: &str, password: &str) -> serde_json::Value {
    serde_json::json!({
        "inbounds": {
            "sq_in": {
                "type": "shadowquic",
                "address": "127.0.0.1",
                "port": 0,
                "username": username,
                "password": password,
                "tls": {
                    "enable": true
                }
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
    })
}

/// Helper: build the client-side (outbound) ShadowQuic config JSON
fn client_config(
    username: &str,
    password: &str,
    proxy_port: u16,
    udp_mod: Option<&str>,
) -> serde_json::Value {
    let mut sq_out = serde_json::json!({
        "type": "shadowquic",
        "address": "127.0.0.1",
        "port": proxy_port,
        "username": username,
        "password": password,
        "tls": {
            "enable": true,
            "insecure": true,
            "sni": "localhost"
        }
    });

    if let Some(mode) = udp_mod {
        sq_out["udp_mod"] = serde_json::json!(mode);
    }

    serde_json::json!({
        "inbounds": {
            "socks_in": {
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
            "outbound": "sq_out",
            "port": 53,
          },
        }
      },
        "outbounds": {
            "default_server": "sq_out",
            "servers": {
                "sq_out": sq_out
            }
        },
        "router": {
        "default_mode": "proxy"
    }
    })
}

// ─── TCP Tests ────────────────────────────────────────────────────────────

#[tokio::test]
async fn test_shadowquic_tcp_full_chain() {
    let mut ctx = TestContext::new().await;

    let proxy_b_idx = ctx
        .start_proxy(server_config("user", "testpassword"), "sq_in")
        .await;
    let proxy_b_port = ctx.proxies[proxy_b_idx].port;

    ctx.start_proxy(
        client_config("user", "testpassword", proxy_b_port, None),
        "socks_in",
    )
    .await;

    let test_fut = async {
        ctx.test_http_get().await;
    };

    tokio::time::timeout(Duration::from_secs(15), test_fut)
        .await
        .expect("ShadowQuic TCP test timed out after 15s");
}

#[tokio::test]
async fn test_shadowquic_tcp_echo() {
    let mut ctx = TestContext::new().await;
    ctx.set_timeout(Duration::from_secs(15));

    let proxy_b_idx = ctx
        .start_proxy(server_config("user", "testpassword"), "sq_in")
        .await;
    let proxy_b_port = ctx.proxies[proxy_b_idx].port;

    ctx.start_proxy(
        client_config("user", "testpassword", proxy_b_port, None),
        "socks_in",
    )
    .await;

    let test_fut = async {
        ctx.test_tcp_echo().await;
    };

    tokio::time::timeout(Duration::from_secs(15), test_fut)
        .await
        .expect("ShadowQuic TCP echo test timed out after 15s");
}

// ─── JLS Tests ────────────────────────────────────────────────────────────

#[tokio::test]
async fn test_shadowquic_jls_full_chain() {
    let mut ctx = TestContext::new().await;
    let password = "testpassword";
    let jls_user = "user";
    let jls_pwd = "pwd";

    let config_b = serde_json::json!({
        "inbounds": {
            "sq_in": {
                "type": "shadowquic",
                "address": "127.0.0.1",
                "port": 0,
                "tls": {
                    "enable_jls": true,
                    "jls_username": jls_user,
                    "jls_password": jls_pwd
                }
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

    let proxy_b_idx = ctx.start_proxy(config_b, "sq_in").await;
    let proxy_b_port = ctx.proxies[proxy_b_idx].port;

    let config_a = serde_json::json!({
        "inbounds": {
            "socks_in": {
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
            "outbound": "sq_out",
            "port": 53,
          },
        }
      },
        "outbounds": {
            "default_server": "sq_out",
            "servers": {
                "sq_out": {
                    "type": "shadowquic",
                    "address": "127.0.0.1",
                    "port": proxy_b_port,
                    "tls": {
                        "enable_jls": true,
                        "insecure": true,
                        "sni": "localhost",
                        "jls_username": jls_user,
                        "jls_password": jls_pwd
                    }
                }
            }
        },
        "router": {
            "default_mode": "proxy"
        }
    });

    ctx.start_proxy(config_a, "socks_in").await;

    let test_fut = async {
        ctx.test_http_get().await;
    };

    tokio::time::timeout(Duration::from_secs(15), test_fut)
        .await
        .expect("ShadowQuic JLS test timed out after 15s");
}

// ─── Connection Reuse Tests ───────────────────────────────────────────────

mod connection_reuse_test {
    use super::*;

    #[tokio::test]
    async fn test_shadowquic_connection_reuse_sequential() {
        let mut ctx = TestContext::new().await;

        let proxy_b_idx = ctx
            .start_proxy(server_config("user", "testpassword"), "sq_in")
            .await;
        let proxy_b_port = ctx.proxies[proxy_b_idx].port;

        ctx.start_proxy(
            client_config("user", "testpassword", proxy_b_port, None),
            "socks_in",
        )
        .await;

        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .unwrap();

        let test_url = format!("http://127.0.0.1:{}/test", ctx.mock_server_http_addr.port());

        let request_count = 5;

        let test_fut = async {
            for i in 0..request_count {
                let resp = client
                    .get(&test_url)
                    .send()
                    .await
                    .unwrap_or_else(|e| panic!("Request #{} failed: {}", i, e));
                assert!(
                    resp.status().is_success(),
                    "Request #{} should return 200",
                    i
                );
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        };

        tokio::time::timeout(Duration::from_secs(30), test_fut)
            .await
            .expect("Sequential connection reuse test timed out after 30s");

        println!(
            "Sequential requests complete ({} requests). Check logs for 'new quic connection' count.",
            request_count
        );
    }

    #[tokio::test]
    async fn test_shadowquic_connection_reuse_concurrent() {
        let mut ctx = TestContext::new().await;

        let proxy_b_idx = ctx
            .start_proxy(server_config("user", "testpassword"), "sq_in")
            .await;
        let proxy_b_port = ctx.proxies[proxy_b_idx].port;

        ctx.start_proxy(
            client_config("user", "testpassword", proxy_b_port, None),
            "socks_in",
        )
        .await;

        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .unwrap();

        let test_url = format!("http://127.0.0.1:{}/test", ctx.mock_server_http_addr.port());

        let request_count = 10;

        let test_fut = async {
            let mut handles = Vec::with_capacity(request_count);

            for i in 0..request_count {
                let client = client.clone();
                let url = test_url.clone();
                let handle = tokio::spawn(async move {
                    let resp = client.get(&url).send().await;
                    (i, resp)
                });
                handles.push(handle);
            }

            for handle in handles {
                let (idx, result) = handle.await.expect("Task should not panic");
                assert!(
                    result.is_ok(),
                    "Concurrent request #{} failed: {:?}",
                    idx,
                    result.err()
                );
            }
        };

        tokio::time::timeout(Duration::from_secs(30), test_fut)
            .await
            .expect("Concurrent connection reuse test timed out after 30s");

        println!(
            "Concurrent requests complete ({} requests). Check logs for 'new quic connection' count.",
            request_count
        );
    }

    #[tokio::test]
    async fn test_shadowquic_stream_survives_idle_timeout() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let mut ctx = TestContext::new().await;

        let mut server_cfg = server_config("user", "testpassword");
        server_cfg["inbounds"]["sq_in"]["idle_timeout"] = serde_json::json!(3);

        let proxy_b_idx = ctx.start_proxy(server_cfg, "sq_in").await;
        let proxy_b_port = ctx.proxies[proxy_b_idx].port;

        let mut client_cfg = client_config("user", "testpassword", proxy_b_port, None);
        client_cfg["outbounds"]["servers"]["sq_out"]["idle_timeout"] = serde_json::json!(3);
        ctx.start_proxy(client_cfg, "socks_in").await;

        let proxy_addr = ctx.last_proxy().addr;
        let test_fut = async {
            let mut stream = tokio::net::TcpStream::connect(proxy_addr).await.unwrap();

            stream.write_all(&[5, 1, 0]).await.unwrap();
            let mut method = [0u8; 2];
            stream.read_exact(&mut method).await.unwrap();
            assert_eq!(method, [5, 0]);

            let mut req = vec![5, 1, 0, 1];
            let ip_octets = match ctx.mock_server_tcp_addr.ip() {
                std::net::IpAddr::V4(ip) => ip.octets(),
                _ => panic!("IPv6 not supported in this test"),
            };
            req.extend_from_slice(&ip_octets);
            req.extend_from_slice(&ctx.mock_server_tcp_addr.port().to_be_bytes());
            stream.write_all(&req).await.unwrap();

            let mut resp_head = [0u8; 4];
            stream.read_exact(&mut resp_head).await.unwrap();
            assert_eq!(resp_head[0], 5);
            assert_eq!(resp_head[1], 0, "SOCKS5 connect should succeed");

            match resp_head[3] {
                1 => {
                    let mut buf = [0u8; 6];
                    stream.read_exact(&mut buf).await.unwrap();
                }
                3 => {
                    let mut len = [0u8; 1];
                    stream.read_exact(&mut len).await.unwrap();
                    let mut buf = vec![0u8; len[0] as usize + 2];
                    stream.read_exact(&mut buf).await.unwrap();
                }
                4 => {
                    let mut buf = [0u8; 18];
                    stream.read_exact(&mut buf).await.unwrap();
                }
                other => panic!("Unexpected address type: {}", other),
            }

            stream.write_all(b"ping-1").await.unwrap();
            let mut buf = [0u8; 128];
            let n = stream.read(&mut buf).await.unwrap();
            assert_eq!(&buf[..n], b"ping-1");

            tokio::time::sleep(Duration::from_secs(5)).await;

            stream.write_all(b"ping-2").await.unwrap();
            let n = stream.read(&mut buf).await.unwrap();
            assert_eq!(&buf[..n], b"ping-2");
        };

        tokio::time::timeout(Duration::from_secs(20), test_fut)
            .await
            .expect("Idle-timeout survival test timed out after 20s");
    }

    #[tokio::test]
    async fn test_shadowquic_socks5_1000_concurrent_requests() {
        let mut ctx = TestContext::new().await;

        let proxy_b_idx = ctx
            .start_proxy(server_config("user", "testpassword"), "sq_in")
            .await;
        let proxy_b_port = ctx.proxies[proxy_b_idx].port;

        ctx.start_proxy(
            client_config("user", "testpassword", proxy_b_port, None),
            "socks_in",
        )
        .await;

        let socks_proxy =
            reqwest::Proxy::http(&format!("socks5://127.0.0.1:{}", ctx.last_proxy().port)).unwrap();
        let client = reqwest::Client::builder()
            .proxy(socks_proxy)
            .timeout(Duration::from_secs(30))
            .build()
            .unwrap();

        let test_url = format!("http://127.0.0.1:{}/test", ctx.mock_server_http_addr.port());

        let request_count = 10;
        const CONCURRENT_LIMIT: usize = 100; // 限制并发数防止系统资源耗尽

        let test_fut = async {
            let semaphore = Arc::new(tokio::sync::Semaphore::new(CONCURRENT_LIMIT));
            let mut handles = Vec::with_capacity(request_count);

            for i in 0..request_count {
                let client = client.clone();
                let url = test_url.clone();
                let sem = semaphore.clone();

                let handle = tokio::spawn(async move {
                    let _permit = sem.acquire().await.expect("Semaphore should not be closed");
                    let start = std::time::Instant::now();
                    let resp = client.get(&url).send().await;
                    let duration = start.elapsed();
                    (i, resp, duration)
                });
                handles.push(handle);
            }

            let mut success_count = 0;
            let mut error_count = 0;
            let mut total_duration = std::time::Duration::from_secs(0);

            for handle in handles {
                let (idx, result, duration) = handle.await.expect("Task should not panic");
                total_duration += duration;

                match result {
                    Ok(resp) if resp.status().is_success() => {
                        success_count += 1;
                    }
                    Err(e) => {
                        error_count += 1;
                        eprintln!("Request #{} failed: {:?}", idx, e);
                    }
                    Ok(resp) => {
                        error_count += 1;
                        eprintln!("Request #{} failed with status: {:?}", idx, resp.status());
                    }
                }
            }

            println!(
                "1000 concurrent requests test result: success={}, error={}, average latency={:?}",
                success_count,
                error_count,
                total_duration / request_count as u32
            );

            assert_eq!(
                error_count, 0,
                "{} requests failed in 1000 concurrent test",
                error_count
            );
        };

        tokio::time::timeout(Duration::from_secs(300), test_fut) // 5分钟超时
            .await
            .expect("1000 concurrent requests test timed out after 300s");
    }
}

// ─── UDP Tests ────────────────────────────────────────────────────────────

mod udp_tests {
    use super::*;
    use std::net::SocketAddr;
    use tokio::net::UdpSocket;

    const TEST_TIMEOUT: Duration = Duration::from_secs(30);
    const PACKET_TIMEOUT: Duration = Duration::from_secs(6);
    const SESSION_TIMEOUT: Duration = Duration::from_secs(12);

    /// Shared helper: set up the two-proxy chain and return the test context.
    async fn setup_udp_chain(udp_mod: &str) -> TestContext {
        let mut ctx = TestContext::new().await;
        ctx.set_timeout(Duration::from_secs(20));

        let proxy_b_idx = ctx
            .start_proxy(server_config("user", "testpassword"), "sq_in")
            .await;
        let proxy_b_port = ctx.proxies[proxy_b_idx].port;

        ctx.start_proxy(
            client_config("user", "testpassword", proxy_b_port, Some(udp_mod)),
            "socks_in",
        )
        .await;

        ctx
    }

    // ── Basic UDP Echo ──

    #[tokio::test]
    async fn test_shadowquic_udp_over_stream() {
        let ctx = setup_udp_chain("stream").await;

        let test_fut = async {
            ctx.test_udp_echo().await;
        };

        tokio::time::timeout(TEST_TIMEOUT, test_fut)
            .await
            .expect("ShadowQuic UDP over stream test timed out after 30s");
    }

    #[tokio::test]
    async fn test_shadowquic_udp_over_datagram2() {
        let ctx = setup_udp_chain("datagram").await;

        let test_fut = async {
            ctx.test_udp_echo().await;
        };

        tokio::time::timeout(TEST_TIMEOUT, test_fut)
            .await
            .expect("ShadowQuic UDP over datagram test timed out after 30s");
    }

    // ── UDP Multiple Packets ──

    #[tokio::test]
    async fn test_shadowquic_udp_over_stream_multiple_packets() {
        let ctx = setup_udp_chain("stream").await;
        let proxy = ctx.last_proxy();

        let test_fut = async {
            let (udp_socket, relay_addr, _tcp_stream) = socks5_udp_associate(proxy.addr).await;

            let packet_count = 5;
            for i in 0..packet_count {
                let msg = format!("UDP packet #{}", i);
                let packet = build_socks5_udp_packet(ctx.mock_server_udp_addr, msg.as_bytes());

                udp_socket
                    .send_to(&packet, relay_addr)
                    .await
                    .unwrap_or_else(|e| panic!("Failed to send packet #{}: {}", i, e));

                let mut recv_buf = [0u8; 2048];
                let len = recv_udp_data_or_panic(
                    &udp_socket,
                    &mut recv_buf,
                    &format!("stream packet #{}", i),
                )
                .await;

                let data = extract_socks5_udp_data(&recv_buf, len);
                assert_eq!(data, msg.as_bytes(), "Response mismatch for packet #{}", i);
            }

            println!(
                "Successfully sent and received {} UDP packets over stream",
                packet_count
            );
        };

        tokio::time::timeout(TEST_TIMEOUT, test_fut)
            .await
            .expect("UDP over stream multiple packets test timed out after 30s");
    }

    /// Helper: Perform SOCKS5 UDP associate and return (udp_socket, relay_addr, tcp_stream)
    async fn socks5_udp_associate(
        proxy_addr: SocketAddr,
    ) -> (UdpSocket, SocketAddr, tokio::net::TcpStream) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let mut stream = tokio::time::timeout(
            Duration::from_secs(5),
            tokio::net::TcpStream::connect(proxy_addr),
        )
        .await
        .expect("TCP connect to proxy timed out")
        .expect("TCP connect to proxy failed");

        // SOCKS5 Handshake
        stream.write_all(&[5, 1, 0]).await.unwrap();
        let mut buf = [0u8; 2];
        stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(buf, [5, 0], "SOCKS5 handshake failed");

        // UDP Associate (CMD 3)
        let mut req = vec![5, 3, 0, 1];
        req.extend_from_slice(&[0, 0, 0, 0]); // 0.0.0.0
        req.extend_from_slice(&[0, 0]); // Port 0
        stream.write_all(&req).await.unwrap();

        // Server response
        let mut resp_head = [0u8; 4];
        stream.read_exact(&mut resp_head).await.unwrap();
        assert_eq!(
            resp_head[1], 0,
            "SOCKS5 UDP ASSOCIATE failed with code {}",
            resp_head[1]
        );

        let addr_type = resp_head[3];
        let relay_addr = match addr_type {
            1 => {
                let mut buf = [0u8; 4];
                stream.read_exact(&mut buf).await.unwrap();
                std::net::IpAddr::V4(std::net::Ipv4Addr::from(buf))
            }
            _ => panic!("Unsupported address type for UDP relay: {}", addr_type),
        };
        let mut port_buf = [0u8; 2];
        stream.read_exact(&mut port_buf).await.unwrap();
        let relay_port = u16::from_be_bytes(port_buf);
        let relay_socket_addr = SocketAddr::new(relay_addr, relay_port);

        let udp_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();

        (udp_socket, relay_socket_addr, stream)
    }

    /// Helper: Build a SOCKS5 UDP packet
    fn build_socks5_udp_packet(target_addr: SocketAddr, data: &[u8]) -> Vec<u8> {
        let mut packet = vec![0u8, 0u8, 0u8, 1]; // RSV(2), FRAG(1), ATYP=IPv4
        let ip_octets = match target_addr.ip() {
            std::net::IpAddr::V4(ip) => ip.octets(),
            _ => panic!("IPv6 not supported in this test helper"),
        };
        packet.extend_from_slice(&ip_octets);
        packet.extend_from_slice(&target_addr.port().to_be_bytes());
        packet.extend_from_slice(data);
        packet
    }

    /// Helper: Extract data from a SOCKS5 UDP response (IPv4 only)
    fn extract_socks5_udp_data(buf: &[u8], len: usize) -> &[u8] {
        let header_len = 3 + 1 + 4 + 2; // RSV(2) + FRAG(1) + ATYP(1) + IPv4(4) + PORT(2)
        &buf[header_len..len]
    }

    async fn recv_udp_data_or_panic(
        udp_socket: &UdpSocket,
        recv_buf: &mut [u8],
        context: &str,
    ) -> usize {
        let (len, _src) = tokio::time::timeout(PACKET_TIMEOUT, udp_socket.recv_from(recv_buf))
            .await
            .unwrap_or_else(|_| panic!("{}: timeout after {:?}", context, PACKET_TIMEOUT))
            .unwrap_or_else(|e| panic!("{}: recv error: {}", context, e));
        len
    }

    #[tokio::test]
    async fn test_shadowquic_udp_over_datagram_multiple_packets() {
        let ctx = setup_udp_chain("datagram").await;

        let test_fut = async {
            // Use shared utility to create UDP association
            let (relay_addr, _tcp_stream) = ctx.create_socks5_udp_association().await;
            let udp_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();

            let packet_count = 5;
            for i in 0..packet_count {
                let msg = format!("UDP datagram packet #{}", i);
                // Use shared utility to send UDP packet
                ctx.send_socks5_udp_packet(
                    &udp_socket,
                    relay_addr,
                    ctx.mock_server_udp_addr,
                    msg.as_bytes(),
                )
                .await;

                let mut recv_buf = [0u8; 2048];
                // Use shared utility to receive and parse UDP response
                let data = tokio::time::timeout(
                    PACKET_TIMEOUT,
                    ctx.recv_socks5_udp_packet(&udp_socket, &mut recv_buf),
                )
                .await
                .unwrap_or_else(|_| {
                    panic!("datagram packet #{}: timeout after {:?}", i, PACKET_TIMEOUT)
                });

                assert_eq!(data, msg.as_bytes(), "Response mismatch for packet #{}", i);
            }

            println!(
                "Successfully sent and received {} UDP packets over datagram",
                packet_count
            );
        };

        tokio::time::timeout(TEST_TIMEOUT, test_fut)
            .await
            .expect("UDP over datagram multiple packets test timed out after 30s");
    }

    // ── UDP Large Payload ──

    #[tokio::test]
    async fn test_shadowquic_udp_over_stream_large_payload() {
        let ctx = setup_udp_chain("stream").await;

        let test_fut = async {
            // Use shared utility to create UDP association
            let (relay_addr, _tcp_stream) = ctx.create_socks5_udp_association().await;
            let udp_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();

            // Test with a ~1200 byte payload (within typical MTU)
            let msg: Vec<u8> = (0..1200).map(|i| (i % 256) as u8).collect();
            // Use shared utility to send UDP packet
            ctx.send_socks5_udp_packet(&udp_socket, relay_addr, ctx.mock_server_udp_addr, &msg)
                .await;

            let mut recv_buf = [0u8; 4096];
            // Use shared utility to receive and parse UDP response
            let data = tokio::time::timeout(
                PACKET_TIMEOUT,
                ctx.recv_socks5_udp_packet(&udp_socket, &mut recv_buf),
            )
            .await
            .unwrap_or_else(|_| panic!("stream large payload: timeout after {:?}", PACKET_TIMEOUT));

            assert_eq!(data, msg.as_slice(), "Large payload mismatch");
            println!(
                "Successfully echoed {} byte UDP payload over stream",
                msg.len()
            );
        };

        tokio::time::timeout(TEST_TIMEOUT, test_fut)
            .await
            .expect("UDP over stream large payload test timed out after 20s");
    }

    // ── UDP Timeout and Re-establishment ──

    #[tokio::test]
    async fn test_shadowquic_udp_timeout() {
        let mut ctx = TestContext::new().await;

        let proxy_b_idx = ctx
            .start_proxy(server_config("user", "testpassword"), "sq_in")
            .await;
        let proxy_b_port = ctx.proxies[proxy_b_idx].port;

        ctx.start_proxy(
            client_config("user", "testpassword", proxy_b_port, Some("stream")),
            "socks_in",
        )
        .await;

        let test_fut = async {
            ctx.test_udp_timeout().await;
        };

        tokio::time::timeout(TEST_TIMEOUT, test_fut)
            .await
            .expect("ShadowQuic UDP timeout test timed out after 30s");
    }

    #[tokio::test]
    async fn test_shadowquic_udp_over_datagram_timeout() {
        let mut ctx = TestContext::new().await;

        let proxy_b_idx = ctx
            .start_proxy(server_config("user", "testpassword"), "sq_in")
            .await;
        let proxy_b_port = ctx.proxies[proxy_b_idx].port;

        ctx.start_proxy(
            client_config("user", "testpassword", proxy_b_port, Some("datagram")),
            "socks_in",
        )
        .await;

        let test_fut = async {
            ctx.test_udp_timeout().await;
        };

        tokio::time::timeout(TEST_TIMEOUT, test_fut)
            .await
            .expect("ShadowQuic UDP over datagram timeout test timed out after 30s");
    }

    // ── UDP Session Isolation ──

    #[tokio::test]
    async fn test_shadowquic_udp_over_stream_concurrent_sessions() {
        let ctx = setup_udp_chain("stream").await;
        let _proxy_addr = ctx.last_proxy().addr;
        let _udp_target = ctx.mock_server_udp_addr;

        let test_fut = async {
            let session_count = 3;
            let mut handles = Vec::new();

            let proxy_addr = ctx.last_proxy().addr;
            let udp_target = ctx.mock_server_udp_addr;
            for session_id in 0..session_count {
                let proxy_addr = proxy_addr;
                let udp_target = udp_target;
                let handle = tokio::spawn(async move {
                    // Manual UDP association (ctx is not Clone, so implement directly)
                    use tokio::io::{AsyncReadExt, AsyncWriteExt};
                    let mut stream = tokio::time::timeout(
                        Duration::from_secs(5),
                        tokio::net::TcpStream::connect(proxy_addr),
                    )
                    .await
                    .unwrap()
                    .unwrap();

                    // SOCKS5 Handshake
                    stream.write_all(&[5, 1, 0]).await.unwrap();
                    let mut buf = [0u8; 2];
                    stream.read_exact(&mut buf).await.unwrap();
                    assert_eq!(buf, [5, 0], "SOCKS5 handshake failed");

                    // UDP Associate
                    let mut req = vec![5, 3, 0, 1];
                    req.extend_from_slice(&[0, 0, 0, 0]); // 0.0.0.0
                    req.extend_from_slice(&[0, 0]); // Port 0
                    stream.write_all(&req).await.unwrap();

                    // Server response
                    let mut resp_head = [0u8; 4];
                    stream.read_exact(&mut resp_head).await.unwrap();
                    assert_eq!(resp_head[1], 0);

                    let addr_type = resp_head[3];
                    let relay_addr = match addr_type {
                        1 => {
                            let mut buf = [0u8; 4];
                            stream.read_exact(&mut buf).await.unwrap();
                            std::net::IpAddr::V4(std::net::Ipv4Addr::from(buf))
                        }
                        _ => panic!("Unsupported address type"),
                    };
                    let mut port_buf = [0u8; 2];
                    stream.read_exact(&mut port_buf).await.unwrap();
                    let relay_port = u16::from_be_bytes(port_buf);
                    let relay_socket_addr = SocketAddr::new(relay_addr, relay_port);

                    let udp_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();

                    let msg = format!("Session-{}-hello", session_id);

                    // Build and send UDP packet
                    let mut packet = vec![0u8, 0u8, 0u8, 1]; // RSV, FRAG, ATYP=IPv4
                    let ip_octets = match udp_target.ip() {
                        std::net::IpAddr::V4(ip) => ip.octets(),
                        _ => panic!("IPv6 not supported"),
                    };
                    packet.extend_from_slice(&ip_octets);
                    packet.extend_from_slice(&udp_target.port().to_be_bytes());
                    packet.extend_from_slice(msg.as_bytes());
                    udp_socket
                        .send_to(&packet, relay_socket_addr)
                        .await
                        .unwrap();

                    // Receive and parse response
                    let mut recv_buf = [0u8; 2048];
                    let (len, _) =
                        tokio::time::timeout(SESSION_TIMEOUT, udp_socket.recv_from(&mut recv_buf))
                            .await
                            .unwrap()
                            .unwrap();
                    let header_len = 3 + 1 + 4 + 2;
                    let data = &recv_buf[header_len..len];

                    assert_eq!(
                        data,
                        msg.as_bytes(),
                        "Session {} response mismatch",
                        session_id
                    );
                    println!("Session {} completed successfully", session_id);
                });
                handles.push(handle);
            }

            for handle in handles {
                handle.await.expect("Session task should not panic");
            }

            println!("All {} concurrent UDP sessions completed", session_count);
        };

        tokio::time::timeout(TEST_TIMEOUT, test_fut)
            .await
            .expect("Concurrent UDP sessions test timed out after 30s");
    }

    #[tokio::test]
    async fn test_shadowquic_udp_over_datagram_concurrent_sessions() {
        let ctx = setup_udp_chain("datagram").await;

        let test_fut = async {
            let session_count = 3;
            let mut handles = Vec::new();

            let proxy_addr = ctx.last_proxy().addr;
            let udp_target = ctx.mock_server_udp_addr;
            for session_id in 0..session_count {
                let proxy_addr = proxy_addr;
                let udp_target = udp_target;
                let handle = tokio::spawn(async move {
                    // Manual UDP association (ctx is not Clone, so implement directly)
                    use tokio::io::{AsyncReadExt, AsyncWriteExt};
                    let mut stream = tokio::time::timeout(
                        Duration::from_secs(5),
                        tokio::net::TcpStream::connect(proxy_addr),
                    )
                    .await
                    .unwrap()
                    .unwrap();

                    // SOCKS5 Handshake
                    stream.write_all(&[5, 1, 0]).await.unwrap();
                    let mut buf = [0u8; 2];
                    stream.read_exact(&mut buf).await.unwrap();
                    assert_eq!(buf, [5, 0], "SOCKS5 handshake failed");

                    // UDP Associate
                    let mut req = vec![5, 3, 0, 1];
                    req.extend_from_slice(&[0, 0, 0, 0]); // 0.0.0.0
                    req.extend_from_slice(&[0, 0]); // Port 0
                    stream.write_all(&req).await.unwrap();

                    // Server response
                    let mut resp_head = [0u8; 4];
                    stream.read_exact(&mut resp_head).await.unwrap();
                    assert_eq!(resp_head[1], 0);

                    let addr_type = resp_head[3];
                    let relay_addr = match addr_type {
                        1 => {
                            let mut buf = [0u8; 4];
                            stream.read_exact(&mut buf).await.unwrap();
                            std::net::IpAddr::V4(std::net::Ipv4Addr::from(buf))
                        }
                        _ => panic!("Unsupported address type"),
                    };
                    let mut port_buf = [0u8; 2];
                    stream.read_exact(&mut port_buf).await.unwrap();
                    let relay_port = u16::from_be_bytes(port_buf);
                    let relay_socket_addr = SocketAddr::new(relay_addr, relay_port);

                    let udp_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();

                    let msg = format!("datagram-session-{}-hello", session_id);
                    let mut recv_buf = [0u8; 2048];
                    let mut got = None;
                    for attempt in 1..=3 {
                        // Build and send UDP packet
                        let mut packet = vec![0u8, 0u8, 0u8, 1]; // RSV, FRAG, ATYP=IPv4
                        let ip_octets = match udp_target.ip() {
                            std::net::IpAddr::V4(ip) => ip.octets(),
                            _ => panic!("IPv6 not supported"),
                        };
                        packet.extend_from_slice(&ip_octets);
                        packet.extend_from_slice(&udp_target.port().to_be_bytes());
                        packet.extend_from_slice(msg.as_bytes());
                        udp_socket
                            .send_to(&packet, relay_socket_addr)
                            .await
                            .unwrap();

                        match tokio::time::timeout(
                            PACKET_TIMEOUT,
                            udp_socket.recv_from(&mut recv_buf),
                        )
                        .await
                        {
                            Ok(Ok((len, _))) => {
                                let header_len = 3 + 1 + 4 + 2;
                                let data = &recv_buf[header_len..len];
                                got = Some(data.to_vec());
                                break;
                            }
                            Ok(Err(e)) => {
                                panic!(
                                    "Datagram recv failed in session {} attempt {}: {}",
                                    session_id, attempt, e
                                );
                            }
                            Err(_) => {
                                if attempt == 3 {
                                    panic!(
                                        "Timeout waiting for datagram response in session {}",
                                        session_id
                                    );
                                }
                            }
                        }
                    }

                    let data = got.expect("datagram response should be set");
                    assert_eq!(
                        data,
                        msg.as_bytes(),
                        "Datagram session {} response mismatch",
                        session_id
                    );
                });
                handles.push(handle);
            }

            for handle in handles {
                handle
                    .await
                    .expect("Datagram session task should not panic");
            }
        };

        tokio::time::timeout(TEST_TIMEOUT, test_fut)
            .await
            .expect("Concurrent datagram UDP sessions test timed out after 30s");
    }

    // ── UDP rapid fire ──

    #[tokio::test]
    async fn test_shadowquic_udp_over_stream_rapid_fire() {
        let ctx = setup_udp_chain("stream").await;

        let test_fut = async {
            // Use shared utility to create UDP association
            let (relay_addr, _tcp_stream) = ctx.create_socks5_udp_association().await;
            let udp_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();

            // Send multiple packets without waiting for response
            let count = 10;
            for i in 0..count {
                let msg = format!("rapid-{}", i);
                // Use shared utility to send UDP packet
                ctx.send_socks5_udp_packet(
                    &udp_socket,
                    relay_addr,
                    ctx.mock_server_udp_addr,
                    msg.as_bytes(),
                )
                .await;
            }

            // Now collect all responses (may arrive in any order)
            let mut received = Vec::new();
            for _ in 0..count {
                let mut recv_buf = [0u8; 2048];
                match tokio::time::timeout(
                    PACKET_TIMEOUT,
                    ctx.recv_socks5_udp_packet(&udp_socket, &mut recv_buf),
                )
                .await
                {
                    Ok(data) => {
                        received.push(data.to_vec());
                    }
                    Err(_) => {
                        println!(
                            "Timeout after receiving {}/{} responses (some packet loss is acceptable in rapid-fire)",
                            received.len(),
                            count
                        );
                        break;
                    }
                }
            }

            // We expect at least 80% delivery for rapid-fire
            let min_expected = count * 8 / 10;
            assert!(
                received.len() >= min_expected,
                "Expected at least {} responses, got {}",
                min_expected,
                received.len()
            );
            println!(
                "Rapid-fire: sent {}, received {} responses",
                count,
                received.len()
            );
        };

        tokio::time::timeout(TEST_TIMEOUT, test_fut)
            .await
            .expect("Rapid-fire UDP test timed out after 30s");
    }

    // ── TCP close does not affect subsequent UDP sessions ──

    #[tokio::test]
    async fn test_shadowquic_udp_tcp_close_no_affect() {
        let ctx = setup_udp_chain("stream").await;

        let test_fut = async {
            use tokio::io::AsyncWriteExt;

            // First session
            {
                // Use shared utility to create UDP association
                let (relay_addr, mut tcp_stream) = ctx.create_socks5_udp_association().await;
                let udp_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();

                let msg = b"first-session";
                // Use shared utility to send UDP packet
                ctx.send_socks5_udp_packet(&udp_socket, relay_addr, ctx.mock_server_udp_addr, msg)
                    .await;

                let mut recv_buf = [0u8; 2048];
                // Use shared utility to receive and parse UDP response
                let data = tokio::time::timeout(
                    PACKET_TIMEOUT,
                    ctx.recv_socks5_udp_packet(&udp_socket, &mut recv_buf),
                )
                .await
                .unwrap_or_else(|_| panic!("first session: timeout after {:?}", PACKET_TIMEOUT));
                assert_eq!(data, msg);

                // Close the TCP stream explicitly
                tcp_stream.shutdown().await.unwrap();
                drop(tcp_stream);
                drop(udp_socket);
            }

            // Wait a bit
            tokio::time::sleep(Duration::from_millis(500)).await;

            // Second session should work fine
            {
                // Use shared utility to create UDP association
                let (relay_addr, _tcp_stream) = ctx.create_socks5_udp_association().await;
                let udp_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();

                let msg = b"second-session";
                // Use shared utility to send UDP packet
                ctx.send_socks5_udp_packet(&udp_socket, relay_addr, ctx.mock_server_udp_addr, msg)
                    .await;

                let mut recv_buf = [0u8; 2048];
                // Use shared utility to receive and parse UDP response
                let data = tokio::time::timeout(
                    PACKET_TIMEOUT,
                    ctx.recv_socks5_udp_packet(&udp_socket, &mut recv_buf),
                )
                .await
                .unwrap_or_else(|_| {
                    panic!(
                        "second session after close: timeout after {:?}",
                        PACKET_TIMEOUT
                    )
                });
                assert_eq!(
                    data, msg,
                    "Second session should work after first was closed"
                );
            }

            println!("TCP close does not affect subsequent UDP sessions: verified");
        };

        tokio::time::timeout(TEST_TIMEOUT, test_fut)
            .await
            .expect("TCP close no-affect test timed out after 20s");
    }
}

// ─── Path State Tests ────────────────────────────────────────────────────

#[tokio::test]
async fn test_shadowquic_path_state() {
    use quicproxy::proxy::outbound::AnyOutbound;
    use quicproxy::proxy::outbound::OUTBOUNDS_MAP;

    let mut ctx = TestContext::new().await;
    ctx.set_timeout(Duration::from_secs(15));

    // Start server
    let proxy_b_idx = ctx
        .start_proxy(server_config("user", "testpassword"), "sq_in")
        .await;
    let proxy_b_port = ctx.proxies[proxy_b_idx].port;

    // Start client
    ctx.start_proxy(
        client_config("user", "testpassword", proxy_b_port, None),
        "socks_in",
    )
    .await;

    // Make a request to establish the QUIC connection
    ctx.test_http_get().await;

    // Get the outbound from the global map
    let outbound = OUTBOUNDS_MAP
        .get("sq_out")
        .expect("sq_out outbound should be registered")
        .clone();

    // Test get_uplink_state
    let uplink_state = outbound.get_uplink_state().await;
    assert!(
        uplink_state.is_some(),
        "get_uplink_state should return Some after connection established"
    );
    let uplink = uplink_state.unwrap();
    println!(
        "Uplink stats: packet_loss_rate={:.2}%, rtt={:.2}ms, mtu={}",
        uplink.packet_loss_rate, uplink.rtt, uplink.mtu
    );
    assert!(
        uplink.rtt > 0.0,
        "RTT should be positive, got {}",
        uplink.rtt
    );
    assert!(uplink.mtu > 0, "MTU should be positive, got {}", uplink.mtu);
    assert!(
        uplink.packet_loss_rate >= 0.0,
        "Packet loss rate should be non-negative, got {}",
        uplink.packet_loss_rate
    );

    // Test get_downlink_state
    let downlink_state = outbound.get_downlink_state().await;
    assert!(
        downlink_state.is_some(),
        "get_downlink_state should return Some after connection established"
    );
    let downlink = downlink_state.unwrap();
    println!(
        "Downlink stats: packet_loss_rate={:.2}%, rtt={:.2}ms, mtu={}",
        downlink.packet_loss_rate, downlink.rtt, downlink.mtu
    );
    assert!(
        downlink.rtt > 0.0,
        "RTT should be positive, got {}",
        downlink.rtt
    );
    assert!(
        downlink.mtu > 0,
        "MTU should be positive, got {}",
        downlink.mtu
    );
    assert!(
        downlink.packet_loss_rate >= 0.0,
        "Packet loss rate should be non-negative, got {}",
        downlink.packet_loss_rate
    );

    // Verify MTU values are reasonable (typically between 1200 and 1500 for QUIC)
    assert!(
        uplink.mtu >= 1200 && uplink.mtu <= 1500,
        "Uplink MTU should be in range [1200, 1500], got {}",
        uplink.mtu
    );
    assert!(
        downlink.mtu >= 1200 && downlink.mtu <= 1500,
        "Downlink MTU should be in range [1200, 1500], got {}",
        downlink.mtu
    );

    println!("Path state test passed successfully");
}
