//! ShadowQuic integration tests: TCP / JLS / connection-reuse / path-state.
//!
//! UDP transport (`udp_mod` = "stream" | "datagram") is covered separately in
//! `tests/shadowquic_udp_test.rs`. Both files boot the same chain and share
//! config builders from `common::shadowquic`.

mod common;
use common::TestContext;
use common::shadowquic::{client_config, jls_client_config, jls_server_config, server_config};
use std::sync::Arc;
use std::time::Duration;

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
    let jls_user = "user";
    let jls_pwd = "pwd";

    let proxy_b_idx = ctx
        .start_proxy(jls_server_config(jls_user, jls_pwd), "sq_in")
        .await;
    let proxy_b_port = ctx.proxies[proxy_b_idx].port;

    ctx.start_proxy(
        jls_client_config(jls_user, jls_pwd, proxy_b_port),
        "socks_in",
    )
    .await;

    let test_fut = async {
        ctx.test_http_get().await;
    };

    tokio::time::timeout(Duration::from_secs(15), test_fut)
        .await
        .expect("ShadowQuic JLS test timed out after 15s");
}

// ─── User Management Tests ────────────────────────────────────────────────

mod user_management_test {
    use super::*;
    use quicproxy::proxy::observe::get_observer;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// Open one proxied TCP echo stream through the SOCKS5 inbound and return
    /// the established stream (SOCKS5 reply consumed, echo verified).
    async fn open_proxied_stream(ctx: &TestContext) -> tokio::net::TcpStream {
        let stream = tokio::net::TcpStream::connect(ctx.last_proxy().addr)
            .await
            .unwrap();
        open_proxied_stream_on(stream, ctx, Duration::from_secs(10))
            .await
            .expect("proxied stream should establish")
    }

    /// Drive the SOCKS5 CONNECT handshake and one echo round-trip on an existing
    /// stream, bounded by `timeout`.
    async fn open_proxied_stream_on(
        mut stream: tokio::net::TcpStream,
        ctx: &TestContext,
        timeout: Duration,
    ) -> std::io::Result<tokio::net::TcpStream> {
        let ip_octets = match ctx.mock_server_tcp_addr.ip() {
            std::net::IpAddr::V4(ip) => ip.octets(),
            _ => panic!("IPv6 not supported in this test"),
        };
        let fut = async {
            stream.write_all(&[5, 1, 0]).await?;
            let mut method = [0u8; 2];
            stream.read_exact(&mut method).await?;
            if method != [5, 0] {
                return Err(std::io::Error::other("no acceptable method"));
            }

            let mut req = vec![5, 1, 0, 1];
            req.extend_from_slice(&ip_octets);
            req.extend_from_slice(&ctx.mock_server_tcp_addr.port().to_be_bytes());
            stream.write_all(&req).await?;

            let mut resp_head = [0u8; 4];
            stream.read_exact(&mut resp_head).await?;
            if resp_head[1] != 0 {
                return Err(std::io::Error::other("socks connect rejected"));
            }
            match resp_head[3] {
                1 => {
                    let mut buf = [0u8; 6];
                    stream.read_exact(&mut buf).await?;
                }
                3 => {
                    let mut len = [0u8; 1];
                    stream.read_exact(&mut len).await?;
                    let mut buf = vec![0u8; len[0] as usize + 2];
                    stream.read_exact(&mut buf).await?;
                }
                4 => {
                    let mut buf = [0u8; 18];
                    stream.read_exact(&mut buf).await?;
                }
                other => return Err(std::io::Error::other(format!("atyp {other}"))),
            }

            stream.write_all(b"ping").await?;
            let mut buf = [0u8; 16];
            let n = stream.read(&mut buf).await?;
            if &buf[..n] != b"ping" {
                return Err(std::io::Error::other("echo mismatch"));
            }
            Ok(stream)
        };
        tokio::time::timeout(timeout, fut)
            .await
            .map_err(|_| std::io::Error::other("timeout"))?
    }

    /// Removing a user must tear down that user's live QUIC connection:
    /// `set_server_config` only affects new handshakes, so a connection that is
    /// left running would keep proxying with a revoked credential. Uses the
    /// non-JLS (sunnyquic) path for a deterministic handshake.
    #[tokio::test]
    async fn test_shadowquic_remove_user_kills_live_connection() {
        let mut ctx = TestContext::new().await;
        let user = "user";
        let pwd = "testpassword";

        let db_path = std::env::temp_dir().join(format!(
            "quicproxy-shadowquic-users-{}.db",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&db_path);

        let mut server_cfg = server_config(user, pwd);
        server_cfg["cache"] = serde_json::json!({
            "users_cache": { "path": db_path.to_string_lossy() }
        });
        server_cfg["observe"] = serde_json::json!({
            "enabled": true,
            "cache": "users_cache",
            "log_interval": 30
        });

        let proxy_b_idx = ctx.start_proxy(server_cfg, "sq_in").await;
        let proxy_b_port = ctx.proxies[proxy_b_idx].port;

        // Force the default outbound so the loopback mock target is proxied
        // through `sq_out` instead of falling back to a leftover outbound.
        let mut client_cfg = client_config(user, pwd, proxy_b_port, None);
        client_cfg["outbounds"]["final_outbound"] = serde_json::json!("sq_out");
        ctx.start_proxy(client_cfg, "socks_in").await;

        let test_fut = async {
            // First stream establishes an authenticated QUIC connection that is
            // tracked for `user`, and confirms the tunnel works.
            let _stream = open_proxied_stream(&ctx).await;

            let observer = get_observer().expect("observer should be initialized");
            assert!(
                !observer.all_user_stats().is_empty(),
                "the config-seeded user should be registered in the observer"
            );

            assert!(
                observer.remove_user(user).await.unwrap(),
                "remove_user should report the user existed"
            );

            // The revoked QUIC connection must not keep serving new streams.
            // With the connection left alive, a second request would reuse it
            // and succeed despite the removed credential.
            let second = tokio::net::TcpStream::connect(ctx.last_proxy().addr)
                .await
                .unwrap();
            let reused = open_proxied_stream_on(second, &ctx, Duration::from_secs(2))
                .await
                .is_ok();
            assert!(
                !reused,
                "a revoked user must not be able to open another stream on the old connection"
            );

            let _ = std::fs::remove_file(&db_path);
        };

        tokio::time::timeout(Duration::from_secs(25), test_fut)
            .await
            .expect("remove-user kill test timed out after 25s");
    }
}

// ─── Connection Reuse Tests ───────────────────────────────────────────────
mod connection_reuse_test {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    async fn socks5_connect(
        proxy_addr: std::net::SocketAddr,
        target: std::net::SocketAddr,
    ) -> tokio::net::TcpStream {
        let mut stream = tokio::net::TcpStream::connect(proxy_addr).await.unwrap();

        stream.write_all(&[5, 1, 0]).await.unwrap();
        let mut method = [0u8; 2];
        stream.read_exact(&mut method).await.unwrap();
        assert_eq!(method, [5, 0]);

        let mut req = vec![5, 1, 0, 1];
        let ip_octets = match target.ip() {
            std::net::IpAddr::V4(ip) => ip.octets(),
            _ => panic!("IPv6 not supported in this test"),
        };
        req.extend_from_slice(&ip_octets);
        req.extend_from_slice(&target.port().to_be_bytes());
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

        stream
    }

    async fn echo(stream: &mut tokio::net::TcpStream, payload: &[u8]) {
        stream.write_all(payload).await.unwrap();
        let mut buf = [0u8; 128];
        let n = stream.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], payload);
    }

    async fn setup_reuse_chain(ctx: &mut TestContext) {
        let proxy_b_idx = ctx
            .start_proxy(server_config("user", "testpassword"), "sq_in")
            .await;
        let proxy_b_port = ctx.proxies[proxy_b_idx].port;

        ctx.start_proxy(
            client_config("user", "testpassword", proxy_b_port, None),
            "socks_in",
        )
        .await;
    }

    #[tokio::test]
    async fn test_shadowquic_connection_reuse_sequential() {
        let mut ctx = TestContext::new().await;
        setup_reuse_chain(&mut ctx).await;

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
        setup_reuse_chain(&mut ctx).await;

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
    async fn test_shadowquic_reconnects_after_idle_timeout() {
        let mut ctx = TestContext::new().await;

        let mut server_cfg = server_config("user", "testpassword");
        server_cfg["inbounds"]["sq_in"]["idle_timeout"] = serde_json::json!(3);

        let proxy_b_idx = ctx.start_proxy(server_cfg, "sq_in").await;
        let proxy_b_port = ctx.proxies[proxy_b_idx].port;

        let mut client_cfg = client_config("user", "testpassword", proxy_b_port, None);
        client_cfg["outbounds"]["servers"]["sq_out"]["idle_timeout"] = serde_json::json!(3);
        ctx.start_proxy(client_cfg, "socks_in").await;

        let proxy_addr = ctx.last_proxy().addr;
        let target = ctx.mock_server_tcp_addr;
        let test_fut = async {
            let mut first = socks5_connect(proxy_addr, target).await;
            echo(&mut first, b"ping-1").await;

            tokio::time::sleep(Duration::from_secs(5)).await;
            drop(first);

            let mut second = socks5_connect(proxy_addr, target).await;
            echo(&mut second, b"ping-2").await;
        };

        tokio::time::timeout(Duration::from_secs(20), test_fut)
            .await
            .expect("Reconnect-after-idle-timeout test timed out after 20s");
    }

    #[tokio::test]
    async fn test_shadowquic_stream_survives_network_change() {
        let mut ctx = TestContext::new().await;
        setup_reuse_chain(&mut ctx).await;

        let proxy_addr = ctx.last_proxy().addr;
        let target = ctx.mock_server_tcp_addr;
        let test_fut = async {
            let mut stream = socks5_connect(proxy_addr, target).await;
            echo(&mut stream, b"ping-1").await;

            quicproxy::utils::interface::InterfaceManager::notify_network_changed();
            tokio::time::sleep(Duration::from_millis(500)).await;

            echo(&mut stream, b"ping-2").await;
        };

        tokio::time::timeout(Duration::from_secs(20), test_fut)
            .await
            .expect("Network change migration test timed out after 20s");
    }

    async fn zero_rtt_reconnect_roundtrip(
        mut server_cfg: serde_json::Value,
        client_cfg: impl FnOnce(u16) -> serde_json::Value,
    ) {
        let mut ctx = TestContext::new().await;

        server_cfg["inbounds"]["sq_in"]["idle_timeout"] = serde_json::json!(3);
        server_cfg["inbounds"]["sq_in"]["tls"]["zero_rtt"] = serde_json::json!(true);
        let proxy_b_idx = ctx.start_proxy(server_cfg, "sq_in").await;
        let proxy_b_port = ctx.proxies[proxy_b_idx].port;

        let mut client_cfg = client_cfg(proxy_b_port);
        client_cfg["outbounds"]["servers"]["sq_out"]["idle_timeout"] = serde_json::json!(3);
        client_cfg["outbounds"]["servers"]["sq_out"]["tls"]["zero_rtt"] = serde_json::json!(true);
        ctx.start_proxy(client_cfg, "socks_in").await;

        let proxy_addr = ctx.last_proxy().addr;
        let target = ctx.mock_server_tcp_addr;
        let test_fut = async {
            let mut first = socks5_connect(proxy_addr, target).await;
            echo(&mut first, b"ping-1").await;
            drop(first);

            tokio::time::sleep(Duration::from_secs(5)).await;

            let mut second = socks5_connect(proxy_addr, target).await;
            echo(&mut second, b"ping-2").await;
        };

        tokio::time::timeout(Duration::from_secs(20), test_fut)
            .await
            .expect("0-RTT reconnect test timed out after 20s");
    }

    #[tokio::test]
    async fn test_shadowquic_zero_rtt_reconnect() {
        zero_rtt_reconnect_roundtrip(server_config("user", "testpassword"), |port| {
            client_config("user", "testpassword", port, None)
        })
        .await;
    }

    #[tokio::test]
    async fn test_shadowquic_jls_zero_rtt_reconnect() {
        zero_rtt_reconnect_roundtrip(jls_server_config("user", "testpassword"), |port| {
            jls_client_config("user", "testpassword", port)
        })
        .await;
    }

    async fn spawn_switchable_udp_relay(
        target: std::net::SocketAddr,
    ) -> (
        std::net::SocketAddr,
        Arc<std::sync::Mutex<std::net::SocketAddr>>,
    ) {
        let relay = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let relay_addr = relay.local_addr().unwrap();
        let target = Arc::new(std::sync::Mutex::new(target));
        let current_target = target.clone();

        tokio::spawn(async move {
            let mut upstreams: std::collections::HashMap<
                (std::net::SocketAddr, std::net::SocketAddr),
                Arc<tokio::net::UdpSocket>,
            > = std::collections::HashMap::new();
            let mut buf = vec![0u8; 65535];
            loop {
                let Ok((n, client)) = relay.recv_from(&mut buf).await else {
                    return;
                };
                let target = *current_target.lock().unwrap();
                let upstream = match upstreams.get(&(client, target)) {
                    Some(socket) => socket.clone(),
                    None => {
                        let socket =
                            Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
                        socket.connect(target).await.unwrap();
                        let (reader, relay) = (socket.clone(), relay.clone());
                        tokio::spawn(async move {
                            let mut buf = vec![0u8; 65535];
                            while let Ok(n) = reader.recv(&mut buf).await {
                                let _ = relay.send_to(&buf[..n], client).await;
                            }
                        });
                        upstreams.insert((client, target), socket.clone());
                        socket
                    }
                };
                let _ = upstream.send(&buf[..n]).await;
            }
        });

        (relay_addr, target)
    }

    #[tokio::test]
    async fn test_shadowquic_rejected_zero_rtt_is_replayed() {
        let mut ctx = TestContext::new().await;

        let server_a_idx = ctx
            .start_proxy(server_config("user", "testpassword"), "sq_in")
            .await;
        let server_a = ctx.proxies[server_a_idx].addr;

        let mut server_b_cfg = server_config("user", "testpassword");
        let inbound = server_b_cfg["inbounds"]
            .as_object_mut()
            .unwrap()
            .remove("sq_in")
            .unwrap();
        server_b_cfg["inbounds"]["sq_in_b"] = inbound;
        let server_b_idx = ctx.start_proxy(server_b_cfg, "sq_in_b").await;
        let server_b = ctx.proxies[server_b_idx].addr;

        let (relay_addr, relay_target) = spawn_switchable_udp_relay(server_a).await;
        let mut client_cfg = client_config("user", "testpassword", relay_addr.port(), None);
        client_cfg["outbounds"]["servers"]["sq_out"]["idle_timeout"] = serde_json::json!(3);
        ctx.start_proxy(client_cfg, "socks_in").await;

        let proxy_addr = ctx.last_proxy().addr;
        let target = ctx.mock_server_tcp_addr;
        let test_fut = async {
            let mut first = socks5_connect(proxy_addr, target).await;
            echo(&mut first, b"ping-1").await;
            drop(first);

            tokio::time::sleep(Duration::from_secs(5)).await;
            *relay_target.lock().unwrap() = server_b;

            let mut second = socks5_connect(proxy_addr, target).await;
            echo(&mut second, b"ping-2").await;
        };

        tokio::time::timeout(Duration::from_secs(20), test_fut)
            .await
            .expect("rejected 0-RTT replay test timed out after 20s");
    }

    #[tokio::test]
    async fn test_shadowquic_socks5_concurrent_http_requests() {
        let mut ctx = TestContext::new().await;
        setup_reuse_chain(&mut ctx).await;

        let socks_proxy =
            reqwest::Proxy::http(&format!("socks5://127.0.0.1:{}", ctx.last_proxy().port)).unwrap();
        let client = reqwest::Client::builder()
            .proxy(socks_proxy)
            .timeout(Duration::from_secs(30))
            .build()
            .unwrap();

        let test_url = format!("http://127.0.0.1:{}/test", ctx.mock_server_http_addr.port());

        let request_count = 10;
        const CONCURRENT_LIMIT: usize = 10; // 限制并发数防止系统资源耗尽

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
                "{} concurrent requests test result: success={}, error={}, average latency={:?}",
                request_count,
                success_count,
                error_count,
                total_duration / request_count as u32
            );

            assert_eq!(
                error_count, 0,
                "{} requests failed in concurrent test",
                error_count
            );
        };

        tokio::time::timeout(Duration::from_secs(120), test_fut)
            .await
            .expect("Concurrent requests test timed out after 120s");
    }
}

// ─── Path State Tests ────────────────────────────────────────────────────

#[tokio::test]
async fn test_shadowquic_path_state() {
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
        "Uplink stats: lost_packets={}, sent_packets={}, rtt={:.2}ms, mtu={}",
        uplink.lost_packets, uplink.sent_packets, uplink.rtt, uplink.mtu
    );
    assert!(
        uplink.rtt > 0.0,
        "RTT should be positive, got {}",
        uplink.rtt
    );
    assert!(uplink.mtu > 0, "MTU should be positive, got {}", uplink.mtu);
    assert!(
        uplink.lost_packets <= uplink.sent_packets,
        "lost_packets should be <= sent_packets, got {} > {}",
        uplink.lost_packets,
        uplink.sent_packets
    );

    // Test get_downlink_state
    let downlink_state = outbound.get_downlink_state().await;
    assert!(
        downlink_state.is_some(),
        "get_downlink_state should return Some after connection established"
    );
    let downlink = downlink_state.unwrap();
    println!(
        "Downlink stats: lost_packets={}, sent_packets={}, rtt={:.2}ms, mtu={}",
        downlink.lost_packets, downlink.sent_packets, downlink.rtt, downlink.mtu
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
        downlink.lost_packets <= downlink.sent_packets,
        "lost_packets should be <= sent_packets, got {} > {}",
        downlink.lost_packets,
        downlink.sent_packets
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
