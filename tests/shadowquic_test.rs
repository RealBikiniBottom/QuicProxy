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

// ─── Connection Reuse Tests ───────────────────────────────────────────────

mod connection_reuse_test {
    use super::*;

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
