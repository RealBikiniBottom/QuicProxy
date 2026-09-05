//! ShadowQuic `udp_mod` integration tests.
//!
//! The `udp_mod` knob on a shadowquic *outbound* selects how UDP payloads are
//! carried to the peer over QUIC:
//! - `"stream"`   (default) -> one QUIC uni-directional stream per peer, cmd 0x04
//! - `"datagram"`           -> QUIC datagrams, cmd 0x03
//!
//! Every scenario below runs once per mode, booting a fresh
//! `socks5(client) -> shadowquic -> server -> direct(echo)` chain, so the two
//! transports are verified through the exact same end-to-end path.

mod common;
use common::TestContext;
use common::shadowquic::{client_config, server_config};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::{TcpStream, UdpSocket};

const TEST_TIMEOUT: Duration = Duration::from_secs(60);
const PACKET_TIMEOUT: Duration = Duration::from_secs(6);
/// Shared across modes: fits both a QUIC datagram (default MTU 1400) and the
/// 2048-byte receive buffer of the mock UDP echo server.
const LARGE_PAYLOAD_LEN: usize = 1200;
/// Total UDP payload pushed through the chain per throughput case.
const THROUGHPUT_20MB: u64 = 20 * 1024 * 1024;
const THROUGHPUT_200MB: u64 = 200 * 1024 * 1024;
/// Per-datagram payload size used by the throughput scenario.
const THROUGHPUT_PACKET_LEN: usize = 1200;
/// Quiet window after the sender finishes before a throughput run is declared over.
const THROUGHPUT_QUIET: Duration = Duration::from_millis(800);

/// Boot server + client for a given `udp_mod` and return the test context.
async fn setup_chain(udp_mod: &str) -> TestContext {
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

/// Open a fresh SOCKS5 UDP association plus a local UDP socket.
async fn new_session(ctx: &TestContext) -> (SocketAddr, UdpSocket, TcpStream) {
    let (relay_addr, tcp_stream) = ctx.create_socks5_udp_association().await;
    let udp_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    (relay_addr, udp_socket, tcp_stream)
}

/// Send one packet and wait for its echo. Panics with a per-mode message.
async fn send_and_expect_echo(
    udp_mod: &str,
    ctx: &TestContext,
    udp_socket: &UdpSocket,
    relay_addr: SocketAddr,
    msg: &[u8],
    what: &str,
) {
    ctx.send_socks5_udp_packet(udp_socket, relay_addr, ctx.mock_server_udp_addr, msg)
        .await;

    let mut recv_buf = [0u8; 2048];
    let data = tokio::time::timeout(
        PACKET_TIMEOUT,
        ctx.recv_socks5_udp_packet(udp_socket, &mut recv_buf),
    )
    .await
    .unwrap_or_else(|_| {
        panic!(
            "[udp_mod={}] {}: no response within {:?}",
            udp_mod, what, PACKET_TIMEOUT
        )
    });
    assert_eq!(data, msg, "[udp_mod={}] {}: echo mismatch", udp_mod, what);
}

/// Run one scenario under an overall timeout, with the mode in panic messages.
async fn run_case(udp_mod: &str, scenario: impl std::future::Future<Output = ()>) {
    tokio::time::timeout(TEST_TIMEOUT, scenario)
        .await
        .unwrap_or_else(|_| {
            panic!(
                "[udp_mod={}] scenario timed out after {:?}",
                udp_mod, TEST_TIMEOUT
            )
        });
}

// ─── Scenarios ────────────────────────────────────────────────────────────

/// Basic UDP ASSOCIATE + single echo packet.
async fn basic_echo(udp_mod: &str) {
    let ctx = setup_chain(udp_mod).await;
    ctx.test_udp_echo().await;
}

/// Several packets over one association, each verified before the next send.
async fn multiple_packets(udp_mod: &str) {
    let ctx = setup_chain(udp_mod).await;
    let (relay_addr, udp_socket, _tcp) = new_session(&ctx).await;

    const PACKET_COUNT: usize = 5;
    for i in 0..PACKET_COUNT {
        let msg = format!("{}-packet-{}", udp_mod, i);
        send_and_expect_echo(udp_mod, &ctx, &udp_socket, relay_addr, msg.as_bytes(), &msg).await;
    }
    println!(
        "[udp_mod={}] {} packets echoed over one association",
        udp_mod, PACKET_COUNT
    );
}

/// One near-datagram-limit payload, exercising framing on both transports.
async fn large_payload(udp_mod: &str) {
    let ctx = setup_chain(udp_mod).await;
    let (relay_addr, udp_socket, _tcp) = new_session(&ctx).await;

    // Non-repeating bytes so truncation/reordering would be caught.
    let msg: Vec<u8> = (0..LARGE_PAYLOAD_LEN).map(|i| (i % 251) as u8).collect();
    send_and_expect_echo(
        udp_mod,
        &ctx,
        &udp_socket,
        relay_addr,
        &msg,
        "large payload",
    )
    .await;
    println!("[udp_mod={}] echoed {}-byte payload", udp_mod, msg.len());
}

/// Burst of packets sent without waiting; UDP loss is tolerated above 80%.
async fn rapid_fire(udp_mod: &str) {
    let ctx = setup_chain(udp_mod).await;
    let (relay_addr, udp_socket, _tcp) = new_session(&ctx).await;

    const PACKET_COUNT: usize = 10;
    for i in 0..PACKET_COUNT {
        let msg = format!("{}-burst-{}", udp_mod, i);
        ctx.send_socks5_udp_packet(
            &udp_socket,
            relay_addr,
            ctx.mock_server_udp_addr,
            msg.as_bytes(),
        )
        .await;
    }

    let mut received = vec![false; PACKET_COUNT];
    for _ in 0..PACKET_COUNT {
        let mut recv_buf = [0u8; 2048];
        match tokio::time::timeout(
            PACKET_TIMEOUT,
            ctx.recv_socks5_udp_packet(&udp_socket, &mut recv_buf),
        )
        .await
        {
            Ok(data) => {
                let prefix = format!("{}-burst-", udp_mod);
                if let Some(idx) = std::str::from_utf8(&data)
                    .ok()
                    .and_then(|s| s.strip_prefix(&prefix))
                    .and_then(|s| s.parse::<usize>().ok())
                {
                    if idx < PACKET_COUNT {
                        received[idx] = true;
                    }
                }
            }
            Err(_) => {
                println!(
                    "[udp_mod={}] quiet after {}/{} responses",
                    udp_mod,
                    received.iter().filter(|&&x| x).count(),
                    PACKET_COUNT
                );
                break;
            }
        }
    }

    let success = received.iter().filter(|&&x| x).count();
    assert!(
        success >= PACKET_COUNT * 8 / 10,
        "[udp_mod={}] rapid fire too lossy: {}/{}",
        udp_mod,
        success,
        PACKET_COUNT
    );
    println!(
        "[udp_mod={}] rapid fire: {}/{} responses",
        udp_mod, success, PACKET_COUNT
    );
}

/// Session survives an idle gap; a later packet is relayed again.
async fn timeout_reestablish(udp_mod: &str) {
    let ctx = setup_chain(udp_mod).await;
    ctx.test_udp_timeout().await;
}

/// Independent associations can run concurrently without cross-talk.
async fn concurrent_sessions(udp_mod: &str) {
    let ctx = setup_chain(udp_mod).await;
    let proxy_addr = ctx.last_proxy().addr;
    let udp_target = ctx.mock_server_udp_addr;

    const SESSION_COUNT: usize = 3;
    let mut handles = Vec::with_capacity(SESSION_COUNT);

    for session_id in 0..SESSION_COUNT {
        let mode = udp_mod.to_string();
        let msg = format!("{}-session-{}-hello", mode, session_id);
        handles.push(tokio::spawn(async move {
            let (relay_addr, _tcp) =
                TestContext::create_socks5_udp_association_for_proxy(proxy_addr).await;
            let udp_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();

            // The first response on a fresh context can race transport setup;
            // only identical bytes are ever echoed on this socket, so a resend
            // is safe.
            for _attempt in 1..=3 {
                TestContext::send_socks5_udp_packet_static(
                    &udp_socket,
                    relay_addr,
                    udp_target,
                    msg.as_bytes(),
                )
                .await;

                let mut recv_buf = [0u8; 2048];
                match tokio::time::timeout(
                    PACKET_TIMEOUT,
                    TestContext::recv_socks5_udp_packet_static(&udp_socket, &mut recv_buf),
                )
                .await
                {
                    Ok(data) if data == msg.as_bytes() => {
                        return Ok::<(), String>(());
                    }
                    Ok(_) => {}  // stray packet, keep waiting
                    Err(_) => {} // timeout, resend
                }
            }
            Err(format!(
                "[udp_mod={}] no echo for session {} after retries",
                mode, session_id
            ))
        }));
    }

    for (session_id, handle) in handles.into_iter().enumerate() {
        handle
            .await
            .expect("session task panicked")
            .unwrap_or_else(|e| panic!("session {} failed: {}", session_id, e));
    }
    println!(
        "[udp_mod={}] {} concurrent UDP sessions isolated",
        udp_mod, SESSION_COUNT
    );
}

/// Dropping the control TCP stream must not break later associations.
async fn tcp_close_no_affect(udp_mod: &str) {
    use tokio::io::AsyncWriteExt;

    let ctx = setup_chain(udp_mod).await;

    // First session, then close the TCP control stream explicitly.
    {
        let (relay_addr, mut tcp_stream) = ctx.create_socks5_udp_association().await;
        let udp_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        send_and_expect_echo(
            udp_mod,
            &ctx,
            &udp_socket,
            relay_addr,
            b"first-session",
            "first session",
        )
        .await;
        tcp_stream.shutdown().await.unwrap();
        drop(tcp_stream);
        drop(udp_socket);
    }

    tokio::time::sleep(Duration::from_millis(500)).await;

    // Second session must still work end-to-end.
    {
        let (relay_addr, _tcp) = ctx.create_socks5_udp_association().await;
        let udp_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        send_and_expect_echo(
            udp_mod,
            &ctx,
            &udp_socket,
            relay_addr,
            b"second-session",
            "second session",
        )
        .await;
    }
}

/// MB/s (decimal megabytes) for `bytes` transferred over `elapsed`.
fn rate_mbps(bytes: u64, elapsed: Duration) -> f64 {
    bytes as f64 / elapsed.as_secs_f64() / 1_000_000.0
}

/// Push `total_bytes` of UDP payload through the chain and report the rate.
///
/// Payload is split into 1200-byte datagrams and sent in bounded batches: a
/// batch is only sent after the echoes of the previous one came back. That
/// keeps the relay/QUIC pipe busy without flooding it (a blind flood just
/// overflows the first UDP hop, so its "rate" measures the kernel, not the
/// chain), and the echoed bytes prove what was actually delivered round-trip.
async fn throughput_burst(udp_mod: &str, total_bytes: u64) {
    const BATCH: usize = 512; // datagrams in flight per batch (~600 KB)

    let ctx = setup_chain(udp_mod).await;
    let (relay_addr, udp_socket, _tcp) = new_session(&ctx).await;

    let packet_count = (total_bytes as usize + THROUGHPUT_PACKET_LEN - 1) / THROUGHPUT_PACKET_LEN;
    let mut sent_pkts = 0usize;
    let mut sent_bytes: u64 = 0;
    let mut echoed_pkts = 0usize;
    let mut echoed_bytes: u64 = 0;

    let start = std::time::Instant::now();
    let mut last_echo_at = start;

    while sent_pkts < packet_count {
        let batch = (packet_count - sent_pkts).min(BATCH);
        for _ in 0..batch {
            let seq = sent_pkts as u32;
            let len = (total_bytes - sent_bytes).min(THROUGHPUT_PACKET_LEN as u64) as usize;
            let mut payload = vec![0u8; len];
            payload[..4].copy_from_slice(&seq.to_be_bytes());
            ctx.send_socks5_udp_packet(&udp_socket, relay_addr, ctx.mock_server_udp_addr, &payload)
                .await;
            sent_pkts += 1;
            sent_bytes += len as u64;
        }

        // Wait for this batch's echoes before sending more.
        let mut recv_buf = [0u8; 2048];
        for _ in 0..batch {
            match tokio::time::timeout(
                THROUGHPUT_QUIET,
                ctx.recv_socks5_udp_packet(&udp_socket, &mut recv_buf),
            )
            .await
            {
                Ok(data) => {
                    echoed_bytes += data.len() as u64;
                    echoed_pkts += 1;
                    last_echo_at = std::time::Instant::now();
                }
                // Pipe went quiet: batch was fully drained (or partly lost).
                Err(_) => break,
            }
        }
    }

    // Final drain so nothing still in flight is left uncounted.
    let mut recv_buf = [0u8; 2048];
    loop {
        match tokio::time::timeout(
            THROUGHPUT_QUIET,
            ctx.recv_socks5_udp_packet(&udp_socket, &mut recv_buf),
        )
        .await
        {
            Ok(data) => {
                echoed_bytes += data.len() as u64;
                echoed_pkts += 1;
                last_echo_at = std::time::Instant::now();
            }
            Err(_) => break,
        }
    }

    let data_elapsed = last_echo_at.duration_since(start);
    let delivery = echoed_pkts as f64 / packet_count as f64 * 100.0;
    println!(
        "[udp_mod={}] {:.1} MiB in {} pkts ({} in flight): echoed {} pkts ({:.1}%), {:.3}s",
        udp_mod,
        total_bytes as f64 / (1024.0 * 1024.0),
        packet_count,
        BATCH,
        echoed_pkts,
        delivery,
        data_elapsed.as_secs_f64(),
    );
    println!(
        "[udp_mod={}] throughput: {:.1} MB/s ({:.1} MiB/s)",
        udp_mod,
        rate_mbps(echoed_bytes, data_elapsed),
        echoed_bytes as f64 / (1024.0 * 1024.0) / data_elapsed.as_secs_f64(),
    );

    assert!(
        delivery >= 90.0,
        "[udp_mod={}] too many packets lost in throughput run ({:.1}%)",
        udp_mod,
        delivery
    );
}

// ─── Tests (one per udp_mod) ──────────────────────────────────────────────

macro_rules! udp_mode_case {
    ($test_name:ident, $mod:literal, $scenario:ident) => {
        #[tokio::test]
        async fn $test_name() {
            run_case($mod, $scenario($mod)).await;
        }
    };
}

udp_mode_case!(test_shadowquic_udp_stream_basic_echo, "stream", basic_echo);
udp_mode_case!(
    test_shadowquic_udp_stream_multiple_packets,
    "stream",
    multiple_packets
);
udp_mode_case!(
    test_shadowquic_udp_stream_large_payload,
    "stream",
    large_payload
);
udp_mode_case!(test_shadowquic_udp_stream_rapid_fire, "stream", rapid_fire);
udp_mode_case!(
    test_shadowquic_udp_stream_timeout_reestablish,
    "stream",
    timeout_reestablish
);
udp_mode_case!(
    test_shadowquic_udp_stream_concurrent_sessions,
    "stream",
    concurrent_sessions
);
udp_mode_case!(
    test_shadowquic_udp_stream_tcp_close_no_affect,
    "stream",
    tcp_close_no_affect
);

#[tokio::test]
async fn test_shadowquic_udp_stream_throughput_20mb() {
    run_case("stream", throughput_burst("stream", THROUGHPUT_20MB)).await;
}

#[tokio::test]
async fn test_shadowquic_udp_stream_throughput_200mb() {
    run_case("stream", throughput_burst("stream", THROUGHPUT_200MB)).await;
}

udp_mode_case!(
    test_shadowquic_udp_datagram_basic_echo,
    "datagram",
    basic_echo
);
udp_mode_case!(
    test_shadowquic_udp_datagram_multiple_packets,
    "datagram",
    multiple_packets
);
udp_mode_case!(
    test_shadowquic_udp_datagram_large_payload,
    "datagram",
    large_payload
);
udp_mode_case!(
    test_shadowquic_udp_datagram_rapid_fire,
    "datagram",
    rapid_fire
);
udp_mode_case!(
    test_shadowquic_udp_datagram_timeout_reestablish,
    "datagram",
    timeout_reestablish
);
udp_mode_case!(
    test_shadowquic_udp_datagram_concurrent_sessions,
    "datagram",
    concurrent_sessions
);
udp_mode_case!(
    test_shadowquic_udp_datagram_tcp_close_no_affect,
    "datagram",
    tcp_close_no_affect
);

#[tokio::test]
async fn test_shadowquic_udp_datagram_throughput_20mb() {
    run_case("datagram", throughput_burst("datagram", THROUGHPUT_20MB)).await;
}

#[tokio::test]
async fn test_shadowquic_udp_datagram_throughput_200mb() {
    run_case("datagram", throughput_burst("datagram", THROUGHPUT_200MB)).await;
}
