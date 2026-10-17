//! ShadowQuic 0-RTT latency tests on a local client/server chain.
//!
//! A UDP relay between the shadowquic client and server adds a fixed one-way
//! delay, so the time a proxied request takes shows how many round trips it
//! cost: about one RTT on a reused or 0-RTT connection, about two on a fresh
//! 1-RTT handshake.

mod common;
use common::TestContext;
use common::shadowquic::{client_config, jls_client_config, jls_server_config, server_config};
use quicproxy::config::AuthUser;
use quicproxy::utils::quic_wrap::quinn_wrap::{QuinnClient, QuinnServer};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

const ONE_WAY_DELAY: Duration = Duration::from_millis(100);
const RTT: Duration = Duration::from_millis(200);
const IDLE_TIMEOUT_SECS: u64 = 3;
const ZERO_RTT_ROUNDS: usize = 3;

/// Forward UDP between clients and `server`, delaying every packet by
/// [ONE_WAY_DELAY] in each direction.
async fn spawn_delay_relay(server: SocketAddr) -> SocketAddr {
    let relay = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let relay_addr = relay.local_addr().unwrap();

    tokio::spawn(async move {
        let mut upstreams: HashMap<SocketAddr, Arc<UdpSocket>> = HashMap::new();
        let mut buf = vec![0u8; 65535];
        loop {
            let Ok((n, client)) = relay.recv_from(&mut buf).await else {
                return;
            };
            let upstream = match upstreams.get(&client) {
                Some(socket) => socket.clone(),
                None => {
                    let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
                    socket.connect(server).await.unwrap();
                    let (reader, relay) = (socket.clone(), relay.clone());
                    tokio::spawn(async move {
                        let mut buf = vec![0u8; 65535];
                        while let Ok(n) = reader.recv(&mut buf).await {
                            let packet = buf[..n].to_vec();
                            let relay = relay.clone();
                            tokio::spawn(async move {
                                tokio::time::sleep(ONE_WAY_DELAY).await;
                                let _ = relay.send_to(&packet, client).await;
                            });
                        }
                    });
                    upstreams.insert(client, socket.clone());
                    socket
                }
            };
            let packet = buf[..n].to_vec();
            tokio::spawn(async move {
                tokio::time::sleep(ONE_WAY_DELAY).await;
                let _ = upstream.send(&packet).await;
            });
        }
    });

    relay_addr
}

async fn socks5_connect(proxy: SocketAddr, target: SocketAddr) -> TcpStream {
    let mut stream = TcpStream::connect(proxy).await.unwrap();

    stream.write_all(&[5, 1, 0]).await.unwrap();
    let mut method = [0u8; 2];
    stream.read_exact(&mut method).await.unwrap();
    assert_eq!(method, [5, 0]);

    let std::net::IpAddr::V4(ip) = target.ip() else {
        panic!("IPv6 not supported in this test");
    };
    let mut req = vec![5, 1, 0, 1];
    req.extend_from_slice(&ip.octets());
    req.extend_from_slice(&target.port().to_be_bytes());
    stream.write_all(&req).await.unwrap();

    let mut resp_head = [0u8; 4];
    stream.read_exact(&mut resp_head).await.unwrap();
    assert_eq!(resp_head[1], 0, "SOCKS5 connect should succeed");
    let rest = match resp_head[3] {
        1 => 6,
        4 => 18,
        3 => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await.unwrap();
            len[0] as usize + 2
        }
        other => panic!("Unexpected address type: {}", other),
    };
    let mut buf = vec![0u8; rest];
    stream.read_exact(&mut buf).await.unwrap();

    stream
}

/// Time one proxied request: SOCKS5 connect, send `payload`, read its echo.
async fn timed_echo(proxy: SocketAddr, target: SocketAddr, payload: &[u8]) -> Duration {
    let start = Instant::now();
    let mut stream = socks5_connect(proxy, target).await;
    stream.write_all(payload).await.unwrap();
    let mut buf = vec![0u8; payload.len()];
    stream.read_exact(&mut buf).await.unwrap();
    assert_eq!(buf, payload);
    start.elapsed()
}

fn rtts(d: Duration) -> f64 {
    d.as_secs_f64() / RTT.as_secs_f64()
}

async fn zero_rtt_latency(
    mut server_cfg: serde_json::Value,
    client_cfg: impl FnOnce(u16) -> serde_json::Value,
) {
    let mut ctx = TestContext::new().await;

    server_cfg["inbounds"]["sq_in"]["idle_timeout"] = serde_json::json!(IDLE_TIMEOUT_SECS);
    server_cfg["inbounds"]["sq_in"]["tls"]["zero_rtt"] = serde_json::json!(true);
    let server_idx = ctx.start_proxy(server_cfg, "sq_in").await;
    let relay = spawn_delay_relay(ctx.proxies[server_idx].addr).await;

    let mut client_cfg = client_cfg(relay.port());
    client_cfg["outbounds"]["servers"]["sq_out"]["idle_timeout"] =
        serde_json::json!(IDLE_TIMEOUT_SECS);
    client_cfg["outbounds"]["servers"]["sq_out"]["tls"]["zero_rtt"] = serde_json::json!(true);
    ctx.start_proxy(client_cfg, "socks_in").await;

    let proxy = ctx.last_proxy().addr;
    let target = ctx.mock_server_tcp_addr;

    let test_fut = async {
        let cold = timed_echo(proxy, target, b"cold").await;
        let reused = timed_echo(proxy, target, b"reused").await;
        println!("cold 1-RTT connection: {:?} ({:.2} RTT)", cold, rtts(cold));
        println!(
            "reused connection:     {:?} ({:.2} RTT)",
            reused,
            rtts(reused)
        );

        let mut zero_rtt = Vec::with_capacity(ZERO_RTT_ROUNDS);
        for round in 0..ZERO_RTT_ROUNDS {
            // Let the idle timeout close the cached connection so the next
            // request has to resume with a session ticket.
            tokio::time::sleep(Duration::from_secs(IDLE_TIMEOUT_SECS + 2)).await;
            let elapsed = timed_echo(proxy, target, b"zero-rtt").await;
            println!(
                "0-RTT connection #{}:   {:?} ({:.2} RTT)",
                round + 1,
                elapsed,
                rtts(elapsed)
            );
            zero_rtt.push(elapsed);
        }

        assert!(
            reused < RTT * 3 / 2,
            "a request on a reused connection should cost one RTT, took {:?}",
            reused
        );
        for (round, elapsed) in zero_rtt.iter().enumerate() {
            assert!(
                *elapsed < RTT * 3 / 2,
                "0-RTT request #{} should cost one RTT like a reused connection, took {:?} \
                 ({:.2} RTT; cold 1-RTT took {:?})",
                round + 1,
                elapsed,
                rtts(*elapsed),
                cold
            );
        }
    };

    tokio::time::timeout(Duration::from_secs(60), test_fut)
        .await
        .expect("0-RTT latency test timed out after 60s");
}

#[tokio::test]
async fn test_shadowquic_zero_rtt_saves_a_round_trip() {
    zero_rtt_latency(server_config("user", "testpassword"), |port| {
        client_config("user", "testpassword", port, None)
    })
    .await;
}

#[tokio::test]
async fn test_shadowquic_jls_zero_rtt_saves_a_round_trip() {
    zero_rtt_latency(jls_server_config("user", "testpassword"), |port| {
        jls_client_config("user", "testpassword", port)
    })
    .await;
}

fn quic_client(socket: std::net::UdpSocket) -> QuinnClient {
    QuinnClient::new(
        socket,
        Duration::from_secs(30),
        false,
        true,
        None,
        Some("localhost".to_string()),
        None,
        None,
        "user".to_string(),
        "password".to_string(),
        false,
        false,
        false,
        1200,
        1200,
    )
    .unwrap()
}

fn client_socket() -> std::net::UdpSocket {
    let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    socket.set_nonblocking(true).unwrap();
    socket
}

/// A busy server hands out tickets to many other clients between two
/// connections of the same client. Its session store must not evict the
/// first client's ticket that quickly, or that client silently loses 0-RTT
/// and pays a rejected 0-RTT attempt plus a replay on a new connection.
#[tokio::test]
async fn test_shadowquic_zero_rtt_survives_busy_server() {
    const OTHER_CLIENTS: usize = 300;

    let addr = std::net::UdpSocket::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap();
    let users = [AuthUser {
        username: "user".to_string(),
        password: "password".to_string(),
    }];
    let mut server = QuinnServer::new(
        addr,
        Duration::from_secs(30),
        None,
        None,
        None,
        Some("localhost".to_string()),
        None,
        true,
        &users,
        false,
        false,
        false,
        1200,
        1200,
    )
    .unwrap();
    tokio::spawn(async move {
        while let Ok(conn) = server.accept().await {
            tokio::spawn(async move { conn.closed().await });
        }
    });

    let test_fut = async {
        let client = quic_client(client_socket());
        let (first, outcome) = client.connect_with_0rtt(addr).await.unwrap();
        assert!(outcome.is_none(), "a fresh client has no session ticket");
        tokio::time::sleep(Duration::from_millis(200)).await;
        first.close(0u32.into(), b"");

        for batch in (0..OTHER_CLIENTS).collect::<Vec<_>>().chunks(30) {
            let handles: Vec<_> = batch
                .iter()
                .map(|_| {
                    tokio::spawn(async move {
                        let other = quic_client(client_socket());
                        let conn = other.connect(addr).await.unwrap();
                        tokio::time::sleep(Duration::from_millis(50)).await;
                        conn.close(0u32.into(), b"");
                    })
                })
                .collect();
            for handle in handles {
                handle.await.unwrap();
            }
        }

        let (_resumed, outcome) = client.connect_with_0rtt(addr).await.unwrap();
        let outcome = outcome.expect("the client still holds a session ticket");
        assert!(
            outcome.await,
            "server rejected 0-RTT after {} other clients connected",
            OTHER_CLIENTS
        );
    };

    tokio::time::timeout(Duration::from_secs(60), test_fut)
        .await
        .expect("busy-server 0-RTT test timed out after 60s");
}
