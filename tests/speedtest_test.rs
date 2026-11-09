mod common;

use common::{TestContext, Watchdog};
use quicproxy::utils::speedtest::{
    self, Direction, Mode, Phase, Snapshot, SpeedTestRequest, SpeedTestTask, StartError, State,
    UpCounting,
};
use std::sync::Arc;
use std::time::Duration;

const SPEEDTEST_DOMAIN: &str = "speedtest.quicproxy.internal";

async fn wait_done(task: &Arc<SpeedTestTask>, limit: Duration) -> Snapshot {
    tokio::time::timeout(limit, async {
        while task.state() == State::Running {
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    })
    .await
    .expect("speed test did not finish in time");
    task.snapshot(None, true)
}

async fn wait_phase(task: &Arc<SpeedTestTask>, phase: Phase, limit: Duration) {
    tokio::time::timeout(limit, async {
        while task.snapshot(None, false).phase != phase {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("speed test never reached {phase:?}"));
}

/// The summary's power is the mean of the per-second powers, each the
/// second's rate over its request ping normalised to 50 ms.
fn check_power(snap: &Snapshot) {
    for (phase, power) in [
        (Phase::Download, snap.summary.down_power),
        (Phase::Upload, snap.summary.up_power),
    ] {
        let mut per_second = Vec::new();
        for s in snap.samples.iter().filter(|s| s.phase == phase) {
            let Some(p) = s.power else { continue };
            let rate = if phase == Phase::Download {
                s.down_bps
            } else {
                s.up_bps
            };
            let ping = s.rtt_ms.expect("power without a ping");
            let expected = rate as f64 / 1e6 / (ping / 50.0);
            // rtt_ms is rounded to 0.01 ms, a few percent on loopback.
            assert!(
                (p - expected).abs() <= 0.05 * expected,
                "{phase:?}: {p} vs {expected}"
            );
            per_second.push(p);
        }
        assert!(
            !per_second.is_empty(),
            "no per-second power during {phase:?}"
        );
        let mean = per_second.iter().sum::<f64>() / per_second.len() as f64;
        let power = power.unwrap_or_else(|| panic!("{phase:?}: no power"));
        assert!(
            (power - mean).abs() <= 0.01 * mean,
            "{phase:?}: {power} vs mean {mean}"
        );
    }
    assert!(snap.summary.down_loaded_rtt_ms.is_some());
    assert!(snap.summary.up_loaded_rtt_ms.is_some());
    assert_eq!(snap.summary.up_counting, Some(UpCounting::Acked));
}

fn request(mode: Mode, direction: Direction, phase_secs: u64) -> SpeedTestRequest {
    let mut req = SpeedTestRequest::new("trojan_out");
    req.mode = mode;
    req.direction = direction;
    req.phase_secs = phase_secs;
    req.connections = 2;
    req
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_speedtest_through_trojan() {
    let _watchdog = Watchdog::new("test_speedtest_through_trojan", Duration::from_secs(150));
    let mut context = TestContext::new().await;
    let (cert_path, key_path) = TestContext::generate_tls_files();

    // No default_server: with two outbounds the test harness then doesn't pin
    // this inbound to a final outbound, so the client's speedtest rule below
    // still applies to it once the client config replaces the router.
    let server_config = serde_json::json!({
        "inbounds": {
            "trojan_in": {
                "type": "trojan",
                "address": "127.0.0.1",
                "port": 0,
                "password": "password",
                "transport": { "type": "tcp" },
                "tls": {
                    "enable": true,
                    "cert": cert_path.to_str().unwrap(),
                    "key": key_path.to_str().unwrap()
                }
            }
        },
        "outbounds": {
            "servers": {
                "direct_out": { "type": "direct" },
                "speedtest": { "type": "speedtest" }
            }
        },
        "dns": {
            "default_server": "local_dns",
            "servers": {
                "local_dns": { "type": "udp", "address": "8.8.8.8", "port": 53, "outbound": "direct_out" }
            }
        },
        "router": {
            "default_mode": "rule",
            "rules": [ { "domain": [SPEEDTEST_DOMAIN], "outbound": "speedtest" } ]
        },
        "log": { "level": "info" }
    });
    let server_idx = context.start_proxy(server_config, "trojan_in").await;
    let server_port = context.proxies[server_idx].port;

    let client_config = serde_json::json!({
        "inbounds": {
            "socks_in": { "type": "socks5", "address": "127.0.0.1", "port": 0 }
        },
        "outbounds": {
            "default_server": "trojan_out",
            "servers": {
                "trojan_out": {
                    "type": "trojan",
                    "address": "127.0.0.1",
                    "port": server_port,
                    "password": "password",
                    "transport": { "type": "tcp" },
                    "tls": {
                        "enable": true,
                        "ca": cert_path.to_str().unwrap(),
                        "server_name": "localhost"
                    }
                },
                // Not a quicproxy server: the speed test handshake must fail.
                "bad_out": {
                    "type": "socks5",
                    "address": context.mock_server_http_addr.ip().to_string(),
                    "port": context.mock_server_http_addr.port()
                },
                "dns_direct": { "type": "direct" }
            }
        },
        "dns": {
            "default_server": "local_dns",
            "servers": {
                "local_dns": { "type": "udp", "address": "8.8.8.8", "port": 53, "outbound": "dns_direct" }
            }
        },
        "router": {
            "default_mode": "rule",
            "rules": [
                { "inbounds": ["trojan_in"], "domain": [SPEEDTEST_DOMAIN], "outbound": "speedtest" }
            ]
        },
        "log": { "level": "info" }
    });
    context.start_proxy(client_config, "socks_in").await;

    // Rejected starts.
    assert!(matches!(
        speedtest::start(SpeedTestRequest::new("missing")),
        Err(StartError::NotFound)
    ));
    assert!(matches!(
        speedtest::start(SpeedTestRequest::new("dns_direct")),
        Err(StartError::Unsupported(_))
    ));

    // Once: idle latency, download, upload.
    let task = speedtest::start(request(Mode::Once, Direction::Both, 3)).unwrap();
    assert!(matches!(
        speedtest::start(request(Mode::Once, Direction::Both, 3)),
        Err(StartError::Busy(_))
    ));
    let snap = wait_done(&task, Duration::from_secs(40)).await;
    println!("once: {}", serde_json::to_string_pretty(&snap).unwrap());
    assert_eq!(snap.state, State::Finished, "error: {:?}", snap.error);
    assert_eq!(snap.stop_reason.as_deref(), Some("completed"));
    assert_eq!(snap.effective_tag, "trojan_out");
    let down = snap.summary.down.as_ref().expect("download summary");
    let up = snap.summary.up.as_ref().expect("upload summary");
    assert!(down.avg_bps > 10_000_000, "download too slow: {down:?}");
    assert!(up.avg_bps > 10_000_000, "upload too slow: {up:?}");
    assert!(snap.summary.idle_rtt_ms.is_some());
    assert!(snap.summary.loaded_rtt_ms.is_some());
    assert!(snap.summary.jitter_ms.is_some());
    // Power comes from the request ping, so trojan has it too; only the QUIC
    // data RTT is missing.
    check_power(&snap);
    assert!(snap.samples.iter().all(|s| s.data_rtt_ms.is_none()));
    assert!(snap.samples.iter().all(|s| s.data_rtt_samples == 0));
    assert_eq!(snap.data_rtt_source, None);
    assert_eq!(snap.summary.down_data_rtt_ms, None);
    // Per-second loss: UDP echo for every node, QUIC never for trojan.
    assert!(snap.samples.iter().all(|s| s.quic_loss_pct.is_none()));
    assert!(
        snap.samples
            .iter()
            .any(|s| s.udp_loss_pct.is_some_and(|l| (0.0..=100.0).contains(&l))),
        "no per-second UDP loss"
    );
    assert!(
        snap.summary.udp_loss_pct.is_some(),
        "UDP echo never answered"
    );
    assert_eq!(snap.rounds.len(), 1);
    assert!(
        snap.samples.len() >= 8,
        "only {} samples",
        snap.samples.len()
    );
    assert!(snap.bytes_down > 10_000_000 && snap.bytes_up > 10_000_000);

    // Incremental polling returns only newer samples.
    let tail = task.snapshot(Some(snap.next_seq - 2), true);
    assert_eq!(tail.samples.len(), 2);

    // Continuous, stopped by the user.
    let task = speedtest::start(request(Mode::Continuous, Direction::Download, 2)).unwrap();
    tokio::time::sleep(Duration::from_secs(6)).await;
    assert!(speedtest::stop(&task.id));
    let snap = wait_done(&task, Duration::from_secs(10)).await;
    assert_eq!(snap.state, State::Cancelled, "error: {:?}", snap.error);
    assert!(snap.summary.down.is_some());
    assert!(snap.summary.up.is_none());

    // Continuous, stopped by the traffic cap.
    let mut req = request(Mode::Continuous, Direction::Both, 2);
    req.max_bytes = Some(64 * 1024 * 1024);
    let task = speedtest::start(req).unwrap();
    let snap = wait_done(&task, Duration::from_secs(60)).await;
    assert_eq!(snap.state, State::Finished, "error: {:?}", snap.error);
    assert_eq!(snap.stop_reason.as_deref(), Some("max_bytes"));
    assert!(snap.bytes_down + snap.bytes_up >= 64 * 1024 * 1024);

    // Periodic: after one round the task waits for the next one.
    let task = speedtest::start(request(Mode::Periodic, Direction::Upload, 2)).unwrap();
    wait_phase(&task, Phase::Waiting, Duration::from_secs(20)).await;
    let snap = task.snapshot(None, true);
    assert_eq!(snap.rounds.len(), 1);
    assert!(snap.rounds[0].summary.up.is_some());
    speedtest::stop(&task.id);
    assert_eq!(
        wait_done(&task, Duration::from_secs(10)).await.state,
        State::Cancelled
    );

    // A node that is not a quicproxy server fails cleanly.
    let mut req = SpeedTestRequest::new("bad_out");
    req.phase_secs = 2;
    let task = speedtest::start(req).unwrap();
    let snap = wait_done(&task, Duration::from_secs(30)).await;
    assert_eq!(snap.state, State::Failed);
    assert!(
        snap.error
            .as_deref()
            .unwrap_or_default()
            .contains("does not support built-in speed test"),
        "{:?}",
        snap.error
    );
}
