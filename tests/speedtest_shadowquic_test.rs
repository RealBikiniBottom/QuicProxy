//! Speed test through shadowquic: the QUIC connection's RTT feeds the power
//! metric. Kept apart from `speedtest_test.rs` because the speed test registry
//! is process-wide and allows one task at a time.

mod common;

use common::shadowquic::{client_config, server_config};
use common::{TestContext, Watchdog};
use quicproxy::utils::speedtest::{
    self, Direction, Mode, Phase, Snapshot, SpeedTestRequest, State, UpCounting,
};
use serde_json::json;
use std::time::Duration;

const SPEEDTEST_DOMAIN: &str = "speedtest.quicproxy.internal";

/// The summary's power is the mean of the per-second powers, each the
/// second's rate (Mbit/s) over its request ping (ms).
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
            // P_t = rate (Mbit/s) / ping (ms). rtt_ms is rounded to 1 µs,
            // which is a few percent of a loopback ping.
            let expected = rate as f64 / 1e6 / ping;
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

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_speedtest_power_through_shadowquic() {
    let _watchdog = Watchdog::new(
        "test_speedtest_power_through_shadowquic",
        Duration::from_secs(90),
    );
    let mut ctx = TestContext::new().await;

    let mut server = server_config("user", "testpassword");
    server["outbounds"] = json!({
        "servers": {
            "direct_out": { "type": "direct" },
            "speedtest": { "type": "speedtest" }
        }
    });
    server["router"] = json!({
        "default_mode": "rule",
        "rules": [ { "domain": [SPEEDTEST_DOMAIN], "outbound": "speedtest" } ]
    });
    let server_idx = ctx.start_proxy(server, "sq_in").await;
    let server_port = ctx.proxies[server_idx].port;

    // The client config replaces the process-wide router, so it carries the
    // server inbound's speedtest rule too.
    let mut client = client_config("user", "testpassword", server_port, None);
    client["router"] = json!({
        "default_mode": "rule",
        "rules": [
            { "inbounds": ["sq_in"], "domain": [SPEEDTEST_DOMAIN], "outbound": "speedtest" }
        ]
    });
    ctx.start_proxy(client, "socks_in").await;

    let mut req = SpeedTestRequest::new("sq_out");
    req.mode = Mode::Once;
    req.direction = Direction::Both;
    req.phase_secs = 4;
    req.connections = 2;
    let task = speedtest::start(req).unwrap();
    tokio::time::timeout(Duration::from_secs(40), async {
        while task.state() == State::Running {
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    })
    .await
    .expect("speed test did not finish in time");
    let snap = task.snapshot(None, true);
    println!(
        "shadowquic: {}",
        serde_json::to_string_pretty(&snap).unwrap()
    );
    assert_eq!(snap.state, State::Finished, "error: {:?}", snap.error);

    for phase in [Phase::Download, Phase::Upload] {
        assert!(
            snap.samples
                .iter()
                .any(|s| s.phase == phase && s.data_rtt_ms.is_some_and(|r| r > 0.0)),
            "no data RTT during {phase:?}"
        );
    }
    // Per-second QUIC loss from the sending side: the server while
    // downloading (shadowquic answers the stats query), the client uploading.
    for phase in [Phase::Download, Phase::Upload] {
        assert!(
            snap.samples
                .iter()
                .any(|s| s.phase == phase && s.quic_loss_pct.is_some()),
            "no per-second QUIC loss during {phase:?}"
        );
    }
    // The data RTT is quinn's smoothed RTT polled every 100 ms, averaged per
    // 1 s sample.
    assert_eq!(snap.data_rtt_source, Some("quic_srtt"));
    let polls: Vec<u32> = snap
        .samples
        .iter()
        .filter(|s| s.data_rtt_ms.is_some())
        .map(|s| s.data_rtt_samples)
        .collect();
    assert!(
        polls.iter().any(|&n| n >= 5),
        "expected several polls per sample: {polls:?}"
    );
    // The data RTT is shown, not used for power.
    assert!(snap.summary.down_data_rtt_ms.is_some_and(|r| r > 0.0));
    assert!(snap.summary.up_data_rtt_ms.is_some_and(|r| r > 0.0));
    check_power(&snap);
}
