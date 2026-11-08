//! Speed test through shadowquic: the QUIC connection's RTT feeds the power
//! metric. Kept apart from `speedtest_test.rs` because the speed test registry
//! is process-wide and allows one task at a time.

mod common;

use common::shadowquic::{client_config, server_config};
use common::{TestContext, Watchdog};
use quicproxy::utils::speedtest::{self, Direction, Mode, Phase, SpeedTestRequest, State};
use serde_json::json;
use std::time::Duration;

const SPEEDTEST_DOMAIN: &str = "speedtest.quicproxy.internal";

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
    let s = &snap.summary;
    for (dir, rtt, util, power) in [
        ("down", s.down_data_rtt_ms, s.down_utilization, s.down_power),
        ("up", s.up_data_rtt_ms, s.up_utilization, s.up_power),
    ] {
        let rtt = rtt.unwrap_or_else(|| panic!("{dir}: no data RTT"));
        let util = util.unwrap_or_else(|| panic!("{dir}: no utilization"));
        let power = power.unwrap_or_else(|| panic!("{dir}: no power"));
        assert!(rtt > 0.0 && util > 0.0 && util <= 1.0, "{dir}: {s:?}");
        // The summary rounds the RTT to 0.01 ms, which on loopback (~0.1 ms)
        // moves the recomputed value by a few percent.
        let expected = util / (rtt / 50.0);
        assert!(
            (power - expected).abs() <= 0.1 * expected,
            "{dir}: power {power} vs {expected}"
        );
    }
}
