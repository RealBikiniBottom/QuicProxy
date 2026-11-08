//! The speed test loop: phases, transfer workers, probes and the sampler.

use std::collections::HashMap;
use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use anyhow::{Context as _, Result, bail};
use bytes::{BufMut, BytesMut};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::task::JoinSet;
use tokio::time::{MissedTickBehavior, interval, sleep, sleep_until, timeout};
use tokio_util::sync::CancellationToken;
use tracing::{debug, info};

use super::proto::{self, SPEEDTEST_DOMAIN};
use super::{Mode, Phase, SampleInput, SpeedTestTask};
use crate::proxy::TargetAddr;
use crate::proxy::outbound::{AnyOutbound, AnyStream, PathState};

/// Idle latency measurement at the start of a round.
pub(super) const IDLE_LATENCY: Duration = Duration::from_secs(3);
const PING_INTERVAL: Duration = Duration::from_secs(1);
const PROBE_TIMEOUT: Duration = Duration::from_secs(2);
const UDP_INTERVAL: Duration = Duration::from_millis(50);
const UDP_PROBE_LEN: usize = 32;
/// Bound on the server-side stats query so a slow answer under load does not
/// hold up the 1 s sampler for long.
const DOWNLINK_STATE_TIMEOUT: Duration = Duration::from_secs(1);
const RECONNECT_DELAY: Duration = Duration::from_millis(500);

/// Samples taken this early in a phase are dropped from the summary, since
/// TCP/QUIC congestion control is still ramping up.
pub(super) fn warmup(phase_secs: u64) -> Duration {
    Duration::from_secs(2.min(phase_secs / 3))
}

/// Marks the task cancelled if its future is dropped before finishing, e.g.
/// when the core shuts down and aborts every spawned task.
struct DropGuard(Arc<SpeedTestTask>);

impl Drop for DropGuard {
    fn drop(&mut self) {
        self.0.stop(None);
        self.0.finish(Ok(()));
    }
}

pub(super) async fn run(task: Arc<SpeedTestTask>, outbound: Arc<dyn AnyOutbound>) {
    let _guard = DropGuard(task.clone());
    info!(
        "speed test {} started on [{}] ({:?}, {:?})",
        task.id, task.effective_tag, task.req.mode, task.req.direction
    );
    let result = run_inner(&task, &outbound).await;
    if let Err(e) = &result {
        info!("speed test {} failed: {e:#}", task.id);
    }
    task.finish(result);
    let (down, up) = task.bytes();
    info!(
        "speed test {} ended: {:?}, down {} bytes, up {} bytes",
        task.id,
        task.state(),
        down,
        up
    );
}

async fn run_inner(task: &Arc<SpeedTestTask>, outbound: &Arc<dyn AnyOutbound>) -> Result<()> {
    // The first connection doubles as the support check: a node that is not a
    // quicproxy server with a speedtest route fails the handshake here.
    let first = tokio::select! {
        r = connect(task, outbound) => r.context("node does not support built-in speed test")?,
        _ = task.cancel.cancelled() => return Ok(()),
    };

    let mut background = JoinSet::new();
    background.spawn(tcp_probe(task.clone(), outbound.clone(), first));
    background.spawn(udp_probe(task.clone(), outbound.clone()));
    background.spawn(sampler(task.clone(), outbound.clone()));

    let result = tokio::select! {
        r = rounds(task, outbound) => r,
        _ = task.cancel.cancelled() => Ok(()),
    };
    background.shutdown().await;
    result
}

async fn rounds(task: &Arc<SpeedTestTask>, outbound: &Arc<dyn AnyOutbound>) -> Result<()> {
    let req = task.req.clone();
    let mut first = true;
    loop {
        let round_start = tokio::time::Instant::now();
        task.begin_round();
        if first || req.mode != Mode::Continuous {
            task.set_phase(Phase::IdleLatency);
            sleep(IDLE_LATENCY).await;
        }
        if req.direction.download() {
            transfer_phase(task, outbound, Phase::Download).await;
        }
        if req.direction.upload() {
            transfer_phase(task, outbound, Phase::Upload).await;
        }
        task.end_round();
        first = false;

        match req.mode {
            Mode::Once => {
                task.stop(Some("completed"));
                return Ok(());
            }
            Mode::Continuous => {}
            Mode::Periodic => {
                task.set_phase(Phase::Waiting);
                sleep_until(round_start + Duration::from_secs(req.interval_secs)).await;
            }
        }
    }
}

async fn transfer_phase(task: &Arc<SpeedTestTask>, outbound: &Arc<dyn AnyOutbound>, phase: Phase) {
    task.set_phase(phase);
    let token = task.cancel.child_token();
    let mut workers = JoinSet::new();
    for _ in 0..task.req.connections {
        workers.spawn(worker(task.clone(), outbound.clone(), phase, token.clone()));
    }
    sleep(Duration::from_secs(task.req.phase_secs)).await;
    token.cancel();
    workers.shutdown().await;
}

async fn worker(
    task: Arc<SpeedTestTask>,
    outbound: Arc<dyn AnyOutbound>,
    phase: Phase,
    token: CancellationToken,
) {
    while !token.is_cancelled() {
        let result = tokio::select! {
            r = transfer(&task, &outbound, phase) => r,
            _ = token.cancelled() => return,
        };
        if let Err(e) = result {
            debug!("speed test {} {:?} stream failed: {e:#}", task.id, phase);
            task.record_error();
            tokio::select! {
                _ = sleep(RECONNECT_DELAY) => {}
                _ = token.cancelled() => return,
            }
        }
    }
}

/// Runs transfers on one stream until it fails; cancellation drops it.
async fn transfer(
    task: &Arc<SpeedTestTask>,
    outbound: &Arc<dyn AnyOutbound>,
    phase: Phase,
) -> Result<()> {
    let mut s = connect(task, outbound).await?;
    loop {
        match phase {
            Phase::Download => {
                s.write_all(&command(proto::CMD_DOWNLOAD, proto::MAX_TRANSFER))
                    .await?;
                s.flush().await?;
                proto::discard(&mut s, proto::MAX_TRANSFER).await?;
            }
            Phase::Upload => {
                s.write_all(&command(proto::CMD_UPLOAD, proto::MAX_TRANSFER))
                    .await?;
                proto::write_payload(&mut s, proto::MAX_TRANSFER).await?;
                let got = s.read_u64().await?;
                if got != proto::MAX_TRANSFER {
                    bail!("server acknowledged {got} of {} bytes", proto::MAX_TRANSFER);
                }
            }
            _ => unreachable!("transfer phase"),
        }
    }
}

fn command(cmd: u8, arg: u64) -> [u8; 9] {
    let mut buf = [0u8; 9];
    buf[0] = cmd;
    buf[1..].copy_from_slice(&arg.to_be_bytes());
    buf
}

fn tcp_target() -> TargetAddr {
    TargetAddr::Domain(SPEEDTEST_DOMAIN.to_string(), proto::TCP_PORT)
}

fn udp_target() -> TargetAddr {
    TargetAddr::Domain(SPEEDTEST_DOMAIN.to_string(), proto::UDP_PORT)
}

async fn connect(
    task: &Arc<SpeedTestTask>,
    outbound: &Arc<dyn AnyOutbound>,
) -> Result<CountingStream> {
    let limit = outbound.connect_timeout() + PROBE_TIMEOUT;
    timeout(limit, async {
        let inner = outbound.connect_stream(&tcp_target()).await?;
        let mut s = CountingStream {
            inner,
            down: task.down.clone(),
            up: task.up.clone(),
        };
        proto::client_handshake(&mut s).await?;
        anyhow::Ok(s)
    })
    .await
    .context("speed test connect timed out")?
}

// ─── Probes ───

async fn tcp_probe(
    task: Arc<SpeedTestTask>,
    outbound: Arc<dyn AnyOutbound>,
    first: CountingStream,
) {
    let mut conn = Some(first);
    let mut seq = 0u64;
    let mut tick = interval(PING_INTERVAL);
    tick.set_missed_tick_behavior(MissedTickBehavior::Delay);
    loop {
        tick.tick().await;
        if conn.is_none() {
            match connect(&task, &outbound).await {
                Ok(s) => conn = Some(s),
                Err(e) => {
                    debug!("speed test {} ping reconnect failed: {e:#}", task.id);
                    task.on_tcp_timeout();
                    continue;
                }
            }
        }
        let Some(s) = conn.as_mut() else { continue };
        seq += 1;
        let start = Instant::now();
        let pong = timeout(PROBE_TIMEOUT, async {
            s.write_all(&command(proto::CMD_PING, seq)).await?;
            s.flush().await?;
            let mut reply = [0u8; 9];
            s.read_exact(&mut reply).await?;
            io::Result::Ok(reply)
        })
        .await;
        match pong {
            Ok(Ok(reply)) if reply == command(proto::CMD_PING, seq) => {
                task.on_tcp_rtt(start.elapsed().as_secs_f64() * 1000.0);
            }
            _ => {
                conn = None;
                task.on_tcp_timeout();
            }
        }
    }
}

async fn udp_probe(task: Arc<SpeedTestTask>, outbound: Arc<dyn AnyOutbound>) {
    let target = udp_target();
    let packet = match outbound.connect_packet(&target).await {
        Ok(p) => p,
        Err(e) => {
            debug!("speed test {} UDP unavailable: {e:#}", task.id);
            return;
        }
    };
    let from = TargetAddr::Ip(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)));
    let base = Instant::now();
    let pending: Arc<Mutex<HashMap<u64, Instant>>> = Arc::default();

    let receiver = {
        let task = task.clone();
        let packet = packet.clone();
        let pending = pending.clone();
        async move {
            loop {
                let Ok((_, _, data)) = packet.recv_from().await else {
                    return;
                };
                if data.len() < 8 {
                    continue;
                }
                let seq = u64::from_be_bytes(data[..8].try_into().unwrap());
                let sent = pending
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .remove(&seq);
                if let Some(sent) = sent {
                    task.udp_received();
                    task.on_udp_rtt(sent.elapsed().as_secs_f64() * 1000.0);
                }
            }
        }
    };

    let sender = {
        let task = task.clone();
        let pending = pending.clone();
        let packet = packet.clone();
        async move {
            let mut seq = 0u64;
            let mut tick = interval(UDP_INTERVAL);
            tick.set_missed_tick_behavior(MissedTickBehavior::Skip);
            let mut last_sweep = Instant::now();
            loop {
                tick.tick().await;
                seq += 1;
                let mut buf = BytesMut::with_capacity(UDP_PROBE_LEN);
                buf.put_u64(seq);
                buf.put_u64(base.elapsed().as_micros() as u64);
                buf.resize(UDP_PROBE_LEN, 0);
                pending
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .insert(seq, Instant::now());
                if packet.send_to(buf.freeze(), &from, &target).await.is_ok() {
                    task.udp_sent(1);
                }
                if last_sweep.elapsed() >= Duration::from_secs(1) {
                    last_sweep = Instant::now();
                    let lost = {
                        let mut pending = pending.lock().unwrap_or_else(|e| e.into_inner());
                        let before = pending.len();
                        pending.retain(|_, sent| sent.elapsed() < PROBE_TIMEOUT);
                        (before - pending.len()) as u64
                    };
                    if lost > 0 {
                        task.on_udp_lost(lost);
                    }
                }
            }
        }
    };

    tokio::select! {
        _ = receiver => {}
        _ = sender => {}
    }
    if let Some(closer) = packet.closer() {
        closer.close();
    }
}

async fn sampler(task: Arc<SpeedTestTask>, outbound: Arc<dyn AnyOutbound>) {
    let mut tick = interval(Duration::from_secs(1));
    tick.set_missed_tick_behavior(MissedTickBehavior::Delay);
    tick.tick().await;
    let mut last_bytes = task.bytes();
    let mut last_at = Instant::now();
    let mut last_gen = task.phase_gen();
    let max_duration = Duration::from_secs(task.req.max_duration_secs);
    loop {
        tick.tick().await;
        let bytes = task.bytes();
        let now = Instant::now();
        let secs = now.duration_since(last_at).as_secs_f64().max(0.001);
        let down_bps = ((bytes.0 - last_bytes.0) as f64 * 8.0 / secs) as u64;
        let up_bps = ((bytes.1 - last_bytes.1) as f64 * 8.0 / secs) as u64;
        let phase = task.phase();
        let uplink = outbound.get_uplink_state().await;
        // The server's RTT estimate is the one fed by download data packets;
        // query it only while downloading.
        let downlink = if phase == Phase::Download {
            timeout(DOWNLINK_STATE_TIMEOUT, outbound.get_downlink_state())
                .await
                .ok()
                .flatten()
        } else {
            None
        };
        let quic = uplink.as_ref().map(|s| (s.lost_packets, s.sent_packets));
        task.on_sample(SampleInput {
            down_bps,
            up_bps,
            gen_at_start: last_gen,
            quic,
            data_rtt_ms: data_rtt_ms(phase, uplink.as_ref(), downlink.as_ref()),
            data_path: data_path(phase, uplink.as_ref(), downlink.as_ref()),
        });
        last_bytes = bytes;
        last_at = now;
        last_gen = task.phase_gen();

        if task.started.elapsed() >= max_duration {
            task.stop(Some("max_duration"));
        }
        if let Some(max) = task.req.max_bytes
            && bytes.0 + bytes.1 >= max
        {
            task.stop(Some("max_bytes"));
        }
    }
}

/// RTT of the QUIC connection as seen by the side that sends the phase's
/// data: the server while downloading, the client otherwise. Falls back to
/// the other side's estimate when one is unavailable (hysteria2 has no
/// server-side query).
pub(super) fn data_rtt_ms(
    phase: Phase,
    uplink: Option<&PathState>,
    downlink: Option<&PathState>,
) -> Option<f64> {
    let valid = |s: Option<&PathState>| {
        s.map(|s| s.rtt as f64)
            .filter(|r| r.is_finite() && *r > 0.0)
            .map(|r| (r * 100.0).round() / 100.0)
    };
    match phase {
        Phase::Download => valid(downlink).or_else(|| valid(uplink)),
        _ => valid(uplink).or_else(|| valid(downlink)),
    }
}

/// Loss counters of the side sending the phase's data: (server side, lost,
/// sent). Unlike the RTT there is no fallback: the client's counters during a
/// download count its ACKs, not the data.
pub(super) fn data_path(
    phase: Phase,
    uplink: Option<&PathState>,
    downlink: Option<&PathState>,
) -> Option<(bool, u64, u64)> {
    match phase {
        Phase::Download => downlink.map(|s| (true, s.lost_packets, s.sent_packets)),
        _ => uplink.map(|s| (false, s.lost_packets, s.sent_packets)),
    }
}

// ─── Counting stream ───

/// Counts every byte read and written so throughput is measured at the
/// tunnel's payload level.
struct CountingStream {
    inner: AnyStream,
    down: Arc<AtomicU64>,
    up: Arc<AtomicU64>,
}

impl AsyncRead for CountingStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        let r = Pin::new(&mut self.inner).poll_read(cx, buf);
        let n = buf.filled().len() - before;
        if n > 0 {
            self.down.fetch_add(n as u64, Ordering::Relaxed);
        }
        r
    }
}

impl AsyncWrite for CountingStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let r = Pin::new(&mut self.inner).poll_write(cx, buf);
        if let Poll::Ready(Ok(n)) = r {
            self.up.fetch_add(n as u64, Ordering::Relaxed);
        }
        r
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn path(rtt: f32) -> PathState {
        PathState {
            lost_packets: 0,
            sent_packets: 0,
            mtu: 1200,
            rtt,
        }
    }

    #[test]
    fn data_path_counts_the_sending_side_only() {
        let mut up = path(20.0);
        up.lost_packets = 1;
        up.sent_packets = 100;
        let mut down = path(30.0);
        down.lost_packets = 7;
        down.sent_packets = 900;
        assert_eq!(
            data_path(Phase::Download, Some(&up), Some(&down)),
            Some((true, 7, 900))
        );
        // hysteria2 while downloading: the client's counters are ACKs.
        assert_eq!(data_path(Phase::Download, Some(&up), None), None);
        assert_eq!(
            data_path(Phase::Upload, Some(&up), Some(&down)),
            Some((false, 1, 100))
        );
        assert_eq!(
            data_path(Phase::IdleLatency, Some(&up), None),
            Some((false, 1, 100))
        );
    }

    #[test]
    fn data_rtt_follows_the_sending_side() {
        let up = path(20.0);
        let down = path(35.555);
        assert_eq!(
            data_rtt_ms(Phase::Download, Some(&up), Some(&down)),
            Some(35.56)
        );
        assert_eq!(
            data_rtt_ms(Phase::Upload, Some(&up), Some(&down)),
            Some(20.0)
        );
        // hysteria2: no server-side estimate.
        assert_eq!(data_rtt_ms(Phase::Download, Some(&up), None), Some(20.0));
        // Non-QUIC outbounds report nothing.
        assert_eq!(data_rtt_ms(Phase::Upload, None, None), None);
        assert_eq!(data_path(Phase::Upload, None, None), None);
        // A connection with no RTT sample yet is ignored.
        assert_eq!(data_rtt_ms(Phase::Upload, Some(&path(0.0)), None), None);
    }
}
