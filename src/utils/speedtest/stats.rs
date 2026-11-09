//! Metric accumulation for a speed test task or one of its rounds.

use serde::Serialize;

use super::Phase;

#[derive(Debug, Clone, Default, Serialize, PartialEq)]
pub struct RateSummary {
    pub avg_bps: u64,
    pub p50_bps: u64,
    pub p90_bps: u64,
    pub max_bps: u64,
    /// Number of one-second samples behind these figures.
    pub samples: usize,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct Summary {
    pub down: Option<RateSummary>,
    pub up: Option<RateSummary>,
    /// Mean request-ping RTT while no transfer was running.
    pub idle_rtt_ms: Option<f64>,
    /// Loaded latency: the QUIC connection's smoothed RTT polled every 100 ms
    /// during download and upload, after each phase's warm-up, on the side
    /// sending the data (server while downloading, client while uploading);
    /// the mean of the polls. No ping is sent during transfers. Absent for
    /// non-QUIC outbounds, and for a direction whose side cannot report it.
    /// [`Summary::down_loaded_rtt_ms`] and [`Summary::up_loaded_rtt_ms`]
    /// split it by direction.
    pub loaded_rtt_ms: Option<f64>,
    pub down_loaded_rtt_ms: Option<f64>,
    pub up_loaded_rtt_ms: Option<f64>,
    /// Mean absolute difference between consecutive RTTs (UDP echo when
    /// available, idle request pings otherwise).
    pub jitter_ms: Option<f64>,
    /// UDP echo loss; absent when the node never echoed a datagram.
    pub udp_loss_pct: Option<f64>,
    pub udp_sent: u64,
    pub udp_lost: u64,
    /// Protocol-level packet loss reported by QUIC-based outbounds.
    pub quic_loss_pct: Option<f64>,
    pub probe_timeouts: u64,
    pub errors: u64,
    /// Mean over the clean transfer seconds of the per-second power
    /// [`second_power`], in Mbit/s per ms.
    pub down_power: Option<f64>,
    pub up_power: Option<f64>,
    /// How upload bytes were counted: confirmed by the server, or written
    /// locally (a version 1 server).
    pub up_counting: Option<UpCounting>,
}

/// Source of the upload byte count.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum UpCounting {
    /// Bytes the server reported received (protocol version 2).
    Acked,
    /// Bytes written into the tunnel stream (version 1 server).
    Written,
}

/// Power of one second, after Kleinrock: P_t = rate_t / rtt_t in Mbit/s per
/// ms, where rtt_t is that second's loaded latency (mean of its QUIC RTT
/// polls). None without one.
pub(super) fn second_power(rate_bps: u64, rtt_ms: Option<f64>) -> Option<f64> {
    let rtt = rtt_ms.filter(|p| *p > 0.0)?;
    Some(rate_bps as f64 / 1e6 / rtt)
}

/// One clean (post-warm-up) transfer phase of one direction.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub(super) struct PhaseAcc {
    /// Payload bits and the time they took, summed over the 1 s samples.
    pub bits: f64,
    pub secs: f64,
    /// Sum and count of the 100 ms data-RTT polls.
    pub rtt_sum_ms: f64,
    pub rtt_n: u64,
}

impl PhaseAcc {
    pub fn add(&mut self, rate_bps: u64, secs: f64, rtt: Option<(f64, u32)>) {
        self.bits += rate_bps as f64 * secs;
        self.secs += secs;
        if let Some((mean, n)) = rtt {
            self.rtt_sum_ms += mean * n as f64;
            self.rtt_n += n as u64;
        }
    }
}

/// Total bits over total time of `phases`.
fn mean_bps(phases: &[PhaseAcc]) -> Option<u64> {
    let secs: f64 = phases.iter().map(|p| p.secs).sum();
    (secs > 0.0).then(|| (phases.iter().map(|p| p.bits).sum::<f64>() / secs).round() as u64)
}

/// Poll-weighted mean loaded latency of `phases`.
fn mean_data_rtt(phases: &[PhaseAcc]) -> Option<f64> {
    let n: u64 = phases.iter().map(|p| p.rtt_n).sum();
    (n > 0).then(|| round2(phases.iter().map(|p| p.rtt_sum_ms).sum::<f64>() / n as f64))
}

fn mean(values: &[f64]) -> Option<f64> {
    (!values.is_empty()).then(|| values.iter().sum::<f64>() / values.len() as f64)
}

#[derive(Debug, Default)]
struct Jitter {
    last: Option<f64>,
    sum: f64,
    n: u64,
}

impl Jitter {
    fn add(&mut self, rtt: f64) {
        if let Some(last) = self.last {
            self.sum += (rtt - last).abs();
            self.n += 1;
        }
        self.last = Some(rtt);
    }

    fn value(&self) -> Option<f64> {
        (self.n > 0).then(|| round2(self.sum / self.n as f64))
    }
}

#[derive(Debug, Default)]
pub(super) struct Acc {
    pub down: Vec<u64>,
    pub up: Vec<u64>,
    /// Clean transfer phases: bytes over time and data RTT.
    pub down_phases: Vec<PhaseAcc>,
    pub up_phases: Vec<PhaseAcc>,
    /// Per-second power of the clean transfer samples.
    pub down_powers: Vec<f64>,
    pub up_powers: Vec<f64>,
    pub up_counting: Option<UpCounting>,
    /// Phase generation of the last entry of each list.
    down_gen: Option<u64>,
    up_gen: Option<u64>,
    idle_rtt: Vec<f64>,
    tcp_jitter: Jitter,
    udp_jitter: Jitter,
    pub udp_sent: u64,
    pub udp_received: u64,
    pub udp_lost: u64,
    pub probe_timeouts: u64,
    pub errors: u64,
    pub quic_base: Option<(u64, u64)>,
    pub quic_now: Option<(u64, u64)>,
}

impl Acc {
    /// Adds a clean 1 s transfer sample to the phase with generation
    /// `phase_gen`, with its data RTT and power.
    pub fn add_transfer(
        &mut self,
        phase: Phase,
        phase_gen: u64,
        rate_bps: u64,
        secs: f64,
        rtt: Option<(f64, u32)>,
        power: Option<f64>,
    ) {
        let (phases, last, powers) = match phase {
            Phase::Download => (
                &mut self.down_phases,
                &mut self.down_gen,
                &mut self.down_powers,
            ),
            Phase::Upload => (&mut self.up_phases, &mut self.up_gen, &mut self.up_powers),
            _ => return,
        };
        if let Some(p) = power {
            powers.push(p);
        }
        if *last != Some(phase_gen) || phases.is_empty() {
            phases.push(PhaseAcc::default());
            *last = Some(phase_gen);
        }
        phases.last_mut().unwrap().add(rate_bps, secs, rtt);
    }

    /// A request-ping RTT; pings only run outside transfers.
    pub fn add_rtt(&mut self, phase: Phase, rtt: f64) {
        if phase.idle() {
            self.idle_rtt.push(rtt);
        }
        self.tcp_jitter.add(rtt);
    }

    pub fn set_up_counting(&mut self, c: UpCounting) {
        // One written stream makes the whole figure "written".
        if self.up_counting != Some(UpCounting::Written) {
            self.up_counting = Some(c);
        }
    }

    pub fn add_udp_rtt(&mut self, rtt: f64) {
        self.udp_jitter.add(rtt);
    }

    pub fn summary(&self) -> Summary {
        let udp_loss_pct = (self.udp_received > 0).then(|| {
            let total = self.udp_received + self.udp_lost;
            round2(self.udp_lost as f64 * 100.0 / total as f64)
        });
        let quic_loss_pct = match (self.quic_base, self.quic_now) {
            (Some((lost0, sent0)), Some((lost1, sent1))) if sent1 > sent0 => Some(round2(
                lost1.saturating_sub(lost0) as f64 * 100.0 / (sent1 - sent0) as f64,
            )),
            _ => None,
        };
        let rates = |values: &[u64], phases: &[PhaseAcc]| {
            rate_summary(values).map(|mut r| {
                r.avg_bps = mean_bps(phases).unwrap_or(r.avg_bps);
                r
            })
        };
        let all_phases: Vec<PhaseAcc> = self
            .down_phases
            .iter()
            .chain(&self.up_phases)
            .copied()
            .collect();
        Summary {
            down: rates(&self.down, &self.down_phases),
            up: rates(&self.up, &self.up_phases),
            idle_rtt_ms: mean(&self.idle_rtt).map(round2),
            loaded_rtt_ms: mean_data_rtt(&all_phases),
            down_loaded_rtt_ms: mean_data_rtt(&self.down_phases),
            up_loaded_rtt_ms: mean_data_rtt(&self.up_phases),
            jitter_ms: self.udp_jitter.value().or_else(|| self.tcp_jitter.value()),
            udp_loss_pct,
            udp_sent: self.udp_sent,
            udp_lost: self.udp_lost,
            quic_loss_pct,
            probe_timeouts: self.probe_timeouts,
            errors: self.errors,
            down_power: mean(&self.down_powers).map(round4),
            up_power: mean(&self.up_powers).map(round4),
            up_counting: self.up_counting,
        }
    }
}

fn round2(v: f64) -> f64 {
    (v * 100.0).round() / 100.0
}

fn round4(v: f64) -> f64 {
    (v * 10_000.0).round() / 10_000.0
}

fn percentile<T: Copy>(sorted: &[T], pct: usize) -> T {
    sorted[(sorted.len() - 1) * pct / 100]
}

pub(super) fn rate_summary(values: &[u64]) -> Option<RateSummary> {
    if values.is_empty() {
        return None;
    }
    let mut sorted = values.to_vec();
    sorted.sort_unstable();
    let sum: u128 = sorted.iter().map(|&v| v as u128).sum();
    Some(RateSummary {
        avg_bps: (sum / sorted.len() as u128) as u64,
        p50_bps: percentile(&sorted, 50),
        p90_bps: percentile(&sorted, 90),
        max_bps: *sorted.last().unwrap(),
        samples: sorted.len(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rate_percentiles() {
        let s = rate_summary(&[10, 20, 30, 40, 50, 60, 70, 80, 90, 100]).unwrap();
        assert_eq!(s.avg_bps, 55);
        assert_eq!(s.p50_bps, 50);
        assert_eq!(s.p90_bps, 90);
        assert_eq!(s.max_bps, 100);
        assert_eq!(s.samples, 10);
        assert!(rate_summary(&[]).is_none());
    }

    #[test]
    fn rtt_split_by_phase_and_jitter() {
        let mut acc = Acc::default();
        acc.add_rtt(Phase::IdleLatency, 100.0);
        acc.add_rtt(Phase::IdleLatency, 110.0);
        acc.add_rtt(Phase::Waiting, 120.0);
        acc.add_rtt(Phase::Connecting, 999.0);
        let s = acc.summary();
        assert_eq!(s.idle_rtt_ms, Some(110.0));
        // Pings are not the loaded latency.
        assert_eq!(s.loaded_rtt_ms, None);
        // |110-100| + |120-110| + |999-120| over 3
        assert_eq!(s.jitter_ms, Some(round2((10.0 + 10.0 + 879.0) / 3.0)));

        acc.add_udp_rtt(50.0);
        acc.add_udp_rtt(54.0);
        assert_eq!(acc.summary().jitter_ms, Some(4.0));
    }

    #[test]
    fn loss_needs_at_least_one_echo() {
        let mut acc = Acc::default();
        acc.udp_sent = 20;
        acc.udp_lost = 20;
        assert_eq!(acc.summary().udp_loss_pct, None);
        acc.udp_received = 18;
        acc.udp_lost = 2;
        assert_eq!(acc.summary().udp_loss_pct, Some(10.0));
    }

    #[test]
    fn second_power_is_rate_over_ping() {
        // 80 Mbit/s at a 40 ms loaded latency → 2 Mbit/s per ms.
        assert_eq!(second_power(80_000_000, Some(40.0)), Some(2.0));
        assert_eq!(second_power(80_000_000, Some(160.0)), Some(0.5));
        assert_eq!(second_power(80_000_000, None), None);
        assert_eq!(second_power(80_000_000, Some(0.0)), None);
    }

    #[test]
    fn summary_power_rates_and_latency() {
        let mut acc = Acc::default();
        // Download: 100 Mbit/s for 1 s and 200 Mbit/s for 1.5 s; second 2
        // has no RTT poll, so no power.
        acc.add_transfer(
            Phase::Download,
            1,
            100_000_000,
            1.0,
            Some((40.0, 10)),
            Some(2.5),
        );
        acc.add_transfer(Phase::Download, 1, 200_000_000, 1.5, None, None);
        // A second download phase (new generation, e.g. the next round).
        acc.add_transfer(
            Phase::Download,
            3,
            100_000_000,
            1.0,
            Some((100.0, 10)),
            Some(1.0),
        );
        // Upload without a QUIC RTT (TCP node, or hysteria2's server side).
        acc.add_transfer(Phase::Upload, 2, 10_000_000, 1.0, None, None);
        acc.down = vec![100_000_000, 200_000_000, 100_000_000];
        acc.up = vec![10_000_000];
        assert_eq!(acc.down_phases.len(), 2);
        acc.add_rtt(Phase::IdleLatency, 5.0);
        acc.add_rtt(Phase::Waiting, 7.0);

        let s = acc.summary();
        // Bytes over time: (100 + 300 + 100) Mbit / 3.5 s, not the mean of
        // the per-second rates (133.3).
        assert_eq!(
            s.down.as_ref().unwrap().avg_bps,
            (500e6 / 3.5f64).round() as u64
        );
        assert_eq!(s.down.as_ref().unwrap().max_bps, 200_000_000);
        // Mean of the per-second powers that exist.
        assert_eq!(s.down_power, Some(1.75));
        assert_eq!(s.up_power, None);
        // Loaded latency: poll-weighted QUIC RTT, (400 + 1000) / 20.
        assert_eq!(s.down_loaded_rtt_ms, Some(70.0));
        assert_eq!(s.up_loaded_rtt_ms, None);
        assert_eq!(s.loaded_rtt_ms, Some(70.0));
        assert_eq!(s.idle_rtt_ms, Some(6.0));
    }

    #[test]
    fn written_upload_counting_wins() {
        let mut acc = Acc::default();
        assert_eq!(acc.summary().up_counting, None);
        acc.set_up_counting(UpCounting::Acked);
        assert_eq!(acc.summary().up_counting, Some(UpCounting::Acked));
        acc.set_up_counting(UpCounting::Written);
        acc.set_up_counting(UpCounting::Acked);
        assert_eq!(acc.summary().up_counting, Some(UpCounting::Written));
    }

    #[test]
    fn quic_loss_from_deltas() {
        let mut acc = Acc::default();
        acc.quic_base = Some((5, 1000));
        acc.quic_now = Some((15, 3000));
        assert_eq!(acc.summary().quic_loss_pct, Some(0.5));
    }
}
