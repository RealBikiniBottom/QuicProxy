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
    /// Median TCP ping RTT while no transfer was running.
    pub idle_rtt_ms: Option<f64>,
    /// Median TCP ping RTT during download/upload.
    pub loaded_rtt_ms: Option<f64>,
    /// Mean absolute difference between consecutive RTTs (UDP echo when
    /// available, TCP ping otherwise).
    pub jitter_ms: Option<f64>,
    /// UDP echo loss; absent when the node never echoed a datagram.
    pub udp_loss_pct: Option<f64>,
    pub udp_sent: u64,
    pub udp_lost: u64,
    /// Protocol-level packet loss reported by QUIC-based outbounds.
    pub quic_loss_pct: Option<f64>,
    pub probe_timeouts: u64,
    pub errors: u64,
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
    idle_rtt: Vec<f64>,
    loaded_rtt: Vec<f64>,
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
    pub fn add_rtt(&mut self, phase: Phase, rtt: f64) {
        if phase.loaded() {
            self.loaded_rtt.push(rtt);
        } else if phase.idle() {
            self.idle_rtt.push(rtt);
        }
        self.tcp_jitter.add(rtt);
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
        Summary {
            down: rate_summary(&self.down),
            up: rate_summary(&self.up),
            idle_rtt_ms: median(&self.idle_rtt),
            loaded_rtt_ms: median(&self.loaded_rtt),
            jitter_ms: self.udp_jitter.value().or_else(|| self.tcp_jitter.value()),
            udp_loss_pct,
            udp_sent: self.udp_sent,
            udp_lost: self.udp_lost,
            quic_loss_pct,
            probe_timeouts: self.probe_timeouts,
            errors: self.errors,
        }
    }
}

fn round2(v: f64) -> f64 {
    (v * 100.0).round() / 100.0
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

fn median(values: &[f64]) -> Option<f64> {
    if values.is_empty() {
        return None;
    }
    let mut sorted = values.to_vec();
    sorted.sort_by(|a, b| a.total_cmp(b));
    Some(round2(percentile(&sorted, 50)))
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
        acc.add_rtt(Phase::Download, 200.0);
        acc.add_rtt(Phase::Connecting, 999.0);
        let s = acc.summary();
        assert_eq!(s.idle_rtt_ms, Some(100.0));
        assert_eq!(s.loaded_rtt_ms, Some(200.0));
        // |110-100| + |200-110| + |999-200| over 3
        assert_eq!(s.jitter_ms, Some(round2((10.0 + 90.0 + 799.0) / 3.0)));

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
    fn quic_loss_from_deltas() {
        let mut acc = Acc::default();
        acc.quic_base = Some((5, 1000));
        acc.quic_now = Some((15, 3000));
        assert_eq!(acc.summary().quic_loss_pct, Some(0.5));
    }
}
