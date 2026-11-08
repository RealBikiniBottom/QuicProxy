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
    /// Mean rate over peak rate of the direction's samples (ρ in [0, 1]).
    pub down_utilization: Option<f64>,
    pub up_utilization: Option<f64>,
    /// Mean RTT of the QUIC connection carrying the transfer (ms); absent for
    /// non-QUIC outbounds.
    pub down_data_rtt_ms: Option<f64>,
    pub up_data_rtt_ms: Option<f64>,
    /// Normalised Kleinrock power ρ / (data RTT / 50 ms); see [`power`].
    pub down_power: Option<f64>,
    pub up_power: Option<f64>,
}

/// Delay that normalises power.
pub const POWER_REFERENCE_RTT_MS: f64 = 50.0;

/// Power figures of one direction.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub(super) struct Power {
    pub utilization: Option<f64>,
    pub data_rtt_ms: Option<f64>,
    pub power: Option<f64>,
}

/// Normalised Kleinrock power P = ρ / (D / 50 ms) over a phase's samples.
///
/// ρ = mean rate / peak rate: the test saturates the link, so its peak rate
/// stands in for the capacity. D is the arithmetic mean of the data RTTs
/// (the QUIC connection's RTT estimate) sampled alongside the rates.
pub(super) fn power(rates: &[u64], data_rtts: &[f64]) -> Power {
    let peak = rates.iter().copied().max().unwrap_or(0);
    let utilization = (peak > 0).then(|| {
        let mean = rates.iter().map(|&r| r as f64).sum::<f64>() / rates.len() as f64;
        (mean / peak as f64).clamp(0.0, 1.0)
    });
    let data_rtt_ms = (!data_rtts.is_empty())
        .then(|| data_rtts.iter().sum::<f64>() / data_rtts.len() as f64)
        .filter(|d| *d > 0.0);
    let power = match (utilization, data_rtt_ms) {
        (Some(rho), Some(d)) => Some(round4(rho / (d / POWER_REFERENCE_RTT_MS))),
        _ => None,
    };
    Power {
        utilization: utilization.map(round4),
        data_rtt_ms: data_rtt_ms.map(round2),
        power,
    }
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
    /// Data RTTs of the clean download/upload samples.
    pub down_data_rtt: Vec<f64>,
    pub up_data_rtt: Vec<f64>,
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
        let down_power = power(&self.down, &self.down_data_rtt);
        let up_power = power(&self.up, &self.up_data_rtt);
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
            down_utilization: down_power.utilization,
            up_utilization: up_power.utilization,
            down_data_rtt_ms: down_power.data_rtt_ms,
            up_data_rtt_ms: up_power.data_rtt_ms,
            down_power: down_power.power,
            up_power: up_power.power,
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
    fn power_is_utilization_over_normalised_data_rtt() {
        // mean 75 / peak 100 → ρ = 0.75; D = 60 ms → P = 0.75 / 1.2 = 0.625
        let p = power(&[50, 100, 75, 75], &[40.0, 80.0, 60.0]);
        assert_eq!(p.utilization, Some(0.75));
        assert_eq!(p.data_rtt_ms, Some(60.0));
        assert_eq!(p.power, Some(0.625));

        // No data RTT (non-QUIC outbound): utilization only.
        let p = power(&[50, 100], &[]);
        assert_eq!(p.utilization, Some(0.75));
        assert_eq!(p.data_rtt_ms, None);
        assert_eq!(p.power, None);

        assert_eq!(
            power(&[], &[10.0]),
            Power {
                data_rtt_ms: Some(10.0),
                ..Power::default()
            }
        );
        assert_eq!(power(&[0, 0], &[10.0]).power, None);
    }

    #[test]
    fn summary_reports_power_per_direction() {
        let mut acc = Acc::default();
        acc.down = vec![100, 100];
        acc.down_data_rtt = vec![25.0, 25.0];
        acc.up = vec![10];
        let s = acc.summary();
        assert_eq!(s.down_utilization, Some(1.0));
        assert_eq!(s.down_data_rtt_ms, Some(25.0));
        assert_eq!(s.down_power, Some(2.0));
        assert_eq!(s.up_utilization, Some(1.0));
        assert_eq!(s.up_power, None);
    }

    #[test]
    fn quic_loss_from_deltas() {
        let mut acc = Acc::default();
        acc.quic_base = Some((5, 1000));
        acc.quic_now = Some((15, 3000));
        assert_eq!(acc.summary().quic_loss_pct, Some(0.5));
    }
}
