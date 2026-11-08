//! Built-in node speed test (client side).
//!
//! A test measures one outbound node against the quicproxy server behind it:
//! download/upload throughput over several parallel streams, idle and loaded
//! latency (TCP ping), and jitter/loss (UDP echo). See [`proto`] for the wire
//! protocol and `proxy::outbound::speedtest` for the server.
//!
//! Test connections are opened straight on the outbound, not through the
//! router, so they never show up in node or domain traffic statistics.

mod engine;
pub mod proto;
mod stats;

use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, LazyLock, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use tokio_util::sync::CancellationToken;

use crate::proxy::outbound::{AnyOutbound, OUTBOUNDS_MAP};
use stats::Acc;
pub use stats::{RateSummary, Summary};

/// Finished tasks stay queryable for this long.
const KEEP_FINISHED: Duration = Duration::from_secs(600);
/// Per-second samples kept per task (10 minutes).
const MAX_SAMPLES: usize = 600;
/// Round summaries kept per task.
const MAX_ROUNDS: usize = 500;

// ─── Request ───

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    /// One round: idle latency, download, upload.
    #[default]
    Once,
    /// Back-to-back download/upload until stopped or a limit is hit.
    Continuous,
    /// One round every `interval_secs`.
    Periodic,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum Direction {
    #[default]
    Both,
    Download,
    Upload,
}

impl Direction {
    fn download(self) -> bool {
        matches!(self, Direction::Both | Direction::Download)
    }
    fn upload(self) -> bool {
        matches!(self, Direction::Both | Direction::Upload)
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct SpeedTestRequest {
    pub tag: String,
    #[serde(default)]
    pub mode: Mode,
    #[serde(default)]
    pub direction: Direction,
    /// Length of each download/upload phase.
    #[serde(default = "default_phase_secs")]
    pub phase_secs: u64,
    /// Round interval in periodic mode, measured from round start.
    #[serde(default = "default_interval_secs")]
    pub interval_secs: u64,
    /// Hard stop for the whole task.
    #[serde(default = "default_max_duration_secs")]
    pub max_duration_secs: u64,
    /// Stop once this many bytes (up + down) were transferred.
    #[serde(default)]
    pub max_bytes: Option<u64>,
    /// Parallel streams per direction.
    #[serde(default = "default_connections")]
    pub connections: usize,
}

fn default_phase_secs() -> u64 {
    10
}
fn default_interval_secs() -> u64 {
    300
}
fn default_max_duration_secs() -> u64 {
    1800
}
fn default_connections() -> usize {
    4
}

impl SpeedTestRequest {
    pub fn new(tag: impl Into<String>) -> Self {
        Self {
            tag: tag.into(),
            mode: Mode::default(),
            direction: Direction::default(),
            phase_secs: default_phase_secs(),
            interval_secs: default_interval_secs(),
            max_duration_secs: default_max_duration_secs(),
            max_bytes: None,
            connections: default_connections(),
        }
    }

    fn normalized(mut self) -> Self {
        self.phase_secs = self.phase_secs.clamp(2, 120);
        self.connections = self.connections.clamp(1, 16);
        self.max_duration_secs = self.max_duration_secs.clamp(5, 7 * 24 * 3600);
        let min_interval = engine::IDLE_LATENCY.as_secs() + self.phase_secs * 2 + 5;
        self.interval_secs = self.interval_secs.clamp(min_interval, 24 * 3600);
        self
    }
}

// ─── State ───

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum State {
    Running,
    Finished,
    Failed,
    Cancelled,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    Connecting,
    IdleLatency,
    Download,
    Upload,
    Waiting,
    Done,
}

impl Phase {
    fn loaded(self) -> bool {
        matches!(self, Phase::Download | Phase::Upload)
    }
    fn idle(self) -> bool {
        matches!(self, Phase::IdleLatency | Phase::Waiting)
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Sample {
    pub seq: u64,
    pub t_ms: u64,
    pub phase: Phase,
    pub down_bps: u64,
    pub up_bps: u64,
    pub rtt_ms: Option<f64>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct Current {
    pub down_bps: u64,
    pub up_bps: u64,
    pub rtt_ms: Option<f64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Round {
    pub index: u32,
    pub t_ms: u64,
    pub summary: Summary,
}

#[derive(Debug, Serialize)]
pub struct Snapshot {
    pub id: String,
    pub tag: String,
    pub effective_tag: String,
    pub protocol: String,
    pub mode: Mode,
    pub direction: Direction,
    pub phase_secs: u64,
    pub state: State,
    pub phase: Phase,
    pub round: u32,
    pub started_at: u64,
    pub elapsed_ms: u64,
    pub bytes_down: u64,
    pub bytes_up: u64,
    pub current: Current,
    pub summary: Summary,
    pub rounds: Vec<Round>,
    pub samples: Vec<Sample>,
    pub next_seq: u64,
    pub stop_reason: Option<String>,
    pub error: Option<String>,
}

struct Inner {
    state: State,
    phase: Phase,
    phase_started: Instant,
    /// Bumped on every phase change so a sample spanning two phases is not
    /// counted toward either.
    phase_gen: u64,
    samples: VecDeque<Sample>,
    next_seq: u64,
    current: Current,
    total: Acc,
    round: Acc,
    round_index: u32,
    round_t_ms: u64,
    rounds: VecDeque<Round>,
    quic_last: Option<(u64, u64)>,
    stop_reason: Option<String>,
    error: Option<String>,
    finished_at: Option<Instant>,
}

pub struct SpeedTestTask {
    pub id: String,
    pub tag: String,
    pub effective_tag: String,
    protocol: String,
    req: SpeedTestRequest,
    started: Instant,
    started_at_ms: u64,
    cancel: CancellationToken,
    down: Arc<AtomicU64>,
    up: Arc<AtomicU64>,
    inner: Mutex<Inner>,
}

impl SpeedTestTask {
    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn elapsed_ms(&self) -> u64 {
        self.started.elapsed().as_millis() as u64
    }

    pub fn state(&self) -> State {
        self.lock().state
    }

    pub fn bytes(&self) -> (u64, u64) {
        (
            self.down.load(Ordering::Relaxed),
            self.up.load(Ordering::Relaxed),
        )
    }

    /// Asks the task to stop. User stops end as `cancelled`; limit stops pass a
    /// reason and end as `finished`.
    pub fn stop(&self, reason: Option<&str>) {
        if let Some(reason) = reason {
            let mut inner = self.lock();
            if inner.stop_reason.is_none() {
                inner.stop_reason = Some(reason.to_string());
            }
        }
        self.cancel.cancel();
    }

    fn set_phase(&self, phase: Phase) {
        let mut inner = self.lock();
        inner.phase = phase;
        inner.phase_started = Instant::now();
        inner.phase_gen += 1;
    }

    fn begin_round(&self) {
        let t_ms = self.elapsed_ms();
        let mut inner = self.lock();
        inner.round_index += 1;
        inner.round_t_ms = t_ms;
        let quic = inner.quic_last;
        inner.round = Acc::default();
        inner.round.quic_base = quic;
    }

    fn end_round(&self) {
        let mut inner = self.lock();
        let round = Round {
            index: inner.round_index,
            t_ms: inner.round_t_ms,
            summary: inner.round.summary(),
        };
        if inner.rounds.len() >= MAX_ROUNDS {
            inner.rounds.pop_front();
        }
        inner.rounds.push_back(round);
    }

    fn record_error(&self) {
        let mut inner = self.lock();
        inner.total.errors += 1;
        inner.round.errors += 1;
    }

    fn on_tcp_rtt(&self, rtt_ms: f64) {
        let mut inner = self.lock();
        inner.current.rtt_ms = Some(rtt_ms);
        let phase = inner.phase;
        inner.total.add_rtt(phase, rtt_ms);
        inner.round.add_rtt(phase, rtt_ms);
    }

    fn on_tcp_timeout(&self) {
        let mut inner = self.lock();
        inner.current.rtt_ms = None;
        inner.total.probe_timeouts += 1;
        inner.round.probe_timeouts += 1;
    }

    fn on_udp_rtt(&self, rtt_ms: f64) {
        let mut inner = self.lock();
        inner.total.add_udp_rtt(rtt_ms);
        inner.round.add_udp_rtt(rtt_ms);
    }

    fn on_udp_lost(&self, lost: u64) {
        let mut inner = self.lock();
        inner.total.udp_lost += lost;
        inner.round.udp_lost += lost;
    }

    fn on_sample(&self, down_bps: u64, up_bps: u64, gen_at_start: u64, quic: Option<(u64, u64)>) {
        let t_ms = self.elapsed_ms();
        let warmup = engine::warmup(self.req.phase_secs);
        let mut inner = self.lock();
        inner.current.down_bps = down_bps;
        inner.current.up_bps = up_bps;
        let clean = inner.phase_gen == gen_at_start && inner.phase_started.elapsed() >= warmup;
        match inner.phase {
            Phase::Download if clean => {
                inner.total.down.push(down_bps);
                inner.round.down.push(down_bps);
            }
            Phase::Upload if clean => {
                inner.total.up.push(up_bps);
                inner.round.up.push(up_bps);
            }
            _ => {}
        }
        if let Some(q) = quic {
            if inner.total.quic_base.is_none() {
                inner.total.quic_base = Some(q);
            }
            if inner.round.quic_base.is_none() {
                inner.round.quic_base = Some(q);
            }
            inner.total.quic_now = Some(q);
            inner.round.quic_now = Some(q);
            inner.quic_last = Some(q);
        }
        let seq = inner.next_seq;
        inner.next_seq += 1;
        let sample = Sample {
            seq,
            t_ms,
            phase: inner.phase,
            down_bps,
            up_bps,
            rtt_ms: inner.current.rtt_ms,
        };
        if inner.samples.len() >= MAX_SAMPLES {
            inner.samples.pop_front();
        }
        inner.samples.push_back(sample);
    }

    fn phase_gen(&self) -> u64 {
        self.lock().phase_gen
    }

    fn udp_sent(&self, n: u64) {
        let mut inner = self.lock();
        inner.total.udp_sent += n;
        inner.round.udp_sent += n;
    }

    fn udp_received(&self) {
        let mut inner = self.lock();
        inner.total.udp_received += 1;
        inner.round.udp_received += 1;
    }

    fn finish(&self, result: anyhow::Result<()>) {
        let mut inner = self.lock();
        if inner.state != State::Running {
            return;
        }
        inner.phase = Phase::Done;
        inner.current = Current::default();
        inner.finished_at = Some(Instant::now());
        inner.state = match result {
            Ok(()) if self.cancel.is_cancelled() && inner.stop_reason.is_none() => State::Cancelled,
            Ok(()) => State::Finished,
            Err(e) => {
                inner.error = Some(format!("{e:#}"));
                State::Failed
            }
        };
    }

    pub fn snapshot(&self, since: Option<u64>, with_samples: bool) -> Snapshot {
        let (bytes_down, bytes_up) = self.bytes();
        let elapsed_ms = self.elapsed_ms();
        let inner = self.lock();
        let samples = if with_samples {
            let since = since.unwrap_or(0);
            inner
                .samples
                .iter()
                .filter(|s| s.seq >= since)
                .cloned()
                .collect()
        } else {
            Vec::new()
        };
        Snapshot {
            id: self.id.clone(),
            tag: self.tag.clone(),
            effective_tag: self.effective_tag.clone(),
            protocol: self.protocol.clone(),
            mode: self.req.mode,
            direction: self.req.direction,
            phase_secs: self.req.phase_secs,
            state: inner.state,
            phase: inner.phase,
            round: inner.round_index,
            started_at: self.started_at_ms,
            elapsed_ms: match inner.finished_at {
                Some(at) => at.duration_since(self.started).as_millis() as u64,
                None => elapsed_ms,
            },
            bytes_down,
            bytes_up,
            current: inner.current.clone(),
            summary: inner.total.summary(),
            rounds: if with_samples {
                inner.rounds.iter().cloned().collect()
            } else {
                Vec::new()
            },
            samples,
            next_seq: inner.next_seq,
            stop_reason: inner.stop_reason.clone(),
            error: inner.error.clone(),
        }
    }

    fn expired(&self) -> bool {
        self.lock()
            .finished_at
            .is_some_and(|at| at.elapsed() > KEEP_FINISHED)
    }
}

// ─── Manager ───

#[derive(Debug)]
pub enum StartError {
    NotFound,
    Busy(String),
    Unsupported(String),
}

impl std::fmt::Display for StartError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StartError::NotFound => write!(f, "outbound not found"),
            StartError::Busy(id) => write!(f, "speed test {id} is already running"),
            StartError::Unsupported(p) => write!(f, "outbound type {p} cannot be speed tested"),
        }
    }
}

impl std::error::Error for StartError {}

static TASKS: LazyLock<Mutex<Vec<Arc<SpeedTestTask>>>> = LazyLock::new(|| Mutex::new(Vec::new()));

fn tasks() -> std::sync::MutexGuard<'static, Vec<Arc<SpeedTestTask>>> {
    let mut tasks = TASKS.lock().unwrap_or_else(|e| e.into_inner());
    tasks.retain(|t| !t.expired());
    tasks
}

fn resolve(tag: &str) -> Result<(String, Arc<dyn AnyOutbound>), StartError> {
    let outbound = OUTBOUNDS_MAP
        .get(tag)
        .map(|e| e.value().clone())
        .ok_or(StartError::NotFound)?;
    let (effective_tag, outbound) = match outbound.as_selector() {
        Some(selector) => {
            let effective = selector.get_effective_tag();
            let node = OUTBOUNDS_MAP
                .get(&effective)
                .map(|e| e.value().clone())
                .ok_or(StartError::NotFound)?;
            (effective, node)
        }
        None => (tag.to_string(), outbound),
    };
    match outbound.protocol() {
        p @ ("direct" | "dns" | "speedtest" | "selector" | "urltest") => {
            Err(StartError::Unsupported(p.to_string()))
        }
        _ => Ok((effective_tag, outbound)),
    }
}

/// Starts a speed test. Only one test runs at a time, since parallel tests
/// would compete for the same bandwidth.
pub fn start(req: SpeedTestRequest) -> Result<Arc<SpeedTestTask>, StartError> {
    let req = req.normalized();
    let (effective_tag, outbound) = resolve(&req.tag)?;

    let mut tasks = tasks();
    if let Some(running) = tasks.iter().find(|t| t.state() == State::Running) {
        return Err(StartError::Busy(running.id.clone()));
    }

    let task = Arc::new(SpeedTestTask {
        id: uuid::Uuid::new_v4().to_string(),
        tag: req.tag.clone(),
        effective_tag,
        protocol: outbound.protocol().to_string(),
        req,
        started: Instant::now(),
        started_at_ms: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0),
        cancel: CancellationToken::new(),
        down: Arc::new(AtomicU64::new(0)),
        up: Arc::new(AtomicU64::new(0)),
        inner: Mutex::new(Inner {
            state: State::Running,
            phase: Phase::Connecting,
            phase_started: Instant::now(),
            phase_gen: 0,
            samples: VecDeque::new(),
            next_seq: 0,
            current: Current::default(),
            total: Acc::default(),
            round: Acc::default(),
            round_index: 0,
            round_t_ms: 0,
            rounds: VecDeque::new(),
            quic_last: None,
            stop_reason: None,
            error: None,
            finished_at: None,
        }),
    });
    tasks.push(task.clone());
    drop(tasks);

    crate::utils::shutdown::spawn(engine::run(task.clone(), outbound));
    Ok(task)
}

pub fn get(id: &str) -> Option<Arc<SpeedTestTask>> {
    tasks().iter().find(|t| t.id == id).cloned()
}

pub fn list() -> Vec<Arc<SpeedTestTask>> {
    tasks().clone()
}

/// Stops a running test; returns false if no task has that id.
pub fn stop(id: &str) -> bool {
    match get(id) {
        Some(task) => {
            task.stop(None);
            true
        }
        None => false,
    }
}

/// Stops every running test (used when the core shuts down).
pub fn stop_all() {
    for task in tasks().iter() {
        task.stop(None);
    }
}
