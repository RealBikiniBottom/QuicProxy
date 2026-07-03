use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use anyhow::bail;
use async_trait::async_trait;
use tracing::{debug, info, warn};

use crate::api::get_outbound_info;
use crate::cache::Cache;
use crate::config::OutboundConfig;
use crate::proxy::TargetAddr;
use crate::proxy::observe::{Observer, get_observer};
use crate::proxy::outbound::{AnyOutbound, AnyStream};
use crate::utils::time::parse_duration;

use super::{AnyPacket, get_outbound_by_tag};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SelectorType {
    Manual,
    UrlTest,
}

pub struct SelectorOutbound {
    tag: String,
    selector_type: SelectorType,
    #[allow(dead_code)]
    default_outbound: String,
    outbounds: Vec<Arc<dyn AnyOutbound>>,
    outbounds_count: usize,
    outbound_tags: Vec<String>,
    selected_index: AtomicUsize,
    observer: Option<Arc<Observer>>,
    cache: Option<Cache<String>>,
    interval: Duration,
    tolerance: u64,
    dns: Option<String>,
}

impl SelectorOutbound {
    pub fn new(tag: String, cfg: &OutboundConfig) -> anyhow::Result<Arc<SelectorOutbound>> {
        let default_outbound = cfg.default_outbound.clone().unwrap_or_else(|| {
            tracing::error!("selector '{}' requires default_outbound", tag);
            std::process::exit(1);
        });

        let outbound_tags = cfg.outbounds.as_ref().unwrap_or_else(|| {
            tracing::error!("selector '{}' requires outbounds", tag);
            std::process::exit(1);
        });

        let mut cache = None;
        if let Some(c) = cfg.cache.clone() {
            cache = Cache::new_with_tag(&c, tag.clone())
                .map_err(|e| {
                    tracing::error!("selector '{}' failed to new cache: {:?}", tag, e);
                    std::process::exit(1);
                })
                .ok();
        }

        let mut selected_tag = default_outbound.clone();
        if let Some(ref cache) = cache {
            match cache.get("selected") {
                Ok(Some((cached_tag, _))) => {
                    if outbound_tags.iter().any(|tag_item| tag_item == &cached_tag) {
                        info!(
                            "selector [{}] restored cached selection: {}",
                            tag, cached_tag
                        );
                        selected_tag = cached_tag;
                    } else {
                        warn!(
                            "selector [{}] cached selection '{}' not found in current outbounds, using default '{}'",
                            tag, cached_tag, default_outbound
                        );
                    }
                }
                Ok(None) => {}
                Err(e) => {
                    warn!("selector [{}] failed to read cached selection: {}", tag, e);
                }
            }
        }

        let mut selected_index = 0;

        let outbounds_vec: Vec<_> = outbound_tags
            .iter()
            .enumerate()
            .map(|(i, tag_item)| {
                if &selected_tag == tag_item {
                    selected_index = i;
                }
                get_outbound_by_tag(tag_item.as_ref())
            })
            .collect();

        let outbounds_count = outbounds_vec.len();
        if outbounds_count == 0 {
            bail!("has no outbound");
        }

        // Determine selector type based on protocol
        let selector_type = match cfg.protocol_type.as_str() {
            "urltest" => SelectorType::UrlTest,
            _ => SelectorType::Manual,
        };

        let interval = match cfg.interval {
            Some(secs) => Duration::from_secs(secs),
            None => match selector_type {
                SelectorType::Manual => parse_duration("3h"),
                SelectorType::UrlTest => parse_duration("3h"),
            },
        };

        let tolerance = match selector_type {
            SelectorType::Manual => 0,
            SelectorType::UrlTest => cfg.tolerance.unwrap_or(50) * 1000,
        };

        let outbound = Arc::new(Self {
            tag,
            selector_type,
            outbounds_count,
            default_outbound,
            outbounds: outbounds_vec,
            outbound_tags: outbound_tags.clone(),
            selected_index: AtomicUsize::new(selected_index),
            observer: None,
            dns: cfg.dns.clone(),
            interval,
            tolerance,
            cache,
        });

        let clone = outbound.clone();
        tokio::spawn(async move {
            clone.run_test_loop().await;
        });

        Ok(outbound)
    }

    async fn run_test_loop(&self) {
        let mode = match self.selector_type {
            SelectorType::Manual => "selector",
            SelectorType::UrlTest => "urltest",
        };
        info!(
            "{} [{}] started latency test loop with interval {:?}",
            mode, self.tag, self.interval
        );
        // Give other components (DNS, etc.) time to initialize before the first check.
        // init_dns runs after init_outbounds in the bootstrap sequence,
        // and the spawned test loop may execute before DNS is ready.
        tokio::time::sleep(Duration::from_secs(3)).await;
        loop {
            self.check_all().await;
            tokio::time::sleep(self.interval).await;
        }
    }

    async fn check_all(&self) {
        let Some(observer) = self.observer.clone().or_else(get_observer) else {
            debug!(
                "{} [{}] skipped outbound info check: observer not ready",
                self.protocol(),
                self.tag
            );
            return;
        };

        debug!(
            "{} [{}] starting latency check...",
            self.protocol(),
            self.tag
        );

        let mut handles = Vec::with_capacity(self.outbounds.len());

        for (i, handler) in self.outbounds.iter().enumerate() {
            let tag = handler.tag().to_string();
            let dns = self
                .dns
                .as_deref()
                .or_else(|| handler.dns_server_name())
                .map(str::to_string);
            let observer = observer.clone();
            handles.push(tokio::spawn(async move {
                let result = get_outbound_info(&tag, observer, dns.as_deref()).await;
                (i, tag, result)
            }));
        }

        let mut results = Vec::with_capacity(self.outbounds.len());

        for handle in handles {
            if let Ok((i, tag, result)) = handle.await {
                match result {
                    Ok(trace) => {
                        let us = trace.duration_ms.saturating_mul(1000);
                        results.push((i, us));
                        debug!(
                            "{} [{}] outbound [{}] trace ip={} loc={} latency={} ms",
                            self.protocol(),
                            self.tag,
                            tag,
                            trace.ip,
                            trace.loc,
                            trace.duration_ms
                        );
                    }
                    Err(err) => {
                        debug!(
                            "{} [{}] outbound [{}] trace failed: {:#}",
                            self.protocol(),
                            self.tag,
                            tag,
                            err
                        );
                    }
                }
            }
        }

        // UrlTest mode: auto-select best node based on tolerance
        if self.selector_type == SelectorType::UrlTest {
            if results.is_empty() {
                warn!("UrlTest [{}] all outbounds failed latency test", self.tag);
                return;
            }
            self.apply_url_test_selection(&results);
        }
    }

    /// Trigger UrlTest reselection based on cached latency data from the observer.
    /// Called when a child outbound's latency is updated (e.g., via get_trace API).
    pub fn try_url_test_reselect(&self) {
        if self.selector_type != SelectorType::UrlTest {
            return;
        }

        let Some(observer) = self.observer.clone().or_else(get_observer) else {
            debug!(
                "UrlTest [{}] skipped reselect: observer not ready",
                self.tag
            );
            return;
        };

        let mut results = Vec::with_capacity(self.outbounds.len());
        for (i, child) in self.outbounds.iter().enumerate() {
            let tag = child.tag();
            if let Some(trace) = observer.get_outbound_trace(tag) {
                results.push((i, trace.latency_us));
            }
        }

        if results.is_empty() {
            warn!(
                "UrlTest [{}] all outbounds have no latency data, skipping reselect",
                self.tag
            );
            return;
        }

        self.apply_url_test_selection(&results);
    }

    fn apply_url_test_selection(&self, results: &[(usize, u64)]) {
        let min_latency = results.iter().map(|(_, l)| *l).min().unwrap_or(0);

        // Find the first outbound (in list order) that is within tolerance
        let mut best_idx = results[0].0;
        for (idx, latency) in results {
            if *latency <= min_latency + self.tolerance {
                best_idx = *idx;
                break;
            }
        }

        let old_idx = self.selected_index.load(Ordering::Relaxed);
        if old_idx != best_idx {
            info!(
                "UrlTest [{}] switching from {} to {} (min latency: {} us, tolerance: {} us)",
                self.tag,
                self.outbounds[old_idx].tag(),
                self.outbounds[best_idx].tag(),
                min_latency,
                self.tolerance
            );
            self.selected_index.store(best_idx, Ordering::Relaxed);

            if let Some(ref cache) = self.cache {
                if let Err(e) = cache.set("selected", &self.outbound_tags[best_idx]) {
                    warn!("UrlTest [{}] failed to persist selection: {}", self.tag, e);
                }
            }
        } else {
            debug!(
                "UrlTest [{}] keeping {} (min latency: {} us)",
                self.tag,
                self.outbounds[old_idx].tag(),
                min_latency
            );
        }
    }

    pub fn get_selected_tag(&self) -> Option<&str> {
        let idx = self.selected_index.load(Ordering::Relaxed);
        self.outbound_tags.get(idx).map(|t| t.as_ref())
    }

    pub fn get_effective_tag(&self) -> String {
        let idx = self.selected_index.load(Ordering::Relaxed);
        if let Some(child) = self.outbounds.get(idx) {
            if let Some(sel) = child.as_selector() {
                return sel.get_effective_tag();
            }
        }
        self.outbound_tags
            .get(idx)
            .cloned()
            .unwrap_or_else(|| self.tag.clone())
    }

    pub fn get_outbound_tags(&self) -> Vec<String> {
        self.outbound_tags.clone()
    }

    pub fn select_by_tag(&self, tag: &str) -> bool {
        if let Some(idx) = self.outbound_tags.iter().position(|t| t == tag) {
            let old_idx = self.selected_index.load(Ordering::Relaxed);
            if old_idx != idx {
                self.selected_index.store(idx, Ordering::Relaxed);
                info!(
                    "Selector [{}] switched from {} to {}",
                    self.tag, self.outbound_tags[old_idx], tag
                );

                // Persist selection to cache
                if let Some(ref cache) = self.cache {
                    // Use the pre-computed tag to avoid allocation
                    if let Err(e) = cache.set("selected", &tag.to_string()) {
                        warn!("Selector [{}] failed to persist selection: {}", self.tag, e);
                    } else {
                        info!(
                            "Selector [{}] persisted selection to disk: {}",
                            self.tag, tag
                        );
                    }
                }
            } else {
                info!("Selector [{}] already selected: {}", self.tag, tag);
            }
            true
        } else {
            warn!("Selector [{}] outbound '{}' not found", self.tag, tag);
            false
        }
    }

    pub fn select_by_index(&self, index: usize) -> bool {
        if index < self.outbound_tags.len() {
            let old_idx = self.selected_index.load(Ordering::Relaxed);
            if old_idx != index {
                self.selected_index.store(index, Ordering::Relaxed);
                let new_tag = &self.outbound_tags[index];
                info!(
                    "Selector [{}] switched from {} to {}",
                    self.tag, self.outbound_tags[old_idx], new_tag
                );

                // Persist selection to cache
                if let Some(ref cache) = self.cache {
                    if let Err(e) = cache.set("selected", &new_tag.to_string()) {
                        warn!("Selector [{}] failed to persist selection: {}", self.tag, e);
                    } else {
                        info!(
                            "Selector [{}] persisted selection to disk: {}",
                            self.tag, new_tag
                        );
                    }
                }
            } else {
                info!("Selector [{}] already selected index: {}", self.tag, index);
            }
            true
        } else {
            warn!(
                "Selector [{}] index {} out of bounds (max: {})",
                self.tag,
                index,
                self.outbound_tags.len().saturating_sub(1)
            );
            false
        }
    }

    fn update_selected_index(&self, new_idx: usize) {
        let old_idx = self.selected_index.swap(new_idx, Ordering::Relaxed);
        if old_idx != new_idx {
            info!(
                "{} [{}] updated selected_index from [{}] to [{}]",
                self.protocol(),
                self.tag,
                self.outbounds[old_idx].tag(),
                self.outbounds[new_idx].tag()
            );
            if let Some(ref cache) = self.cache {
                if let Err(e) = cache.set("selected", &self.outbound_tags[new_idx]) {
                    warn!(
                        "{} [{}] failed to persist fallback selection: {}",
                        self.protocol(),
                        self.tag,
                        e
                    );
                }
            }
        }
    }
}

#[async_trait]
impl AnyOutbound for SelectorOutbound {
    fn tag(&self) -> &str {
        &self.tag
    }

    fn protocol(&self) -> &str {
        match self.selector_type {
            SelectorType::Manual => "selector",
            SelectorType::UrlTest => "urltest",
        }
    }

    fn as_selector(&self) -> Option<&SelectorOutbound> {
        Some(self)
    }

    fn dns_server_name(&self) -> Option<&str> {
        if self.dns.is_some() {
            return self.dns.as_deref();
        }
        let idx = self.selected_index.load(Ordering::Relaxed) % self.outbounds.len();
        self.outbounds[idx].dns_server_name()
    }

    fn connect_timeout(&self) -> Duration {
        let idx = self.selected_index.load(Ordering::Relaxed) % self.outbounds.len();
        self.outbounds[idx].connect_timeout()
    }

    async fn connect_stream_base(&self) -> anyhow::Result<AnyStream> {
        let idx = self.selected_index.load(Ordering::Relaxed) % self.outbounds.len();
        self.outbounds[idx].connect_stream_base().await
    }

    async fn connect_stream_with(
        &self,
        target: &TargetAddr,
        stream: AnyStream,
    ) -> anyhow::Result<AnyStream> {
        let idx = self.selected_index.load(Ordering::Relaxed) % self.outbounds.len();
        self.outbounds[idx]
            .connect_stream_with(target, stream)
            .await
    }

    async fn connect_stream(&self, target: &TargetAddr) -> anyhow::Result<AnyStream> {
        match self.selector_type {
            SelectorType::Manual => {
                let idx = self.selected_index.load(Ordering::Relaxed) % self.outbounds_count;
                let out = &self.outbounds[idx];
                info!(
                    "Selector [{}] using [{}] to connect_stream",
                    self.tag(),
                    out.tag()
                );
                out.connect_stream(target).await
            }
            SelectorType::UrlTest => {
                let start_idx = self.selected_index.load(Ordering::Relaxed);

                for i in 0..self.outbounds_count {
                    let idx = (start_idx + i) % self.outbounds_count;
                    let handler = &self.outbounds[idx];

                    match handler.connect_stream(target).await {
                        Ok(stream) => {
                            if idx != start_idx {
                                info!(
                                    "urltest [{}] fallback from [{}] to [{}]",
                                    self.tag,
                                    self.outbounds[start_idx].tag(),
                                    handler.tag()
                                );
                                self.update_selected_index(idx);
                            } else {
                                info!(
                                    "Urltest [{}] using [{}] to connect_stream",
                                    self.tag(),
                                    handler.tag()
                                );
                            }
                            return Ok(stream);
                        }
                        Err(e) => {
                            debug!(
                                "urltest [{}] handler [{}] failed: {}, trying next...",
                                self.tag,
                                handler.tag(),
                                e
                            );
                        }
                    }
                }

                bail!("urltest [{}] all outbounds failed", self.tag)
            }
        }
    }

    async fn connect_packet(&self, target: &TargetAddr) -> anyhow::Result<Arc<dyn AnyPacket>> {
        match self.selector_type {
            SelectorType::Manual => {
                let idx = self.selected_index.load(Ordering::Relaxed) % self.outbounds_count;
                self.outbounds[idx].connect_packet(target).await
            }
            SelectorType::UrlTest => {
                let start_idx = self.selected_index.load(Ordering::Relaxed);

                for i in 0..self.outbounds_count {
                    let idx = (start_idx + i) % self.outbounds_count;
                    let handler = &self.outbounds[idx];

                    match handler.connect_packet(target).await {
                        Ok(socket) => {
                            if idx != start_idx {
                                info!(
                                    "Urltest [{}] UDP fallback from [{}] to [{}]",
                                    self.tag,
                                    self.outbounds[start_idx].tag(),
                                    handler.tag()
                                );
                                self.update_selected_index(idx);
                            }
                            return Ok(socket);
                        }
                        Err(e) => {
                            debug!(
                                "Urltest [{}] handler [{}] UDP failed: {}, trying next...",
                                self.tag,
                                handler.tag(),
                                e
                            );
                        }
                    }
                }

                bail!("urltest [{}] all outbounds failed UDP", self.tag);
            }
        }
    }
}
