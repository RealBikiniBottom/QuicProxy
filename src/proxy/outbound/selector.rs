use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

use tokio::task::JoinSet;

use anyhow::{Context, bail};
use async_trait::async_trait;
use tracing::{debug, info, warn};

use crate::api::get_outbound_info;
use crate::cache::Cache;
use crate::config::OutboundConfig;
use crate::proxy::TargetAddr;
use crate::proxy::observe::get_observer;
use crate::proxy::outbound::{AnyOutbound, AnyStream};
use crate::utils::time::parse_duration;

use super::{AnyPacket, get_outbound_by_tag};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SelectorType {
    Manual,
    UrlTest,
}

/// 单轮测速的总超时。超时后取消尚未完成的任务，保证展示结果和选举结果一致。
const SELECTOR_TEST_ROUND_TIMEOUT: Duration = Duration::from_secs(10);

pub struct SelectorOutbound {
    tag: String,
    selector_type: SelectorType,
    #[allow(dead_code)]
    default_outbound: String,
    outbounds: Vec<Arc<dyn AnyOutbound>>,
    outbounds_count: usize,
    outbound_tags: Vec<String>,
    selected_index: AtomicUsize,
    has_completed_test: AtomicBool,
    cache: Option<Cache<String>>,
    interval: Duration,
    tolerance: u64,
    dns: Option<String>,
}

impl SelectorOutbound {
    pub fn new(tag: String, cfg: &OutboundConfig) -> anyhow::Result<Arc<SelectorOutbound>> {
        let default_outbound = cfg
            .default_outbound
            .clone()
            .with_context(|| format!("selector '{tag}' requires default_outbound"))?;

        let outbound_tags = cfg
            .outbounds
            .as_ref()
            .with_context(|| format!("selector '{tag}' requires outbounds"))?;

        let cache = cfg
            .cache
            .as_ref()
            .map(|cache_tag| {
                Cache::new_with_tag(cache_tag, tag.clone())
                    .with_context(|| format!("selector '{tag}' failed to create cache"))
            })
            .transpose()?;

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
                SelectorType::Manual => parse_duration("1h"),
                SelectorType::UrlTest => parse_duration("1h"),
            },
        };

        let tolerance = match selector_type {
            SelectorType::Manual => 0,
            SelectorType::UrlTest => cfg.tolerance.unwrap_or(50),
        };

        let outbound = Arc::new(Self {
            tag,
            selector_type,
            outbounds_count,
            default_outbound,
            outbounds: outbounds_vec,
            outbound_tags: outbound_tags.clone(),
            selected_index: AtomicUsize::new(selected_index),
            has_completed_test: AtomicBool::new(false),
            dns: cfg.dns.clone(),
            interval,
            tolerance,
            cache,
        });

        Ok(outbound)
    }

    pub fn test_interval(&self) -> Duration {
        self.interval
    }

    pub async fn check_all(&self) {
        let Some(observer) = get_observer() else {
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

        let mut tasks = JoinSet::new();
        let mode = self.protocol().to_string();
        let selector_tag = self.tag.clone();

        for (i, handler) in self.outbounds.iter().enumerate() {
            let tag = handler.tag().to_string();
            let dns = self
                .dns
                .as_deref()
                .or_else(|| handler.dns_server_name())
                .map(str::to_string);
            let observer = observer.clone();
            let mode = mode.clone();
            let selector_tag = selector_tag.clone();
            tasks.spawn(async move {
                match get_outbound_info(&tag, observer, dns.as_deref()).await {
                    Ok(trace) => {
                        let latency_ms = trace.duration_ms as i64;
                        debug!(
                            "{} [{}] outbound [{}] trace ip={} loc={} latency={} ms",
                            mode, selector_tag, tag, trace.ip, trace.loc, trace.duration_ms
                        );
                        Some((i, latency_ms))
                    }
                    Err(err) => {
                        debug!(
                            "{} [{}] outbound [{}] trace failed: {:#}",
                            mode, selector_tag, tag, err
                        );
                        None
                    }
                }
            });
        }

        let mut results = Vec::with_capacity(self.outbounds.len());
        let deadline = tokio::time::Instant::now() + SELECTOR_TEST_ROUND_TIMEOUT;
        while !tasks.is_empty() {
            match tokio::time::timeout_at(deadline, tasks.join_next()).await {
                Ok(Some(Ok(Some(info)))) => results.push(info),
                Ok(Some(Ok(None))) => {}
                Ok(Some(Err(err))) => {
                    debug!(
                        "{} [{}] latency test task failed: {}",
                        self.protocol(),
                        self.tag,
                        err
                    );
                }
                Ok(None) => break,
                Err(_) => {
                    warn!(
                        "{} [{}] latency test timed out after {:?}",
                        self.protocol(),
                        self.tag,
                        SELECTOR_TEST_ROUND_TIMEOUT
                    );
                    tasks.abort_all();
                    while tasks.join_next().await.is_some() {}
                    break;
                }
            }
        }

        if results.is_empty() {
            warn!(
                "{} [{}] all outbounds failed latency test",
                self.protocol(),
                self.tag
            );
            return;
        }

        self.reselect_node_by_info(&results);
    }

    fn reselect_node_by_info(&self, results: &[(usize, i64)]) {
        if self.selector_type != SelectorType::UrlTest {
            return;
        }

        let mut sorted_results = results.to_vec();
        sorted_results.sort_by_key(|(_, latency)| *latency);

        let reachable: Vec<_> = sorted_results.iter().filter(|(_, l)| *l > 0).collect();
        if reachable.is_empty() {
            warn!("UrlTest [{}] all outbounds failed latency test", self.tag);
            return;
        }

        let (min_idx, min_latency) = *reachable[0];
        let is_first_successful_test = !self.has_completed_test.swap(true, Ordering::Relaxed);

        let best_idx = if is_first_successful_test {
            min_idx
        } else {
            let current_idx = self.selected_index.load(Ordering::Relaxed);
            let current_latency = reachable
                .iter()
                .find(|(idx, _)| *idx == current_idx)
                .map(|(_, latency)| *latency);
            let tolerance = i64::try_from(self.tolerance).unwrap_or(i64::MAX);
            let tolerance_limit = min_latency.saturating_add(tolerance);

            match current_latency {
                Some(latency) if latency <= tolerance_limit => current_idx,
                _ => min_idx,
            }
        };

        self.update_selected_by_index(best_idx);
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

    /// Returns the complete currently selected outbound path, from this
    /// selector through any nested selectors to the effective leaf outbound.
    pub fn get_active_outbound_tags(&self) -> Vec<String> {
        let mut tags = vec![self.tag.clone()];
        let idx = self.selected_index.load(Ordering::Relaxed);
        if let Some(child) = self.outbounds.get(idx) {
            if let Some(selector) = child.as_selector() {
                tags.extend(selector.get_active_outbound_tags());
            } else {
                tags.push(child.tag().to_string());
            }
        }
        tags
    }

    pub fn get_outbound_tags(&self) -> Vec<String> {
        self.outbound_tags.clone()
    }

    pub fn select_by_tag(&self, tag: &str) -> bool {
        if let Some(idx) = self.outbound_tags.iter().position(|t| t == tag) {
            self.update_selected_by_index(idx);
            true
        } else {
            warn!("Selector [{}] outbound '{}' not found", self.tag, tag);
            false
        }
    }

    fn update_selected_by_index(&self, new_idx: usize) {
        let old_idx = self.selected_index.swap(new_idx, Ordering::Relaxed);
        if old_idx == new_idx {
            return;
        }

        let new_selected_node = self.outbounds[new_idx].clone();
        info!(
            "{} [{}] updated node from [{}] to [{}]",
            self.protocol(),
            self.tag,
            self.outbounds[old_idx].tag(),
            new_selected_node.tag()
        );

        if let Some(observer) = get_observer() {
            if let Some(selected_tag) = self.get_selected_tag() {
                if let (Some(node), Some(trace)) = (
                    observer.get_outbound_stats(selected_tag),
                    observer.get_outbound_trace(selected_tag),
                ) {
                    observer.update_outbound_trace(
                        get_outbound_by_tag(&self.tag),
                        node.stats.get_latency_ms(),
                        trace.ip,
                        trace.loc,
                        trace.uplink_path_stats,
                        trace.downlink_path_stats,
                    );
                }
            }
            observer.kill_connections_by_outbound(&self.tag);
        }

        if let Some(ref cache) = self.cache {
            if let Err(e) = cache.set("selected", &new_selected_node.tag().to_string()) {
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
                                self.update_selected_by_index(idx);
                            }
                            info!(
                                "Urltest [{}] using [{}] to connect_stream",
                                self.tag(),
                                handler.tag()
                            );
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
                                self.update_selected_by_index(idx);
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

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    use anyhow::bail;
    use async_trait::async_trait;

    use crate::proxy::TargetAddr;
    use crate::proxy::outbound::{AnyOutbound, AnyPacket, AnyStream};

    /// 仅用于测试的占位出站，不涉及真实网络行为。
    struct MockOutbound {
        tag: String,
    }

    #[async_trait]
    impl AnyOutbound for MockOutbound {
        fn tag(&self) -> &str {
            &self.tag
        }

        fn protocol(&self) -> &str {
            "mock"
        }

        fn dns_server_name(&self) -> Option<&str> {
            None
        }

        fn connect_timeout(&self) -> Duration {
            Duration::from_secs(5)
        }

        async fn connect_packet(&self, _target: &TargetAddr) -> anyhow::Result<Arc<dyn AnyPacket>> {
            bail!("not implemented")
        }

        async fn connect_stream_base(&self) -> anyhow::Result<AnyStream> {
            bail!("not implemented")
        }

        async fn connect_stream_with(
            &self,
            _target: &TargetAddr,
            _stream: AnyStream,
        ) -> anyhow::Result<AnyStream> {
            bail!("not implemented")
        }
    }

    fn mock_outbound(tag: &str) -> Arc<dyn AnyOutbound> {
        Arc::new(MockOutbound {
            tag: tag.to_string(),
        })
    }

    fn build_selector(
        selector_type: SelectorType,
        tolerance: u64,
        selected_index: usize,
    ) -> SelectorOutbound {
        let tags = vec!["a".to_string(), "b".to_string(), "c".to_string()];
        let outbounds: Vec<Arc<dyn AnyOutbound>> = tags.iter().map(|t| mock_outbound(t)).collect();

        SelectorOutbound {
            tag: "selector-test".to_string(),
            selector_type,
            default_outbound: "a".to_string(),
            outbounds_count: outbounds.len(),
            outbound_tags: tags,
            outbounds,
            selected_index: AtomicUsize::new(selected_index),
            has_completed_test: AtomicBool::new(false),
            cache: None,
            interval: Duration::from_secs(3600),
            tolerance,
            dns: None,
        }
    }

    fn selected_index(selector: &SelectorOutbound) -> usize {
        selector.selected_index.load(Ordering::Relaxed)
    }

    #[test]
    fn manual_selector_does_not_reselect() {
        let selector = build_selector(SelectorType::Manual, 0, 1);
        let results = vec![(0, 10), (1, 20)];

        selector.reselect_node_by_info(&results);

        assert_eq!(selected_index(&selector), 1);
    }

    #[test]
    fn empty_results_do_not_reselect() {
        let selector = build_selector(SelectorType::UrlTest, 50, 0);

        selector.reselect_node_by_info(&[]);

        assert_eq!(selected_index(&selector), 0);
    }

    #[test]
    fn all_unreachable_does_not_reselect() {
        let selector = build_selector(SelectorType::UrlTest, 50, 2);
        let results = vec![(0, -1), (1, -2)];

        selector.reselect_node_by_info(&results);

        assert_eq!(selected_index(&selector), 2);
    }

    #[test]
    fn failed_round_does_not_consume_first_successful_selection() {
        let selector = build_selector(SelectorType::UrlTest, 200, 0);
        selector.reselect_node_by_info(&[(0, -1), (1, -2)]);

        selector.reselect_node_by_info(&[(0, 300), (1, 150)]);

        assert_eq!(selected_index(&selector), 1);
    }

    #[test]
    fn filters_unreachable_nodes() {
        let selector = build_selector(SelectorType::UrlTest, 0, 2);
        let results = vec![(0, -1), (1, 20), (2, 30)];

        selector.reselect_node_by_info(&results);

        assert_eq!(selected_index(&selector), 1);
    }

    #[test]
    fn picks_first_min_latency_node() {
        let selector = build_selector(SelectorType::UrlTest, 0, 0);
        let results = vec![(0, 30), (1, 20), (2, 20)];

        selector.reselect_node_by_info(&results);

        assert_eq!(selected_index(&selector), 1);
    }

    #[test]
    fn first_successful_test_ignores_tolerance_and_picks_strict_min() {
        let selector = build_selector(SelectorType::UrlTest, 200, 0);
        let results = vec![(0, 300), (1, 150)];

        selector.reselect_node_by_info(&results);

        assert_eq!(selected_index(&selector), 1);
    }

    #[test]
    fn later_test_keeps_current_node_within_tolerance() {
        let selector = build_selector(SelectorType::UrlTest, 50, 0);
        selector.reselect_node_by_info(&[(0, 20), (1, 60)]);

        selector.reselect_node_by_info(&[(0, 60), (1, 20)]);

        assert_eq!(selected_index(&selector), 0);
    }

    #[test]
    fn later_test_switches_when_current_node_exceeds_tolerance() {
        let selector = build_selector(SelectorType::UrlTest, 50, 0);
        selector.reselect_node_by_info(&[(0, 20), (1, 60)]);

        selector.reselect_node_by_info(&[(0, 80), (1, 20)]);

        assert_eq!(selected_index(&selector), 1);
    }

    #[test]
    fn active_outbound_tags_include_nested_selectors_and_leaf() {
        let mut urltest = build_selector(SelectorType::UrlTest, 50, 0);
        urltest.tag = "urltest".to_string();

        let mut proxy = build_selector(SelectorType::Manual, 0, 0);
        proxy.tag = "proxy".to_string();
        proxy.outbound_tags[0] = "urltest".to_string();
        proxy.outbounds[0] = Arc::new(urltest);

        assert_eq!(
            proxy.get_active_outbound_tags(),
            vec!["proxy".to_string(), "urltest".to_string(), "a".to_string()]
        );
        assert_eq!(proxy.get_effective_tag(), "a");
    }
}
