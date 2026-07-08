use crate::config::{Config, NetworkType, RouterMode};
use crate::dns::AnyDNS;
use crate::proxy::observe::{ConnectionTracker, get_observer};
use crate::proxy::outbound::pool::POOL_SHOULD_RETRY;
use crate::proxy::outbound::{AnyOutbound, AnyPacket, AnyStream, UdpHandler, get_default_outbound};
use crate::proxy::{SessionCloser, SourceAddr, TargetAddr};
use crate::utils::{copy_bidirectional, format_duration, now};
use anyhow::{Context, bail};
use bytes::Bytes;
use bytesize::ByteSize;
use dashmap::DashMap;
use std::future::Future;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{Notify, RwLock, mpsc};
use tokio::time::sleep;
use tracing::{Instrument, Span, debug, error, field, info, info_span, trace};

pub use observe::{ObservedPacket, ObservedStream};
pub use rule::{Rule, RuleAction};

use super::outbound::SessionMap;

use tokio::sync::OnceCell;

pub static GLOBAL_ROUTER: OnceCell<Arc<Router>> = OnceCell::const_new();

pub fn get_router() -> Arc<Router> {
    GLOBAL_ROUTER
        .get()
        .unwrap_or_else(|| {
            tracing::error!("Router not set");
            std::process::exit(1);
        })
        .clone()
}

pub fn init_router(cfg: &Config) -> anyhow::Result<()> {
    let r = Router::new(cfg)?;

    let _ = GLOBAL_ROUTER.set(Arc::new(r));
    Ok(())
}

pub mod geoip;
pub mod geoip_db;
pub mod observe;
pub mod rule;

pub struct Router {
    mode: Arc<RwLock<RouterMode>>,
    default_outbound: Arc<dyn AnyOutbound>,
    rules: Vec<Rule>,
}

fn sniff_dns_target(
    payload: Option<&[u8]>,
    original_target: &TargetAddr,
) -> (
    Option<String>,
    Option<simple_dns::QTYPE>,
    Option<TargetAddr>,
) {
    let Some(data) = payload else {
        return (None, None, None);
    };

    match simple_dns::Packet::parse(data) {
        Ok(packet) if !packet.questions.is_empty() => {
            let q = &packet.questions[0];
            let qname = q.qname.to_string();
            info!("Sniffed DNS domain: {} type: {:?}", qname, q.qtype);
            (
                Some("dns".to_string()),
                Some(q.qtype),
                Some(TargetAddr::Domain(qname, original_target.port())),
            )
        }
        Ok(_) => (None, None, None),
        Err(e) => {
            debug!("Failed to parse DNS packet during sniffing: {}", e);
            (None, None, None)
        }
    }
}

impl Router {
    pub fn new(cfg: &Config) -> anyhow::Result<Self> {
        let mode = cfg.router.default_mode.clone();
        let mut rules = Vec::new();
        for item in cfg.router.rules.iter() {
            rules.push(Rule::new(&item)?);
        }

        Ok(Self {
            mode: Arc::new(RwLock::new(mode)),
            default_outbound: get_default_outbound(),
            rules,
        })
    }

    pub async fn get_mode(&self) -> RouterMode {
        *self.mode.read().await
    }

    pub async fn set_mode(&self, mode: RouterMode) {
        *self.mode.write().await = mode;
    }

    fn wrap_streams_with_observer(
        &self,
        inbound_stream: AnyStream,
        outbound_stream: AnyStream,
        inbound_tag: &str,
        outbound: &Arc<dyn AnyOutbound>,
        matched_idx: Option<usize>,
        final_target: &TargetAddr,
        target: &TargetAddr,
        is_fakeip: bool,
    ) -> (AnyStream, AnyStream, Option<Arc<SessionCloser>>) {
        let Some(obs) = get_observer() else {
            return (inbound_stream, outbound_stream, None);
        };

        let inbound_tag_str = inbound_tag.to_string();

        let outbound_tag = outbound.tag().to_string();
        let outbound_stats_tag = outbound
            .as_selector()
            .map(|s| s.get_effective_tag())
            .unwrap_or_else(|| outbound.tag().to_string());

        let inbound_stats = obs
            .get_inbound_stats(&inbound_tag_str)
            .map(|n| n.stats.clone())
            .unwrap_or_default();
        let outbound_stats = obs
            .get_outbound_stats(&outbound_stats_tag)
            .map(|n| n.stats.clone())
            .unwrap_or_default();

        let extra_outbound_stats = if outbound_tag != outbound_stats_tag {
            obs.get_outbound_stats(&outbound_tag)
                .map(|n| n.stats.clone())
        } else {
            None
        };

        let tracker = ConnectionTracker::new(
            inbound_tag_str,
            outbound_tag.to_string(),
            matched_idx,
            final_target.clone(),
            target.clone(),
            is_fakeip,
            false,
        );

        let closer = Arc::new(SessionCloser::new());
        let tracker_arc = obs.add_connection(tracker, closer.clone());

        (
            Box::new(ObservedStream::new(
                inbound_stream,
                inbound_stats,
                None,
                tracker_arc.clone(),
                obs.clone(),
                true,
            )),
            Box::new(ObservedStream::new(
                outbound_stream,
                outbound_stats,
                extra_outbound_stats,
                tracker_arc,
                obs.clone(),
                false,
            )),
            Some(closer),
        )
    }

    async fn wait_copy_with_signals<F>(
        copy_fut: F,
        session_closer: Option<Arc<SessionCloser>>,
        stop_notify: Option<Arc<Notify>>,
    ) -> anyhow::Result<(u64, u64)>
    where
        F: Future<Output = anyhow::Result<(u64, u64)>>,
    {
        tokio::pin!(copy_fut);

        match (session_closer, stop_notify) {
            (Some(c), Some(stop)) => {
                tokio::select! {
                    r = &mut copy_fut => r,
                    _ = c.wait() => {
                        info!("Connection closed by API");
                        Ok((0, 0))
                    }
                    _ = stop.notified() => {
                        info!("Connection closed by stop signal");
                        Ok((0, 0))
                    }
                }
            }
            (Some(c), None) => {
                tokio::select! {
                    r = &mut copy_fut => r,
                    _ = c.wait() => {
                        info!("Connection closed by API");
                        Ok((0, 0))
                    }
                }
            }
            (None, Some(stop)) => {
                tokio::select! {
                    r = &mut copy_fut => r,
                    _ = stop.notified() => {
                        info!("Connection closed by stop signal");
                        Ok((0, 0))
                    }
                }
            }
            (None, None) => copy_fut.await,
        }
    }

    pub async fn dispatch_stream(
        &self,
        inbound_stream: AnyStream,
        target: &TargetAddr,
        inbound_tag: &str,
    ) -> anyhow::Result<()> {
        self.dispatch_stream_with_stop(inbound_stream, target, inbound_tag, None)
            .await
    }

    pub async fn dispatch_stream_with_stop(
        &self,
        inbound_stream: AnyStream,
        target: &TargetAddr,
        inbound_tag: &str,
        stop_notify: Option<Arc<Notify>>,
    ) -> anyhow::Result<()> {
        // Select outbound
        let (outbound, final_target, matched_idx, is_fakeip) = self
            .select_out(target, inbound_tag, Some(NetworkType::Tcp), None)
            .await;

        let start_time = now();

        // Connect outbound
        let outbound_stream = match outbound.connect_stream(&final_target).await {
            Ok(s) => s,
            Err(e) => {
                bail!(
                    "Failed to connect: {:?}, cost {}",
                    e,
                    format_duration(start_time.elapsed())
                );
            }
        };

        // Setup observer wrapper and connection close signals
        let (mut inbound_stream, mut outbound_stream, session_closer) = self
            .wrap_streams_with_observer(
                inbound_stream,
                outbound_stream,
                inbound_tag,
                &outbound,
                matched_idx,
                &final_target,
                target,
                is_fakeip,
            );

        info!(
            "build stream cost {}",
            format_duration(start_time.elapsed())
        );

        let copy_fut = async move {
            // 1. 执行第一次转发尝试
            match copy_bidirectional(&mut inbound_stream, &mut outbound_stream).await {
                Ok(counts) => Ok(counts),
                Err(e) => {
                    if outbound.is_pool() {
                        let err_msg = e.to_string();

                        debug!("pool stream failed, fallback to origin stream, {}", err_msg);

                        if err_msg == POOL_SHOULD_RETRY {
                            let mut out = outbound
                                .retry_connect_stream(&final_target)
                                .await
                                .with_context(|| {
                                    format!(
                                        "Failed to connect: {}, cost {}",
                                        final_target,
                                        format_duration(start_time.elapsed())
                                    )
                                })?;

                            return copy_bidirectional(&mut inbound_stream, &mut out)
                                .await
                                .map_err(anyhow::Error::from);
                        }
                    }
                    Err(anyhow::Error::from(e))
                }
            }
        };

        let res = Self::wait_copy_with_signals(copy_fut, session_closer, stop_notify).await;

        match res {
            Ok((n1, n2)) => {
                info!(
                    "Stream closed. Upload: {} Download: {}, cost: {}",
                    ByteSize(n1),
                    ByteSize(n2),
                    format_duration(start_time.elapsed())
                );
            }
            Err(e) => {
                bail!(
                    "Stream error: {}, cost: {}",
                    e,
                    format_duration(start_time.elapsed())
                )
            }
        }

        Ok(())
    }

    pub async fn select_out(
        &self,
        original_target: &TargetAddr,
        inbound_tag: &str,
        network: Option<NetworkType>,
        payload: Option<&[u8]>,
    ) -> (Arc<dyn AnyOutbound>, TargetAddr, Option<usize>, bool) {
        let start_time = now();
        let mode = self.get_mode().await;

        let mut match_result: Option<(
            usize,
            Arc<dyn AnyOutbound>,
            Option<TargetAddr>,
            Option<Arc<dyn AnyDNS>>,
        )> = None;
        let mut target_override: Option<TargetAddr> = None;
        let mut sniffed_protocol: Option<String> = None;
        let mut sniffed_query_type: Option<simple_dns::QTYPE> = None;
        let mut has_sniffed = false;

        for (i, rule) in self.rules.iter().enumerate() {
            if let Some(ref rule_modes) = rule.mode {
                if !rule_modes.is_empty() && !rule_modes.contains(&mode) {
                    continue;
                }
            }

            // Sniffing logic - only triggered if rule requires it and we haven't sniffed yet
            if !has_sniffed && rule.protocol.is_some() {
                let (proto, qtype, override_target) = sniff_dns_target(payload, original_target);
                sniffed_protocol = proto;
                sniffed_query_type = qtype;
                target_override = override_target;
                has_sniffed = true;
            }

            let effective_target = target_override.as_ref().unwrap_or(original_target);
            let effective_proto = sniffed_protocol.as_deref();

            let (matched, resolved_target) = rule
                .matches(
                    effective_target,
                    inbound_tag,
                    network.clone(),
                    effective_proto,
                    sniffed_query_type,
                )
                .await;

            if matched {
                match_result = Some((i, rule.outbound.clone(), resolved_target, rule.dns.clone()));
                break;
            }
        }

        let (final_outbound, final_target, matched_idx, rule_dns) = match match_result {
            Some((index, outbound, resolved_target, rule_dns)) => {
                info!(
                    "matched rule #{} to {} for {}. cost {}",
                    index,
                    original_target.to_string(),
                    outbound.tag(),
                    format_duration(start_time.elapsed())
                );

                let new_target = resolved_target
                    .or(target_override)
                    .unwrap_or(original_target.clone());
                (outbound, new_target, Some(index), rule_dns)
            }
            None => {
                info!(
                    "no rule matched, using default outbound [{}] for [{}]. cost {}",
                    self.default_outbound.tag(),
                    original_target.to_string(),
                    format_duration(start_time.elapsed())
                );
                (
                    self.default_outbound.clone(),
                    target_override.unwrap_or(original_target.clone()),
                    None,
                    None,
                )
            }
        };

        // Select outbound
        if let Some(obs) = get_observer() {
            obs.record_route_time(start_time.elapsed().as_micros() as u64);
        }

        let is_fakeip = if let TargetAddr::Ip(addr) = original_target {
            if let Some(ref dns) = rule_dns {
                dns.is_fakeip(&addr.ip()).await
            } else {
                false
            }
        } else {
            false
        };

        let tag = final_outbound.tag().to_string();
        Span::current().record("d", &final_target.to_string());
        let i = match matched_idx {
            Some(i) => i.to_string(),
            None => "d".to_string(),
        };
        Span::current().record("r", &i);
        Span::current().record("o", &tag);
        (final_outbound, final_target, matched_idx, is_fakeip)
    }

    pub async fn dispatch_packet(
        &self,
        in_packet: Arc<dyn AnyPacket>,
        original_target: &TargetAddr,
        source_addr: &SourceAddr,
        inbound_tag: &str,
        payload: Option<&[u8]>,
        timeout_duration: Duration,
        reset: Option<Arc<Notify>>,
    ) -> anyhow::Result<()> {
        let (out_packet, final_target) = self
            ._dispatch_packet(source_addr, original_target, inbound_tag, payload)
            .await?;
        let out_packet_closer = out_packet.closer();
        let in_packet_closer = in_packet.closer();

        if let Some(packet) = payload {
            trace!(
                "sending {} from {} to {}({})",
                packet.len(),
                source_addr,
                original_target,
                final_target
            );
            out_packet
                .send_to(Bytes::copy_from_slice(packet), source_addr, &final_target)
                .await?;
        }

        // ==========================================
        // Time Touch 核心：记录最后一次活跃时间
        // ==========================================
        // 使用 std::sync::Mutex 即可，因为它只在同步代码块中被极短时间持有，不存在跨 await 阻塞的问题。
        let last_activity = Arc::new(std::sync::Mutex::new(Instant::now()));

        // ==========================================
        // Spawn: Inbound -> Outbound (发往目标服务器)
        // ==========================================
        let t1_in = in_packet.clone();
        let t1_out = out_packet.clone();
        let t1_activity = last_activity.clone();
        let t1_source = source_addr.clone();
        let t1_target = original_target.clone();
        let t1_final_target = final_target.clone();

        let mut t1 = tokio::spawn(
            async move {
                loop {
                    match t1_in.recv_many().await {
                        Ok(packets) => {
                            for (_from, target, buf) in &packets {
                                let mut t = target;
                                if *target == t1_target {
                                    t = &t1_final_target;
                                }
                                trace!(
                                    "sending {} from {} to {}({})",
                                    buf.len(),
                                    t1_source,
                                    t1_target,
                                    t
                                );
                                if let Err(e) = t1_out.send_to(buf.clone(), &t1_source, t).await {
                                    error!("UDP session quit because [outbound err: {:?}]", e);
                                    break;
                                }
                            }
                            *t1_activity.lock().unwrap() = Instant::now();
                        }
                        Err(e) => {
                            info!("UDP session quit because [inbound err: {:?}]", e);
                            break;
                        }
                    }
                }
            }
            .in_current_span(),
        );

        // ==========================================
        // Spawn: Outbound -> Inbound (接收目标服务器返回)
        // ==========================================
        let t2_in = in_packet.clone();
        let t2_out = out_packet.clone();
        let t2_activity = last_activity.clone();
        let t2_source = source_addr.clone();
        let t2_target = original_target.clone();
        let t2_final_target = final_target.clone();

        let mut t2 = tokio::spawn(
            async move {
                loop {
                    match t2_out.recv_many().await {
                        Ok(packets) => {
                            for (from, _target, buf) in &packets {
                                let mut f = from;
                                if *from == t2_final_target {
                                    f = &t2_target;
                                }
                                trace!(
                                    "receiving {} from {}({}) to {}",
                                    buf.len(),
                                    from,
                                    f,
                                    t2_source,
                                );
                                if let Err(e) = t2_in.send_to(buf.clone(), f, &t2_source).await {
                                    error!("UDP session quit because [inbound err: {:#}]", e);
                                    break;
                                }
                            }
                            *t2_activity.lock().unwrap() = Instant::now();
                        }
                        Err(e) => {
                            info!("UDP session quit because [outbound err: {:#}]", e);
                            break;
                        }
                    }
                }
            }
            .in_current_span(),
        );

        // 初始化检查定时器
        let mut check_timer = Box::pin(sleep(timeout_duration));

        // ==========================================
        // 主监控循环
        // ==========================================
        loop {
            tokio::select! {
                // 1. 定期/按需检查 Idle Timeout
                _ = &mut check_timer => {
                    let last = *last_activity.lock().unwrap();
                    let elapsed = last.elapsed();

                    if elapsed >= timeout_duration {
                        // 距离上一次 Time Touch 的时间已经超过超时阈值，真正超时
                        info!("UDP session quit because [idle timeout]");
                        break;
                    } else {
                        // 期间有流量发生，重新将定时器拨到预期的下一次超时时间点
                        check_timer.as_mut().reset((last + timeout_duration).into());
                    }
                },
                // 2. 通道关闭通知
                _ = out_packet_closer.wait() => {
                    info!("UDP session quit because [outbound actively closed]");
                    break;
                },
                _ = in_packet_closer.wait() => {
                    info!("UDP session quit because [inbound actively closed]");
                    break;
                },
                // 3. 重置信号触发
                _ = async {
                    if let Some(n) = &reset {
                        n.notified().await
                    } else {
                        std::future::pending().await // 永远挂起
                    }
                } => {
                    info!("UDP session quit because [reset notified]");
                    break;
                },
                // 4. 子任务退出监控
                _ = &mut t1 => {
                    break;
                },
                _ = &mut t2 => {
                    break;
                }
            }
        }

        // ==========================================
        // 资源清理
        // ==========================================
        t1.abort();
        t2.abort();

        out_packet_closer.close();
        in_packet_closer.close();

        if let Some((upload, download, start_time)) = out_packet.get_udp_stats() {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            let duration = now - start_time;
            info!(
                "UDP session Closed, upload: {}, download: {}, duration: {}s",
                ByteSize(upload),
                ByteSize(download),
                duration
            );
        } else {
            info!("UDP session Closed");
        }

        Ok(())
    }

    pub async fn _dispatch_packet(
        &self,
        source_addr: &SourceAddr,
        target_addr: &TargetAddr,
        inbound_tag: &str,
        payload: Option<&[u8]>,
    ) -> anyhow::Result<(Arc<dyn AnyPacket>, TargetAddr)> {
        // Match rule to find outbound
        let (outbound, final_target, matched_idx, is_fakeip) = self
            .select_out(target_addr, inbound_tag, Some(NetworkType::Udp), payload)
            .await;
        let tracker_tag = outbound.tag().to_string();
        let stats_tag = outbound
            .as_selector()
            .map(|s| s.get_effective_tag())
            .unwrap_or_else(|| outbound.tag().to_string());

        info!("New UDP session: {} -> {}", source_addr, final_target);

        // Connect
        match outbound.connect_packet(&final_target).await {
            Ok(out_packet) => {
                info!(
                    "Connected UDP outbound [{}] for {}",
                    tracker_tag, final_target
                );
                // s is already Arc<TrackedPacket>
                if let Some(obs) = get_observer() {
                    let inbound_tag_str = inbound_tag.to_string();
                    obs.on_inbound_open_udp(&inbound_tag_str);
                    obs.on_outbound_open_udp(&stats_tag);

                    let tracker = ConnectionTracker::new(
                        inbound_tag_str.clone(),
                        tracker_tag.clone(),
                        matched_idx,
                        final_target.clone(),
                        target_addr.clone(),
                        is_fakeip,
                        true,
                    );

                    let tracker_arc = obs.add_connection(tracker, out_packet.closer());

                    let extra_outbound_tag = if tracker_tag != stats_tag {
                        obs.on_outbound_open_udp(&tracker_tag);
                        Some(tracker_tag.clone())
                    } else {
                        None
                    };

                    let wrapped = ObservedPacket {
                        inner: out_packet,
                        observer: obs.clone(),
                        tracker: tracker_arc,
                        outbound_tag: stats_tag,
                        inbound_tag: inbound_tag_str,
                        extra_outbound_tag,
                    };
                    Ok((Arc::new(wrapped), final_target))
                } else {
                    Ok((out_packet, final_target))
                }
            }
            Err(e) => {
                bail!("Failed to connect UDP outbound {}: {:?}", tracker_tag, e)
            }
        }
    }
}

pub async fn start_udp_loop(
    inbound_packet: Arc<dyn AnyPacket>,
    router: Arc<Router>,
    inbound_tag: String,
    timeout_duration: Duration,
    reset: Arc<Notify>,
) {
    let inbound_packet_clone = inbound_packet.clone();

    let sessions: SessionMap = Arc::new(DashMap::new());
    let timeout_duration = timeout_duration.clone();

    loop {
        match inbound_packet.recv_from().await {
            Ok((src, dst, payload)) => {
                let key = (src.clone(), dst.clone());

                if let Some(tx) = sessions.get(&key) {
                    if tx.send(payload).await.is_err() {
                        drop(tx);
                        sessions.remove(&key);
                    }
                    continue;
                }

                let (new_tx, new_rx) = mpsc::channel::<Bytes>(32);
                sessions.insert(key.clone(), new_tx);

                let handler = Arc::new(UdpHandler::new(
                    inbound_packet_clone.clone(),
                    new_rx,
                    src.clone(),
                    dst.clone(),
                ));

                let router_clone = router.clone();
                let inbound_tag_clone = inbound_tag.clone();
                let timeout_duration = timeout_duration;
                let sessions = sessions.clone();
                let reset = reset.clone();

                let span = info_span!(
                    "udp",
                    i = inbound_tag,
                    s = %src,
                    d = field::Empty,
                    r = field::Empty,
                    o = field::Empty
                );

                tokio::spawn(
                    async move {
                        if let Err(err) = router_clone
                            .dispatch_packet(
                                handler,
                                &dst.clone(),
                                &src.clone(),
                                &inbound_tag_clone,
                                Some(payload.as_ref()),
                                timeout_duration,
                                Some(reset),
                            )
                            .await
                        {
                            error!("Session {} handler error: {:?}", src, err);
                        }
                        sessions.remove(&key);
                    }
                    .instrument(span),
                );
            }
            Err(e) => {
                error!("inbound_packet.recv_from error: {:?}", e);
                break;
            }
        }
    }
}
