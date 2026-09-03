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
use std::sync::{Arc, LazyLock, RwLock as StdRwLock};
use std::time::{Duration, Instant};
use tokio::select;
use tokio::sync::{Notify, RwLock, mpsc};
use tokio::time::sleep;
use tracing::{Instrument, Span, debug, error, field, info, info_span, trace};

pub use observe::{ObservedPacket, ObservedStream};
pub use rule::{Rule, RuleAction};

use super::outbound::SessionMap;

const UDP_SESSION_QUEUE_CAPACITY: usize = 16;

static GLOBAL_ROUTER: LazyLock<StdRwLock<Option<Arc<Router>>>> =
    LazyLock::new(|| StdRwLock::new(None));

pub fn get_router() -> anyhow::Result<Arc<Router>> {
    GLOBAL_ROUTER
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .as_ref()
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("Router not set"))
}

pub fn init_router(cfg: &Config) -> anyhow::Result<()> {
    let r = Router::new(cfg)?;

    *GLOBAL_ROUTER
        .write()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(Arc::new(r));
    Ok(())
}

/// Release the router and everything it owns, including DNS and outbound handles.
/// This must run before the shared cache databases are closed.
pub fn shutdown_router() {
    GLOBAL_ROUTER
        .write()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .take();
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

async fn forward_udp_inbound_once(
    in_packet: &Arc<dyn AnyPacket>,
    out_packet: &Arc<dyn AnyPacket>,
    source_addr: &SourceAddr,
    original_target: &TargetAddr,
    final_target: &TargetAddr,
    mut packets: Vec<super::outbound::PacketInfo>,
) -> anyhow::Result<Vec<super::outbound::PacketInfo>> {
    in_packet
        .recv_many(&mut packets)
        .await
        .context("receive inbound UDP packets")?;

    for (_from, target, buf) in packets.drain(..) {
        let target = if target == *original_target {
            final_target
        } else {
            &target
        };
        trace!(
            "sending {} from {} to {}({})",
            buf.len(),
            source_addr,
            original_target,
            target
        );
        out_packet
            .send_to(buf, source_addr, target)
            .await
            .context("send outbound UDP packet")?;
    }

    Ok(packets)
}

async fn forward_udp_outbound_once(
    in_packet: &Arc<dyn AnyPacket>,
    out_packet: &Arc<dyn AnyPacket>,
    source_addr: &SourceAddr,
    original_target: &TargetAddr,
    final_target: &TargetAddr,
    mut packets: Vec<super::outbound::PacketInfo>,
) -> anyhow::Result<Vec<super::outbound::PacketInfo>> {
    out_packet
        .recv_many(&mut packets)
        .await
        .context("receive outbound UDP packets")?;

    for (from, _target, buf) in packets.drain(..) {
        let from = if from == *final_target {
            original_target
        } else {
            &from
        };
        trace!("receiving {} from {} to {}", buf.len(), from, source_addr,);
        in_packet
            .send_to(buf, from, source_addr)
            .await
            .context("send inbound UDP packet")?;
    }

    Ok(packets)
}

/// Delivers a packet to an existing UDP session. If the session receiver has
/// already gone away, the payload is returned so the caller can reopen the
/// session without dropping its first packet.
async fn send_to_existing_udp_session(
    sessions: &SessionMap,
    key: &super::outbound::SessionKey,
    tx: mpsc::Sender<Bytes>,
    payload: Bytes,
) -> Option<Bytes> {
    match tx.send(payload).await {
        Ok(()) => None,
        Err(error) => {
            sessions.remove_if(key, |_, active_tx| {
                active_tx.same_channel(&tx) && active_tx.is_closed()
            });
            Some(error.0)
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
            default_outbound: get_default_outbound()?,
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

        let inbound_tag_str: Arc<str> = Arc::from(inbound_tag);

        let outbound_tags = match outbound.as_selector() {
            Some(selector) => selector.get_active_outbound_tags(),
            None => vec![outbound.tag().to_string()],
        };
        let outbound_tag: Arc<str> = Arc::from(outbound.tag());
        let outbound_stats_tag: Arc<str> = outbound_tags
            .last()
            .map(|tag| Arc::from(tag.as_str()))
            .unwrap_or_else(|| outbound_tag.clone());

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
            outbound_tags,
            matched_idx,
            final_target.clone(),
            target.clone(),
            is_fakeip,
            false,
        );

        let closer = Arc::new(SessionCloser::new());
        let tracker_arc = obs.add_connection(tracker, Some(closer.clone()));

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
                select! {
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
                select! {
                    r = &mut copy_fut => r,
                    _ = c.wait() => {
                        info!("Connection closed by API");
                        Ok((0, 0))
                    }
                }
            }
            (None, Some(stop)) => {
                select! {
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
        payload: Option<Bytes>,
        timeout_duration: Duration,
        reset: Option<Arc<Notify>>,
    ) -> anyhow::Result<()> {
        let (out_packet, final_target) = self
            ._dispatch_packet(
                source_addr,
                original_target,
                inbound_tag,
                payload.as_deref(),
            )
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
                .send_to(packet, source_addr, &final_target)
                .await?;
        }

        let mut last_activity = Instant::now();
        let inbound_packets = Vec::with_capacity(UDP_SESSION_QUEUE_CAPACITY);
        let outbound_packets = Vec::with_capacity(10);
        let check_timer = sleep(timeout_duration);
        let inbound_forward = forward_udp_inbound_once(
            &in_packet,
            &out_packet,
            source_addr,
            original_target,
            &final_target,
            inbound_packets,
        );
        let outbound_forward = forward_udp_outbound_once(
            &in_packet,
            &out_packet,
            source_addr,
            original_target,
            &final_target,
            outbound_packets,
        );
        let out_packet_closed = async move {
            if let Some(closer) = out_packet_closer {
                closer.wait().await;
            } else {
                std::future::pending::<()>().await;
            }
        };
        let in_packet_closed = async move {
            if let Some(closer) = in_packet_closer {
                closer.wait().await;
            } else {
                std::future::pending::<()>().await;
            }
        };
        let reset_notified = async {
            if let Some(reset) = reset {
                reset.notified().await;
            } else {
                std::future::pending::<()>().await;
            }
        };
        tokio::pin!(
            check_timer,
            inbound_forward,
            outbound_forward,
            out_packet_closed,
            in_packet_closed,
            reset_notified
        );

        loop {
            select! {
                result = &mut inbound_forward => {
                    match result {
                        Ok(packets) => {
                            last_activity = Instant::now();
                            inbound_forward.set(forward_udp_inbound_once(
                                &in_packet,
                                &out_packet,
                                source_addr,
                                original_target,
                                &final_target,
                                packets,
                            ));
                        }
                        Err(e) => {
                            info!("UDP session quit because [inbound forwarding err: {:#}]", e);
                            break;
                        }
                    }
                },
                result = &mut outbound_forward => {
                    match result {
                        Ok(packets) => {
                            last_activity = Instant::now();
                            outbound_forward.set(forward_udp_outbound_once(
                                &in_packet,
                                &out_packet,
                                source_addr,
                                original_target,
                                &final_target,
                                packets,
                            ));
                        }
                        Err(e) => {
                            info!("UDP session quit because [outbound forwarding err: {:#}]", e);
                            break;
                        }
                    }
                },
                _ = &mut check_timer => {
                    if last_activity.elapsed() >= timeout_duration {
                        info!("UDP session quit because [idle timeout]");
                        break;
                    } else {
                        check_timer
                            .as_mut()
                            .reset((last_activity + timeout_duration).into());
                    }
                },
                _ = &mut out_packet_closed => {
                    info!("UDP session quit because [outbound actively closed]");
                    break;
                },
                _ = &mut in_packet_closed => {
                    info!("UDP session quit because [inbound actively closed]");
                    break;
                },
                _ = &mut reset_notified => {
                    info!("UDP session quit because [reset notified]");
                    break;
                },
            }
        }

        if let Some(closer) = out_packet.closer() {
            closer.close();
        }
        if let Some(closer) = in_packet.closer() {
            closer.close();
        }

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
        let tracker_tag: Arc<str> = Arc::from(outbound.tag());

        info!("New UDP session: {} -> {}", source_addr, final_target);

        // Connect
        match outbound.connect_packet(&final_target).await {
            Ok(out_packet) => {
                info!(
                    "Connected UDP outbound [{}] for {}",
                    tracker_tag, final_target
                );
                // urltest may switch to a fallback while connecting, so capture
                // the effective leaf only after the connection succeeds.
                let outbound_tags = match outbound.as_selector() {
                    Some(selector) => selector.get_active_outbound_tags(),
                    None => vec![outbound.tag().to_string()],
                };
                let stats_tag: Arc<str> = outbound_tags
                    .last()
                    .map(|tag| Arc::from(tag.as_str()))
                    .unwrap_or_else(|| tracker_tag.clone());
                // s is already Arc<TrackedPacket>
                if let Some(obs) = get_observer() {
                    let inbound_tag_str: Arc<str> = Arc::from(inbound_tag);
                    obs.on_inbound_open_udp(&inbound_tag_str);
                    obs.on_outbound_open_udp(&stats_tag);

                    let tracker = ConnectionTracker::new(
                        inbound_tag_str,
                        outbound_tags,
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
    loop {
        match inbound_packet.recv_from().await {
            Ok((src, dst, mut payload)) => {
                let key = (src, dst);

                let existing_tx = sessions.get(&key).map(|entry| entry.value().clone());
                if let Some(tx) = existing_tx {
                    match send_to_existing_udp_session(&sessions, &key, tx, payload).await {
                        Some(recovered_payload) => payload = recovered_payload,
                        None => continue,
                    }
                }

                let session_key = Arc::new(key);
                let (new_tx, new_rx) = mpsc::channel::<Bytes>(UDP_SESSION_QUEUE_CAPACITY);
                sessions.insert(session_key.clone(), new_tx);

                let handler = Arc::new(UdpHandler::new(
                    inbound_packet_clone.clone(),
                    new_rx,
                    session_key.clone(),
                ));

                let router_clone = router.clone();
                let inbound_tag_clone = inbound_tag.clone();
                let sessions = sessions.clone();
                let reset = reset.clone();

                let span = info_span!(
                    "udp",
                    i = inbound_tag,
                    s = %session_key.0,
                    d = field::Empty,
                    r = field::Empty,
                    o = field::Empty
                );

                tokio::spawn(
                    async move {
                        if let Err(err) = router_clone
                            .dispatch_packet(
                                handler,
                                &session_key.1,
                                &session_key.0,
                                &inbound_tag_clone,
                                Some(payload),
                                timeout_duration,
                                Some(reset),
                            )
                            .await
                        {
                            error!("Session {} handler error: {:?}", session_key.0, err);
                        }
                        sessions
                            .remove_if(session_key.as_ref(), |_, active_tx| active_tx.is_closed());
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

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn closed_udp_session_returns_first_payload_for_reopen() {
        let sessions: SessionMap = Arc::new(DashMap::new());
        let key = Arc::new((
            TargetAddr::Domain("client.example".to_string(), 12345),
            TargetAddr::Domain("target.example".to_string(), 443),
        ));
        let (tx, rx) = mpsc::channel(1);
        sessions.insert(key.clone(), tx.clone());
        drop(rx);
        let payload = Bytes::from_static(b"first packet");

        let recovered =
            send_to_existing_udp_session(&sessions, key.as_ref(), tx, payload.clone()).await;

        assert_eq!(recovered, Some(payload));
        assert!(!sessions.contains_key(key.as_ref()));
    }
}
