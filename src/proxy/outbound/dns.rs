use crate::config::OutboundConfig;
use crate::dns::get_dns_by_tag;
use crate::proxy::outbound::{AnyOutbound, AnyPacket, AnyStream, PacketInfo};
use crate::proxy::{SessionCloser, SourceAddr, TargetAddr};
use anyhow::{Context, Result, bail};
use async_trait::async_trait;
use bytes::Bytes;
use simple_dns::{Packet, RCODE};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use tokio::sync::mpsc;
use tracing::{Instrument, debug, error, warn};

pub struct DnsOutbound {
    tag: String,
    dns: String,
    connect_timeout: Duration,
}

impl DnsOutbound {
    pub fn new(tag: String, cfg: &OutboundConfig) -> Result<Arc<dyn AnyOutbound>> {
        let dns = cfg
            .dns
            .clone()
            .context(format!("dns outbound '{}' requires dns", tag))?;

        let connect_timeout = Duration::from_secs(cfg.connect_timeout.unwrap_or(30));

        Ok(Arc::new(Self {
            tag,
            dns,
            connect_timeout,
        }))
    }
}

struct DnsUdpOutbound {
    rx: Mutex<mpsc::Receiver<PacketInfo>>,
    tx: mpsc::Sender<PacketInfo>,
    dns: String,
    closer: Arc<SessionCloser>,
    last_buf: Mutex<Option<(Bytes, SourceAddr, TargetAddr)>>,
}

#[async_trait]
impl AnyPacket for DnsUdpOutbound {
    fn closer(&self) -> Arc<SessionCloser> {
        self.closer.clone()
    }

    async fn send_to(&self, buf: Bytes, from: &SourceAddr, target: &TargetAddr) -> Result<usize> {
        let tx = self.tx.clone();
        let closer = self.closer.clone();
        let target = target.clone();
        let from = from.clone();
        let len = buf.len();
        let dns_server = get_dns_by_tag(&self.dns)?;

        {
            let mut last = self.last_buf.lock().await;
            *last = Some((buf.clone(), from.clone(), target.clone()));
        }

        let current_span = tracing::Span::current();
        tokio::spawn(
            async move {
                match dns_server.hijack_exchange(&buf.to_vec()).await {
                    Ok(response) => {
                        let _ = tx.send((target, from, Bytes::from(response))).await;
                    }
                    Err(e) => {
                        error!("failed to send dns query: {:#}", e);
                        closer.close();
                    }
                }
            }
            .instrument(current_span),
        );

        Ok(len)
    }

    async fn recv_from(&self) -> Result<PacketInfo> {
        let mut rx = self.rx.lock().await;
        let closer = self.closer.clone();
        tokio::select! {
            res = rx.recv() => {
                match res {
                    Some(res) => {
                        self.closer.close();
                        Ok(res)
                    }
                    None => {
                        self.closer.close();
                        let mut last = self.last_buf.lock().await;
                        match last.take() {
                            Some((query, src, dst)) => {
                                match build_dns_error_response(&query) {
                                    Ok(error_resp) => {
                                        warn!("sending Err dns response");
                                        Ok((dst, src, Bytes::from(error_resp)))
                                    },
                                    Err(_) => bail!("Channel closed"),
                                }
                            }
                            None => bail!("Channel closed"),
                        }
                    },

                }
            }
            _ = closer.wait() => {
                bail!("received closer signal");
            }
        }
    }
}

#[async_trait]
impl AnyOutbound for DnsOutbound {
    fn tag(&self) -> &str {
        &self.tag
    }

    fn protocol(&self) -> &str {
        "dns"
    }

    fn dns_server_name(&self) -> Option<&str> {
        Some(self.dns.as_str())
    }

    fn connect_timeout(&self) -> Duration {
        self.connect_timeout
    }

    async fn connect_stream_base(&self) -> Result<AnyStream> {
        bail!("DNS Outbound does not support TCP yet")
    }

    async fn connect_stream_with(
        &self,
        _target: &TargetAddr,
        _stream: AnyStream,
    ) -> Result<AnyStream> {
        bail!("DNS Outbound does not support TCP yet")
    }

    async fn connect_packet(&self, _target: &TargetAddr) -> Result<Arc<dyn AnyPacket>> {
        let (tx, rx) = mpsc::channel(1);
        let closer = Arc::new(SessionCloser::new());

        let inner = Arc::new(DnsUdpOutbound {
            rx: Mutex::new(rx),
            tx,
            dns: self.dns.clone(),
            closer: closer.clone(),
            last_buf: Mutex::new(None),
        });
        Ok(inner)
    }
}

fn build_dns_error_response(query: &[u8]) -> Result<Vec<u8>> {
    let packet =
        Packet::parse(query).map_err(|e| anyhow::anyhow!("Failed to parse DNS query: {e}"))?;
    let mut reply = Packet::new_reply(packet.id());
    for question in &packet.questions {
        reply.questions.push(question.clone());
    }
    *reply.rcode_mut() = RCODE::ServerFailure;
    reply
        .build_bytes_vec()
        .map(|b| b.to_vec())
        .map_err(|e| anyhow::anyhow!("Failed to build DNS error response: {e}"))
}
