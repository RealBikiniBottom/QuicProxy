//! TCP connections to targets that resolve to several addresses: the addresses are tried
//! in turn, each started `attempt_delay` after the previous one (RFC 8305), and the first
//! that connects wins.

use std::future::Future;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::LazyLock;
use std::time::{Duration, Instant};

use anyhow::Result;
use dashmap::DashMap;
use futures::stream::{FuturesUnordered, StreamExt};
use rand::seq::SliceRandom;
use tokio::net::TcpStream;
use tracing::debug;

use super::select_outbound_interface;
use crate::config::OutboundConfig;
use crate::dns::{dns_server_for, resolve_target_all};
use crate::proxy::TargetAddr;
use crate::utils::error::Context;
use crate::utils::new_io_timeout_error;
use crate::utils::socket::socket_helpers::new_tcp_stream;

/// How long an address that failed to connect is tried after the others.
const FAILED_ADDR_TTL: Duration = Duration::from_secs(60);
const FAILED_ADDR_LIMIT: usize = 1024;

static FAILED_ADDRS: LazyLock<DashMap<IpAddr, Instant>> = LazyLock::new(DashMap::new);

/// How an outbound connects when a target has several addresses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DialOptions {
    /// Wait before starting the next attempt; zero starts them all at once.
    pub attempt_delay: Duration,
    /// Try IPv6 addresses before IPv4 ones.
    pub prefer_ipv6: bool,
}

impl Default for DialOptions {
    fn default() -> Self {
        Self {
            attempt_delay: Duration::from_millis(250),
            prefer_ipv6: false,
        }
    }
}

impl DialOptions {
    pub fn from_config(cfg: &OutboundConfig) -> Self {
        Self {
            attempt_delay: cfg.attempt_delay(),
            prefer_ipv6: cfg.prefer_ipv6.unwrap_or(false),
        }
    }
}

fn recently_failed(ip: &IpAddr) -> bool {
    FAILED_ADDRS
        .get(ip)
        .is_some_and(|failed_at| failed_at.elapsed() < FAILED_ADDR_TTL)
}

fn mark_failed(ip: IpAddr) {
    if FAILED_ADDRS.len() >= FAILED_ADDR_LIMIT {
        FAILED_ADDRS.retain(|_, failed_at| failed_at.elapsed() < FAILED_ADDR_TTL);
        if FAILED_ADDRS.len() >= FAILED_ADDR_LIMIT {
            FAILED_ADDRS.clear();
        }
    }
    FAILED_ADDRS.insert(ip, Instant::now());
}

fn mark_connected(ip: &IpAddr) {
    FAILED_ADDRS.remove(ip);
}

/// Orders addresses for connecting: shuffled within each family to spread load,
/// interleaved starting with the preferred family (RFC 8305 section 4), and with
/// addresses that recently failed moved to the back.
pub fn order_addrs(addrs: Vec<SocketAddr>, prefer_ipv6: bool) -> Vec<SocketAddr> {
    let mut rng = rand::rng();
    let (mut v6, mut v4): (Vec<_>, Vec<_>) = addrs.into_iter().partition(SocketAddr::is_ipv6);
    v6.shuffle(&mut rng);
    v4.shuffle(&mut rng);

    let (first, second) = if prefer_ipv6 { (v6, v4) } else { (v4, v6) };
    let mut ordered = Vec::with_capacity(first.len() + second.len());
    let (mut first, mut second) = (first.into_iter(), second.into_iter());
    loop {
        match (first.next(), second.next()) {
            (None, None) => break,
            (a, b) => ordered.extend(a.into_iter().chain(b)),
        }
    }

    // A stable sort keeps the interleaving within the healthy and the failed addresses.
    ordered.sort_by_key(|addr| recently_failed(&addr.ip()));
    ordered
}

/// Connects to the first of `addrs` that answers. Each attempt starts `attempt_delay`
/// after the previous one, or right away when the previous one fails; attempts still
/// running when one succeeds are dropped.
pub async fn connect_tcp_any<F, Fut>(
    addrs: &[SocketAddr],
    attempt_delay: Duration,
    connect: F,
) -> io::Result<TcpStream>
where
    F: Fn(SocketAddr) -> Fut,
    Fut: Future<Output = io::Result<TcpStream>>,
{
    let mut pending = addrs.iter().copied();
    let Some(first) = pending.next() else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "no address to connect to",
        ));
    };

    let attempt = |addr: SocketAddr| {
        let connecting = connect(addr);
        async move { (addr, connecting.await) }
    };
    let mut running = FuturesUnordered::new();
    running.push(attempt(first));
    let mut errors: Vec<(SocketAddr, io::Error)> = Vec::new();

    loop {
        let has_pending = pending.len() > 0;
        tokio::select! {
            Some((addr, result)) = running.next() => match result {
                Ok(stream) => {
                    mark_connected(&addr.ip());
                    return Ok(stream);
                }
                Err(e) => {
                    debug!("tcp connect to {addr} failed: {e}");
                    mark_failed(addr.ip());
                    errors.push((addr, e));
                    if let Some(next) = pending.next() {
                        running.push(attempt(next));
                    } else if running.is_empty() {
                        return Err(combine_errors(errors));
                    }
                }
            },
            _ = tokio::time::sleep(attempt_delay), if has_pending => {
                if let Some(next) = pending.next() {
                    running.push(attempt(next));
                }
            }
        }
    }
}

/// A single failure is returned as is, so its kind survives; several are listed together.
fn combine_errors(mut errors: Vec<(SocketAddr, io::Error)>) -> io::Error {
    if errors.len() == 1 {
        return errors.pop().unwrap().1;
    }
    let message = errors
        .iter()
        .map(|(addr, e)| format!("{addr}: {e}"))
        .collect::<Vec<_>>()
        .join("; ");
    io::Error::other(format!("all addresses failed: {message}"))
}

/// Resolves `target` to all its addresses and connects to the first that answers, within
/// `connect_timeout` overall. When none does, the cached DNS answer for the domain is
/// dropped so the next connection asks upstream again.
pub async fn connect_tcp_target(
    target: &TargetAddr,
    dns_server_tag: Option<&str>,
    bind_interface: Option<&str>,
    connect_timeout: Duration,
    options: DialOptions,
) -> Result<TcpStream> {
    let addrs = order_addrs(
        resolve_target_all(target, dns_server_tag).await?,
        options.prefer_ipv6,
    );

    let connect = |addr: SocketAddr| {
        new_tcp_stream(addr, select_outbound_interface(bind_interface, Some(addr)), None)
    };
    let result = tokio::time::timeout(
        connect_timeout,
        connect_tcp_any(&addrs, options.attempt_delay, connect),
    )
    .await
    .unwrap_or_else(|_| Err(new_io_timeout_error("connect timeout")));

    if result.is_err()
        && let TargetAddr::Domain(domain, _) = target
        && let Ok(dns) = dns_server_for(dns_server_tag)
    {
        dns.invalidate(domain);
    }
    result.context("TCP connect failed")
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    async fn listening() -> (TcpListener, SocketAddr) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        (listener, addr)
    }

    async fn closed() -> SocketAddr {
        listening().await.1
    }

    #[tokio::test]
    async fn refused_address_moves_on_without_waiting() {
        let (_listener, open) = listening().await;
        let refused = closed().await;

        let started = Instant::now();
        let stream = connect_tcp_any(&[refused, open], Duration::from_secs(5), |addr| {
            TcpStream::connect(addr)
        })
        .await
        .unwrap();

        assert_eq!(stream.peer_addr().unwrap(), open);
        assert!(started.elapsed() < Duration::from_secs(1));
    }

    #[tokio::test]
    async fn silent_address_is_overtaken_after_attempt_delay() {
        let (_listener, open) = listening().await;
        let silent: SocketAddr = "192.0.2.1:443".parse().unwrap();

        let started = Instant::now();
        let stream = connect_tcp_any(&[silent, open], Duration::from_millis(100), |addr| async move {
            if addr == silent {
                std::future::pending::<()>().await;
            }
            TcpStream::connect(addr).await
        })
        .await
        .unwrap();

        assert_eq!(stream.peer_addr().unwrap(), open);
        let elapsed = started.elapsed();
        assert!(elapsed >= Duration::from_millis(100), "{elapsed:?}");
        assert!(elapsed < Duration::from_secs(1), "{elapsed:?}");
    }

    #[tokio::test]
    async fn zero_delay_starts_every_attempt_at_once() {
        let (_listener, open) = listening().await;
        let silent: SocketAddr = "192.0.2.2:443".parse().unwrap();

        let started = Instant::now();
        connect_tcp_any(&[silent, silent, open], Duration::ZERO, |addr| async move {
            if addr == silent {
                std::future::pending::<()>().await;
            }
            TcpStream::connect(addr).await
        })
        .await
        .unwrap();

        assert!(started.elapsed() < Duration::from_millis(100));
    }

    #[tokio::test]
    async fn all_failures_are_reported() {
        let (a, b) = (closed().await, closed().await);

        let err = connect_tcp_any(&[a, b], Duration::from_secs(5), TcpStream::connect)
            .await
            .unwrap_err();

        let message = err.to_string();
        assert!(message.contains(&a.to_string()), "{message}");
        assert!(message.contains(&b.to_string()), "{message}");
    }

    #[tokio::test]
    async fn single_failure_keeps_its_kind() {
        let refused = closed().await;

        let err = connect_tcp_any(&[refused], Duration::from_secs(5), TcpStream::connect)
            .await
            .unwrap_err();

        assert_eq!(err.kind(), io::ErrorKind::ConnectionRefused);
    }

    #[test]
    fn addresses_interleave_starting_with_preferred_family() {
        let addrs: Vec<SocketAddr> = [
            "198.51.100.1:80",
            "198.51.100.2:80",
            "[2001:db8::1]:80",
            "[2001:db8::2]:80",
            "[2001:db8::3]:80",
        ]
        .iter()
        .map(|s| s.parse().unwrap())
        .collect();

        let families = |ordered: &[SocketAddr]| {
            ordered.iter().map(SocketAddr::is_ipv6).collect::<Vec<_>>()
        };
        assert_eq!(
            families(&order_addrs(addrs.clone(), false)),
            [false, true, false, true, true]
        );
        assert_eq!(
            families(&order_addrs(addrs, true)),
            [true, false, true, false, true]
        );
    }

    #[test]
    fn recently_failed_addresses_go_last() {
        let failed: SocketAddr = "203.0.113.7:80".parse().unwrap();
        let healthy: SocketAddr = "203.0.113.8:80".parse().unwrap();
        mark_failed(failed.ip());

        for _ in 0..10 {
            assert_eq!(order_addrs(vec![failed, healthy], false), [healthy, failed]);
        }

        mark_connected(&failed.ip());
        assert!(!recently_failed(&failed.ip()));
    }
}
