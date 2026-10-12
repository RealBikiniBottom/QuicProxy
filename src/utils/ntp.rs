use crate::config::{Config, NtpConfig};
use crate::dns::resolve_target;
use crate::proxy::outbound::{AnyOutbound, get_default_outbound, get_outbound_by_tag};
use crate::proxy::{SourceAddr, TargetAddr};
use crate::utils::shutdown;
use crate::utils::time::parse_duration;
use anyhow::{Context, Result, anyhow, ensure};
use bytes::Bytes;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::time::timeout;
use tracing::{info, warn};

const NTP_PACKET_LEN: usize = 48;
/// Seconds from the NTP epoch (1900-01-01) to the Unix epoch.
const NTP_UNIX_EPOCH_DELTA: u64 = 2_208_988_800;
const DEFAULT_INTERVAL: Duration = Duration::from_secs(30 * 60);
const RETRY_DELAY: Duration = Duration::from_secs(30);

static OFFSET_NANOS: AtomicI64 = AtomicI64::new(0);
static SYNCED: AtomicBool = AtomicBool::new(false);

/// Wall-clock time corrected by the last NTP sync. Falls back to the system
/// clock while NTP is disabled or has not synced yet.
pub fn system_time() -> SystemTime {
    let now = SystemTime::now();
    #[cfg(test)]
    if let Some(offset) = test_clock::offset() {
        return apply_offset(now, offset);
    }
    if !SYNCED.load(Ordering::Relaxed) {
        return now;
    }
    apply_offset(now, OFFSET_NANOS.load(Ordering::Relaxed))
}

pub fn unix_time() -> Duration {
    system_time().duration_since(UNIX_EPOCH).unwrap_or_default()
}

pub fn is_synced() -> bool {
    SYNCED.load(Ordering::Relaxed)
}

/// Per-thread clock offset so tests can simulate an NTP correction without
/// racing other tests that read the global clock.
#[cfg(test)]
pub(crate) mod test_clock {
    use std::cell::Cell;
    use std::time::SystemTime;

    thread_local! {
        static OFFSET_NANOS: Cell<Option<i64>> = const { Cell::new(None) };
    }

    pub(super) fn offset() -> Option<i64> {
        OFFSET_NANOS.with(Cell::get)
    }

    pub struct Guard;

    impl Drop for Guard {
        fn drop(&mut self) {
            OFFSET_NANOS.with(|o| o.set(None));
        }
    }

    /// Makes the NTP clock on this thread read `target` (approximately).
    pub fn set_now(target: SystemTime) -> Guard {
        let nanos = |t: SystemTime| match t.duration_since(std::time::UNIX_EPOCH) {
            Ok(d) => d.as_nanos() as i128,
            Err(e) => -(e.duration().as_nanos() as i128),
        };
        let offset = nanos(target) - nanos(SystemTime::now());
        OFFSET_NANOS.with(|o| o.set(Some(offset as i64)));
        Guard
    }
}

fn apply_offset(time: SystemTime, offset_nanos: i64) -> SystemTime {
    let delta = Duration::from_nanos(offset_nanos.unsigned_abs());
    let corrected = if offset_nanos >= 0 {
        time.checked_add(delta)
    } else {
        time.checked_sub(delta)
    };
    corrected.unwrap_or(time)
}

/// rustls reads the time through this to validate certificates and tickets.
macro_rules! ntp_tls_builders {
    () => {
        #[derive(Debug)]
        struct NtpTimeProvider;

        impl rustls::time_provider::TimeProvider for NtpTimeProvider {
            fn current_time(&self) -> Option<rustls::pki_types::UnixTime> {
                Some(rustls::pki_types::UnixTime::since_unix_epoch(
                    super::unix_time(),
                ))
            }
        }

        fn crypto_provider() -> Arc<rustls::crypto::CryptoProvider> {
            rustls::crypto::CryptoProvider::get_default()
                .cloned()
                .unwrap_or_else(|| Arc::new(rustls::crypto::ring::default_provider()))
        }

        /// Same as `rustls::ClientConfig::builder()`, but on the NTP clock.
        pub fn client_builder()
        -> rustls::ConfigBuilder<rustls::ClientConfig, rustls::WantsVerifier> {
            rustls::ClientConfig::builder_with_details(crypto_provider(), Arc::new(NtpTimeProvider))
                .with_safe_default_protocol_versions()
                .expect("crypto provider supports the default protocol versions")
        }

        /// Same as `rustls::ServerConfig::builder()`, but on the NTP clock.
        pub fn server_builder()
        -> rustls::ConfigBuilder<rustls::ServerConfig, rustls::WantsVerifier> {
            rustls::ServerConfig::builder_with_details(crypto_provider(), Arc::new(NtpTimeProvider))
                .with_safe_default_protocol_versions()
                .expect("crypto provider supports the default protocol versions")
        }
    };
}

pub mod tls {
    use std::sync::Arc;
    ntp_tls_builders!();
}

/// quinn links its own copy of the rustls-jls fork, so it needs separate builders.
pub mod quic_tls {
    use quinn::rustls;
    use std::sync::Arc;
    ntp_tls_builders!();
}

pub fn init_ntp(cfg: &Config) -> Result<()> {
    let Some(ntp) = cfg.ntp.as_ref().filter(|ntp| ntp.enabled) else {
        return Ok(());
    };
    let client = NtpClient::new(ntp)?;
    info!(
        "NTP enabled: server {}, interval {:?}, outbound {}",
        client.server,
        client.interval,
        client.outbound.tag()
    );
    shutdown::spawn(client.run());
    Ok(())
}

pub fn shutdown_ntp() {
    SYNCED.store(false, Ordering::Relaxed);
    OFFSET_NANOS.store(0, Ordering::Relaxed);
}

struct NtpClient {
    server: TargetAddr,
    outbound: Arc<dyn AnyOutbound>,
    dns: Option<String>,
    interval: Duration,
}

impl NtpClient {
    fn new(cfg: &NtpConfig) -> Result<Self> {
        let server = TargetAddr::from_str2(&cfg.address, cfg.port)
            .with_context(|| format!("invalid ntp address '{}'", cfg.address))?;
        let outbound = match cfg.outbound.as_deref() {
            Some(tag) => get_outbound_by_tag(tag)
                .with_context(|| format!("ntp references unknown outbound '{}'", tag))?,
            None => get_default_outbound().context("ntp requires a default outbound")?,
        };
        let interval = match cfg.interval.as_deref().map(parse_duration) {
            Some(interval) if interval.is_zero() => {
                warn!("Invalid ntp interval, using {:?}", DEFAULT_INTERVAL);
                DEFAULT_INTERVAL
            }
            Some(interval) => interval,
            None => DEFAULT_INTERVAL,
        };
        Ok(Self {
            server,
            outbound,
            dns: cfg.dns.clone(),
            interval,
        })
    }

    async fn run(self) {
        loop {
            let wait = match self.query_offset().await {
                Ok(offset_nanos) => {
                    OFFSET_NANOS.store(offset_nanos, Ordering::Relaxed);
                    SYNCED.store(true, Ordering::Relaxed);
                    info!(
                        "NTP synced with {}, clock offset {:+.3}ms",
                        self.server,
                        offset_nanos as f64 / 1_000_000.0
                    );
                    self.interval
                }
                Err(e) => {
                    warn!("NTP sync with {} failed: {:#}", self.server, e);
                    RETRY_DELAY.min(self.interval)
                }
            };
            tokio::time::sleep(wait).await;
        }
    }

    /// Returns how far the local system clock lags behind the server, in nanoseconds.
    async fn query_offset(&self) -> Result<i64> {
        let target = TargetAddr::Ip(resolve_target(&self.server, self.dns.as_deref()).await?);
        let socket = self.outbound.connect_packet(&target).await?;
        let closer = socket.closer();

        let result = async {
            let t1 = SystemTime::now();
            let request = build_request(t1);
            socket
                .send_to(
                    Bytes::copy_from_slice(&request),
                    &SourceAddr::dummy(),
                    &target,
                )
                .await?;
            let (_, _, response) = timeout(self.outbound.connect_timeout(), socket.recv_from())
                .await
                .map_err(|_| anyhow!("NTP query timed out"))??;
            let t4 = SystemTime::now();
            parse_response(&request, &response, t1, t4)
        }
        .await;

        if let Some(closer) = closer {
            closer.close();
        }

        result
    }
}

fn build_request(transmit: SystemTime) -> [u8; NTP_PACKET_LEN] {
    let mut packet = [0u8; NTP_PACKET_LEN];
    // LI = 0, VN = 4, Mode = 3 (client)
    packet[0] = 0x23;
    packet[40..48].copy_from_slice(&to_ntp_timestamp(transmit).to_be_bytes());
    packet
}

fn parse_response(
    request: &[u8; NTP_PACKET_LEN],
    response: &[u8],
    t1: SystemTime,
    t4: SystemTime,
) -> Result<i64> {
    ensure!(
        response.len() >= NTP_PACKET_LEN,
        "NTP response too short: {} bytes",
        response.len()
    );
    ensure!(
        response[0] & 0x07 == 4,
        "NTP response is not in server mode"
    );
    ensure!(response[0] >> 6 != 3, "NTP server clock is unsynchronized");
    let stratum = response[1];
    ensure!(
        (1..16).contains(&stratum),
        "NTP server returned stratum {}",
        stratum
    );
    // The server echoes our transmit timestamp as its origin timestamp; a
    // mismatch means a stale or spoofed reply.
    ensure!(
        response[24..32] == request[40..48],
        "NTP response origin timestamp mismatch"
    );

    let t2 = from_ntp_timestamp(read_u64(&response[32..40]));
    let t3 = from_ntp_timestamp(read_u64(&response[40..48]));
    let t1 = unix_nanos(t1);
    let t4 = unix_nanos(t4);
    let offset = ((t2 - t1) + (t3 - t4)) / 2;
    i64::try_from(offset).context("NTP clock offset out of range")
}

fn read_u64(bytes: &[u8]) -> u64 {
    u64::from_be_bytes(bytes.try_into().expect("8-byte slice"))
}

fn unix_nanos(time: SystemTime) -> i128 {
    match time.duration_since(UNIX_EPOCH) {
        Ok(d) => d.as_nanos() as i128,
        Err(e) => -(e.duration().as_nanos() as i128),
    }
}

fn to_ntp_timestamp(time: SystemTime) -> u64 {
    let since_unix = time.duration_since(UNIX_EPOCH).unwrap_or_default();
    let secs = (since_unix.as_secs() + NTP_UNIX_EPOCH_DELTA) as u32;
    let frac = ((since_unix.subsec_nanos() as u64) << 32) / 1_000_000_000;
    ((secs as u64) << 32) | frac
}

/// Converts an NTP timestamp to Unix nanoseconds. Seconds with the top bit
/// clear belong to NTP era 1 (after 2036-02-07).
fn from_ntp_timestamp(timestamp: u64) -> i128 {
    let secs = timestamp >> 32;
    let frac = timestamp & 0xFFFF_FFFF;
    let secs = if secs & 0x8000_0000 == 0 {
        secs + (1 << 32)
    } else {
        secs
    };
    let unix_secs = secs as i128 - NTP_UNIX_EPOCH_DELTA as i128;
    unix_secs * 1_000_000_000 + ((frac as i128 * 1_000_000_000) >> 32)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn now_timestamp_follows_ntp_clock() {
        let target = UNIX_EPOCH + Duration::from_secs(2_222_000_000);
        let _clock = test_clock::set_now(target);
        let now = crate::utils::now_timestamp();
        assert!(now.abs_diff(2_222_000_000) <= 1, "{now}");
    }

    /// Hysteria2 and shadowquic build their TLS config from `quic_tls`.
    #[test]
    fn quic_tls_validates_certificate_with_ntp_time() {
        use quinn::rustls;
        let _ = rustls::crypto::ring::default_provider().install_default();

        let mut params = rcgen::CertificateParams::new(vec!["localhost".to_string()]).unwrap();
        params.not_before = rcgen::date_time_ymd(2040, 1, 1);
        params.not_after = rcgen::date_time_ymd(2041, 1, 1);
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = params.self_signed(&key).unwrap();
        let cert_der = rustls::pki_types::CertificateDer::from(cert.der().to_vec());
        let key_der = rustls::pki_types::PrivateKeyDer::try_from(key.serialize_der()).unwrap();
        let server_config = Arc::new(
            rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(vec![cert_der.clone()], key_der)
                .unwrap(),
        );
        let mut roots = rustls::RootCertStore::empty();
        roots.add(cert_der).unwrap();
        let client_config = Arc::new(
            quic_tls::client_builder()
                .with_root_certificates(roots)
                .with_no_client_auth(),
        );

        let handshake = || -> std::result::Result<(), rustls::Error> {
            let name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
            let mut client = rustls::ClientConnection::new(client_config.clone(), name)?;
            let mut server = rustls::ServerConnection::new(server_config.clone())?;
            while client.is_handshaking() || server.is_handshaking() {
                let mut buf = Vec::new();
                client.write_tls(&mut buf).unwrap();
                server.read_tls(&mut buf.as_slice()).unwrap();
                server.process_new_packets()?;
                let mut buf = Vec::new();
                server.write_tls(&mut buf).unwrap();
                client.read_tls(&mut buf.as_slice()).unwrap();
                client.process_new_packets()?;
            }
            Ok(())
        };

        let err = handshake().unwrap_err();
        assert!(err.to_string().contains("not valid yet"), "{err}");

        let _clock = test_clock::set_now(UNIX_EPOCH + Duration::from_secs(2_222_000_000));
        handshake().unwrap();
    }

    #[test]
    fn ntp_timestamp_round_trips() {
        let time = UNIX_EPOCH + Duration::new(1_791_742_167, 123_456_789);
        let nanos = from_ntp_timestamp(to_ntp_timestamp(time));
        assert!((nanos - unix_nanos(time)).abs() < 1_000);
    }

    #[test]
    fn ntp_era_one_timestamps_are_after_2036() {
        let time = UNIX_EPOCH + Duration::from_secs(2_200_000_000);
        let nanos = from_ntp_timestamp(to_ntp_timestamp(time));
        assert_eq!(nanos / 1_000_000_000, 2_200_000_000);
    }

    #[test]
    fn parse_response_computes_offset() {
        let t1 = UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let t4 = t1 + Duration::from_millis(100);
        let server_offset = Duration::from_secs(5);
        let request = build_request(t1);

        let mut response = [0u8; NTP_PACKET_LEN];
        response[0] = 0x24;
        response[1] = 2;
        response[24..32].copy_from_slice(&request[40..48]);
        let t2 = t1 + Duration::from_millis(50) + server_offset;
        response[32..40].copy_from_slice(&to_ntp_timestamp(t2).to_be_bytes());
        response[40..48].copy_from_slice(&to_ntp_timestamp(t2).to_be_bytes());

        let offset = parse_response(&request, &response, t1, t4).unwrap();
        assert!((offset - 5_000_000_000).abs() < 1_000);
    }

    #[test]
    fn parse_response_rejects_mismatched_origin() {
        let t1 = UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let request = build_request(t1);
        let mut response = [0u8; NTP_PACKET_LEN];
        response[0] = 0x24;
        response[1] = 2;
        assert!(parse_response(&request, &response, t1, t1).is_err());
    }

    #[test]
    fn apply_offset_moves_both_directions() {
        let time = UNIX_EPOCH + Duration::from_secs(1_000);
        assert_eq!(
            apply_offset(time, 2_000_000_000),
            UNIX_EPOCH + Duration::from_secs(1_002)
        );
        assert_eq!(
            apply_offset(time, -2_000_000_000),
            UNIX_EPOCH + Duration::from_secs(998)
        );
    }
}
