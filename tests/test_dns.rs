use std::net::{IpAddr, Ipv4Addr};
use std::str::FromStr;
use std::time::Duration;

use quicproxy::cache;
use quicproxy::config::{CacheConfig, Config, DnsServerConfig};
use quicproxy::dns::*;
use tempfile::TempDir;

#[cfg(any())]
use std::sync::{Arc, Mutex};
#[cfg(any())]
use rustls::crypto::ring::default_provider;
#[cfg(any())]
use quicproxy::proxy::outbound::direct::DirectOutbound;
#[cfg(any())]
use quicproxy::proxy::outbound::AnyOutbound;
#[cfg(any())]
use simple_dns::{Packet, QTYPE, RCODE, TYPE};

const TEST_TIMEOUT: Duration = Duration::from_secs(15);

#[cfg(any())]
async fn create_test_direct_outbound() -> Arc<dyn AnyOutbound> {
    let dns_resolver = Arc::new(DnsResolver::new(None).await);

    Arc::new(DirectOutbound::new(
        "test_direct".to_string(),
        Duration::from_secs(10),
        None,
        dns_resolver,
        None,
        false,
    ))
}

#[cfg(any())]
#[tokio::test]
async fn test_udp_dns_provider() {
    let outbound = create_test_direct_outbound().await;

    let udp_provider = UdpDnsProvider {
        address: "8.8.8.8".to_string(),
        port: 53,
        min_ttl: None,
        max_ttl: None,
        timeout: Duration::from_secs(5),
        outbound,
    };

    println!("Testing UDP DNS IPv4 query for cloudflare.com...");
    let ipv4_result = tokio::time::timeout(
        TEST_TIMEOUT,
        udp_provider.lookup_ipv4("cloudflare.com"),
    )
    .await
    .expect("UDP IPv4 query timed out");
    match ipv4_result {
        Ok(ips) => {
            println!("✅ UDP IPv4 query success, got {} IPs:", ips.len());
            assert!(!ips.is_empty(), "Should get at least one IPv4 address");
            for ip in &ips {
                println!("  - {}", ip);
            }
        }
        Err(e) => {
            eprintln!("❌ UDP IPv4 query failed: {}", e);
            panic!("UDP IPv4 query failed");
        }
    }

    println!("Testing UDP DNS IPv6 query for cloudflare.com...");
    let ipv6_result = tokio::time::timeout(
        TEST_TIMEOUT,
        udp_provider.lookup_ipv6("cloudflare.com"),
    )
    .await
    .expect("UDP IPv6 query timed out");
    match ipv6_result {
        Ok(ips) => {
            println!("✅ UDP IPv6 query success, got {} IPs:", ips.len());
            assert!(!ips.is_empty(), "Should get at least one IPv6 address");
            for ip in &ips {
                println!("  - {}", ip);
            }
        }
        Err(e) => {
            eprintln!("❌ UDP IPv6 query failed: {}", e);
            panic!("UDP IPv6 query failed");
        }
    }
}

#[cfg(any())]
#[tokio::test]
async fn test_https_dns_provider() {
    let _ = default_provider().install_default();

    let outbound = create_test_direct_outbound().await;

    let https_provider = HttpsDnsProvider {
        address: "223.5.5.5".to_string(),
        port: 443,
        min_ttl: None,
        max_ttl: None,
        outbound,
    };

    println!("Testing HTTPS DNS IPv4 query for cloudflare.com...");
    let ipv4_result = tokio::time::timeout(
        TEST_TIMEOUT,
        https_provider.lookup_ipv4("cloudflare.com"),
    )
    .await
    .expect("HTTPS IPv4 query timed out");
    match ipv4_result {
        Ok(ips) => {
            println!("✅ HTTPS IPv4 query success, got {} IPs:", ips.len());
            assert!(!ips.is_empty(), "Should get at least one IPv4 address");
            for ip in &ips {
                println!("  - {}", ip);
            }
        }
        Err(e) => {
            eprintln!("❌ HTTPS IPv4 query failed: {}", e);
            panic!("HTTPS IPv4 query failed");
        }
    }

    println!("Testing HTTPS DNS IPv6 query for cloudflare.com...");
    let ipv6_result = tokio::time::timeout(
        TEST_TIMEOUT,
        https_provider.lookup_ipv6("cloudflare.com"),
    )
    .await
    .expect("HTTPS IPv6 query timed out");
    match ipv6_result {
        Ok(ips) => {
            println!("✅ HTTPS IPv6 query success, got {} IPs:", ips.len());
            assert!(!ips.is_empty(), "Should get at least one IPv6 address");
            for ip in &ips {
                println!("  - {}", ip);
            }
        }
        Err(e) => {
            eprintln!("❌ HTTPS IPv6 query failed: {}", e);
            panic!("HTTPS IPv6 query failed");
        }
    }
}

#[cfg(any())]
#[tokio::test]
async fn test_fake_ip_dns_provider() {
    let fake_ip_manager = Arc::new(Mutex::new(
        FakeIpManager::new("", 100, Some("198.18.0.0/15".to_string()), None).unwrap(),
    ));

    let fake_provider = FakeIpDnsProvider {
        min_ttl: None,
        max_ttl: None,
        fake_ip_manager,
    };

    println!("Testing Fake IP IPv4 query for test.com...");
    let ipv4_result = tokio::time::timeout(
        TEST_TIMEOUT,
        fake_provider.lookup_ipv4("test.com"),
    )
    .await
    .expect("Fake IP IPv4 query timed out");
    match ipv4_result {
        Ok(ips) => {
            println!("✅ Fake IP IPv4 query success, got {} IPs:", ips.len());
            assert_eq!(ips.len(), 1, "Should get exactly one IPv4 address");
            for ip in &ips {
                println!("  - {}", ip);
                assert!(
                    ip.octets()[0] == 198 && ip.octets()[1] == 18,
                    "Should be fake IP range (198.18.x.x)"
                );
            }
        }
        Err(e) => {
            eprintln!("❌ Fake IP IPv4 query failed: {}", e);
            panic!("Fake IP IPv4 query failed");
        }
    }
}

#[cfg(any())]
fn make_fakeip_manager() -> Arc<Mutex<FakeIpManager>> {
    Arc::new(Mutex::new(FakeIpManager::new(
        "",
        100,
        Some("198.18.0.0/15".to_string()),
        Some("fc00::/18".to_string()),
    ).unwrap()))
}

#[cfg(any())]
fn make_provider(
    mgr: Arc<Mutex<FakeIpManager>>,
    min_ttl: Option<Duration>,
    max_ttl: Option<Duration>,
) -> FakeIpDnsProvider {
    FakeIpDnsProvider {
        min_ttl,
        max_ttl,
        fake_ip_manager: mgr,
    }
}

#[cfg(any())]
fn ttl_of_first_answer(response_bytes: &[u8]) -> u32 {
    let packet = Packet::parse(response_bytes).expect("should parse response");
    assert!(!packet.answers.is_empty(), "response should have answers");
    packet.answers[0].ttl
}

#[cfg(any())]
fn rcode_of(response_bytes: &[u8]) -> RCODE {
    Packet::parse(response_bytes)
        .expect("should parse response")
        .rcode()
}

#[cfg(any())]
#[tokio::test]
async fn test_fakeip_exchange_ipv4() {
    tokio::time::timeout(TEST_TIMEOUT, async {
        let mgr = make_fakeip_manager();
        let provider = make_provider(mgr.clone(), None, None);

        let query_packet =
            build_dns_query_packet("example.com", QTYPE::TYPE(TYPE::A)).unwrap();
        let query_bytes = query_packet.build_bytes_vec().unwrap();

        let response = provider.exchange(&query_bytes).await.unwrap();
        assert_eq!(rcode_of(&response), RCODE::NoError);

        let ips = extract_ipv4_from_response(&response);
        assert_eq!(ips.len(), 1);

        let mgr = mgr.lock().unwrap();
        assert!(mgr.is_fake_ip(std::net::IpAddr::V4(ips[0])));
        assert_eq!(
            mgr.lookup_domain(std::net::IpAddr::V4(ips[0])).as_deref(),
            Some("example.com")
        );
    })
    .await
    .expect("test timed out");
}

#[cfg(any())]
#[tokio::test]
async fn test_fakeip_exchange_ipv6() {
    tokio::time::timeout(TEST_TIMEOUT, async {
        let mgr = make_fakeip_manager();
        let provider = make_provider(mgr.clone(), None, None);

        let query_packet =
            build_dns_query_packet("example.com", QTYPE::TYPE(TYPE::AAAA)).unwrap();
        let query_bytes = query_packet.build_bytes_vec().unwrap();

        let response = provider.exchange(&query_bytes).await.unwrap();
        assert_eq!(rcode_of(&response), RCODE::NoError);

        let ips = extract_ipv6_from_response(&response);
        assert_eq!(ips.len(), 1);

        let mgr = mgr.lock().unwrap();
        assert!(mgr.is_fake_ip(std::net::IpAddr::V6(ips[0])));
        assert_eq!(
            mgr.lookup_domain(std::net::IpAddr::V6(ips[0])).as_deref(),
            Some("example.com")
        );
    })
    .await
    .expect("test timed out");
}

#[cfg(any())]
#[tokio::test]
async fn test_fakeip_exchange_same_domain_returns_same_ip() {
    tokio::time::timeout(TEST_TIMEOUT, async {
        let mgr = make_fakeip_manager();
        let provider = make_provider(mgr, None, None);

        let query_packet =
            build_dns_query_packet("test.local", QTYPE::TYPE(TYPE::A)).unwrap();
        let query_bytes = query_packet.build_bytes_vec().unwrap();

        let response1 = provider.exchange(&query_bytes).await.unwrap();
        let response2 = provider.exchange(&query_bytes).await.unwrap();

        let ips1 = extract_ipv4_from_response(&response1);
        let ips2 = extract_ipv4_from_response(&response2);
        assert_eq!(ips1, ips2);
    })
    .await
    .expect("test timed out");
}

#[cfg(any())]
#[tokio::test]
async fn test_fakeip_exchange_unsupported_qtype_returns_err() {
    tokio::time::timeout(TEST_TIMEOUT, async {
        let mgr = make_fakeip_manager();
        let provider = make_provider(mgr, None, None);

        let query_packet =
            build_dns_query_packet("example.com", QTYPE::TYPE(TYPE::MX)).unwrap();
        let query_bytes = query_packet.build_bytes_vec().unwrap();

        let result = provider.exchange(&query_bytes).await;
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("only supports A and AAAA"),
            "unexpected error: {}",
            err_msg
        );
    })
    .await
    .expect("test timed out");
}

#[cfg(any())]
#[tokio::test]
async fn test_fakeip_exchange_default_ttl() {
    tokio::time::timeout(TEST_TIMEOUT, async {
        let mgr = make_fakeip_manager();
        let provider = make_provider(mgr, None, None);

        let query_packet =
            build_dns_query_packet("ttl.test", QTYPE::TYPE(TYPE::A)).unwrap();
        let query_bytes = query_packet.build_bytes_vec().unwrap();

        let response = provider.exchange(&query_bytes).await.unwrap();
        assert_eq!(ttl_of_first_answer(&response), 60);
    })
    .await
    .expect("test timed out");
}

#[cfg(any())]
#[tokio::test]
async fn test_fakeip_exchange_min_ttl_raises_ttl() {
    tokio::time::timeout(TEST_TIMEOUT, async {
        let mgr = make_fakeip_manager();
        let provider = make_provider(mgr, Some(Duration::from_secs(120)), None);

        let query_packet =
            build_dns_query_packet("min.ttl.test", QTYPE::TYPE(TYPE::A)).unwrap();
        let query_bytes = query_packet.build_bytes_vec().unwrap();

        let response = provider.exchange(&query_bytes).await.unwrap();
        assert_eq!(ttl_of_first_answer(&response), 120);
    })
    .await
    .expect("test timed out");
}

#[cfg(any())]
#[tokio::test]
async fn test_fakeip_exchange_max_ttl_caps_ttl() {
    tokio::time::timeout(TEST_TIMEOUT, async {
        let mgr = make_fakeip_manager();
        let provider = make_provider(mgr, None, Some(Duration::from_secs(30)));

        let query_packet =
            build_dns_query_packet("max.ttl.test", QTYPE::TYPE(TYPE::A)).unwrap();
        let query_bytes = query_packet.build_bytes_vec().unwrap();

        let response = provider.exchange(&query_bytes).await.unwrap();
        assert_eq!(ttl_of_first_answer(&response), 30);
    })
    .await
    .expect("test timed out");
}

#[cfg(any())]
#[tokio::test]
async fn test_fakeip_exchange_min_and_max_ttl() {
    tokio::time::timeout(TEST_TIMEOUT, async {
        let mgr = make_fakeip_manager();
        let provider = make_provider(
            mgr,
            Some(Duration::from_secs(120)),
            Some(Duration::from_secs(300)),
        );

        let query_packet =
            build_dns_query_packet("both.ttl.test", QTYPE::TYPE(TYPE::A)).unwrap();
        let query_bytes = query_packet.build_bytes_vec().unwrap();

        let response = provider.exchange(&query_bytes).await.unwrap();
        assert_eq!(ttl_of_first_answer(&response), 120);
    })
    .await
    .expect("test timed out");
}

#[cfg(any())]
#[tokio::test]
async fn test_fakeip_reverse_lookup() {
    tokio::time::timeout(TEST_TIMEOUT, async {
        let mgr = make_fakeip_manager();
        let provider = make_provider(mgr, None, None);

        let ipv4s = provider.lookup_ipv4("reverse.test").await.unwrap();
        assert_eq!(ipv4s.len(), 1);

        let domain = provider
            .reverse(&std::net::IpAddr::V4(ipv4s[0]))
            .await
            .unwrap();
        assert_eq!(domain.as_deref(), Some("reverse.test"));
    })
    .await
    .expect("test timed out");
}

#[cfg(any())]
#[tokio::test]
async fn test_fakeip_reverse_unknown_ip_returns_none() {
    tokio::time::timeout(TEST_TIMEOUT, async {
        let mgr = make_fakeip_manager();
        let provider = make_provider(mgr, None, None);

        let result = provider
            .reverse(&std::net::IpAddr::V4(std::net::Ipv4Addr::new(8, 8, 8, 8)))
            .await
            .unwrap();
        assert!(result.is_none());
    })
    .await
    .expect("test timed out");
}

// ========================
// FakeIPDNS direct tests
// ========================

fn setup_cache_for_tag(temp_dir: &TempDir, tag: &str, memory_size: u64) {
    let db_path = temp_dir.path().join("cache.db");
    let mut config = Config::default();
    config.cache.insert(
        tag.to_string(),
        CacheConfig {
            memory_size,
            path: Some(db_path.to_string_lossy().to_string()),
        },
    );
    cache::init_cache(&config);
}

fn make_fakeipdns(
    tag: &str,
    cache_tag: &str,
    range_v4: &str,
    range_v6: Option<&str>,
) -> FakeIPDNS {
    let default_v4 = ipnet::Ipv4Net::from_str("198.18.0.0/16").unwrap();
    let default_v6 = ipnet::Ipv6Net::from_str("fc00::/18").unwrap();

    let mut v4_found = None;
    let mut v6_found = None;

    if let Ok(net) = ipnet::IpNet::from_str(range_v4) {
        if let ipnet::IpNet::V4(v4) = net {
            v4_found = Some(v4);
        }
    }
    if let Some(v6_str) = range_v6 {
        if let Ok(net) = ipnet::IpNet::from_str(v6_str) {
            if let ipnet::IpNet::V6(v6) = net {
                v6_found = Some(v6);
            }
        }
    }

    let ipv4_cidr = v4_found.unwrap_or(default_v4);
    let ipv6_cidr = v6_found.unwrap_or(default_v6);

    let cache: quicproxy::cache::Cache<String> = quicproxy::cache::Cache::new_with_tag(
        cache_tag,
        format!("fakeip:{}", tag),
    )
    .expect("failed to init cache");

    let ipv4_cursor = match cache.get("fakeip_ipv4_cursor_index") {
        Ok(Some(r)) => r.0.trim().parse().unwrap_or(0),
        _ => 0,
    };
    let ipv6_cursor = match cache.get("fakeip_ipv6_cursor_index") {
        Ok(Some(r)) => r.0.trim().parse().unwrap_or(0),
        _ => 0,
    };

    FakeIPDNS {
        tag: tag.to_string(),
        min_ttl: None,
        ipv4_cidr,
        ipv6_cidr,
        cache,
        ipv4_cursor: std::sync::atomic::AtomicU64::new(ipv4_cursor),
        ipv6_cursor: std::sync::atomic::AtomicU64::new(ipv6_cursor),
        reject_ipv6: false,
    }
}

#[tokio::test]
async fn test_fakeipdns_cache_same_domain_returns_same_ip() {
    tokio::time::timeout(TEST_TIMEOUT, async {
        let temp_dir = TempDir::new().expect("failed to create temp dir");
        let cache_tag = "fk_cache_basic";
        setup_cache_for_tag(&temp_dir, cache_tag, 100);

        let dns = make_fakeipdns("test", cache_tag, "198.18.0.0/15", None);

        let ip1 = dns.resolve_v4("test.example.com").expect("should resolve");
        assert!(dns.ipv4_cidr.contains(&ip1), "IP should be in the CIDR range");

        let ip2 = dns.resolve_v4("test.example.com").expect("should resolve again");
        assert_eq!(ip1, ip2, "same domain should return the same cached IP");

        let ip3 = dns.resolve_v4("other.example.com").expect("should resolve other");
        assert_ne!(ip1, ip3, "different domains should get different IPs");
    })
    .await
    .expect("test timed out");
}

#[tokio::test]
async fn test_fakeipdns_cache_multiple_domains() {
    tokio::time::timeout(TEST_TIMEOUT, async {
        let temp_dir = TempDir::new().expect("failed to create temp dir");
        let cache_tag = "fk_cache_multi";
        setup_cache_for_tag(&temp_dir, cache_tag, 100);

        let dns = make_fakeipdns("test", cache_tag, "198.18.0.0/15", None);

        let domains: Vec<String> = (0..5)
            .map(|i| format!("host{}.example.com", i))
            .collect();

        let ips: Vec<Ipv4Addr> = domains
            .iter()
            .map(|d| dns.resolve_v4(d).expect("should resolve"))
            .collect();

        for ip in &ips {
            assert!(dns.ipv4_cidr.contains(ip), "all IPs must be in CIDR range");
        }

        let unique: std::collections::HashSet<_> = ips.iter().collect();
        assert_eq!(unique.len(), ips.len(), "each domain should get a unique IP");

        for (domain, expected_ip) in domains.iter().zip(ips.iter()) {
            let cached_ip = dns.resolve_v4(domain).expect("should hit cache");
            assert_eq!(
                cached_ip, *expected_ip,
                "cached IP for {domain} should match"
            );
        }
    })
    .await
    .expect("test timed out");
}

#[tokio::test]
async fn test_fakeipdns_cursor_persistence() {
    tokio::time::timeout(TEST_TIMEOUT, async {
        let temp_dir = TempDir::new().expect("failed to create temp dir");
        let cache_tag = "fk_cursor_persist";
        let dns_tag = "fakeip_persist";
        setup_cache_for_tag(&temp_dir, cache_tag, 100);

        let dns1 = make_fakeipdns(dns_tag, cache_tag, "198.18.0.0/15", None);

        let domains: Vec<String> = (0..5)
            .map(|i| format!("host{}.persist.com", i))
            .collect();

        let ips_first: Vec<(String, Ipv4Addr)> = domains
            .iter()
            .map(|d| (d.clone(), dns1.resolve_v4(d).expect("should resolve")))
            .collect();

        let _ = dns1.cache.set("fakeip_ipv4_cursor_index", &dns1.ipv4_cursor.load(std::sync::atomic::Ordering::Relaxed).to_string());
        let _ = dns1.cache.set("fakeip_ipv6_cursor_index", &dns1.ipv6_cursor.load(std::sync::atomic::Ordering::Relaxed).to_string());

        let dns2 = make_fakeipdns(dns_tag, cache_tag, "198.18.0.0/15", None);

        for (domain, expected_ip) in &ips_first {
            let ip = dns2
                .resolve_v4(domain)
                .expect("should resolve from disk cache");
            assert_eq!(
                ip, *expected_ip,
                "reopened cache: domain {domain} should return same IP"
            );
        }

        let new_ip = dns2.resolve_v4("fresh.persist.com").expect("should resolve new");
        for (_, old_ip) in &ips_first {
            assert_ne!(
                new_ip, *old_ip,
                "new allocation should not collide with old cached IPs"
            );
        }
    })
    .await
    .expect("test timed out");
}

#[tokio::test]
async fn test_fakeipdns_reverse_lookup() {
    tokio::time::timeout(TEST_TIMEOUT, async {
        let temp_dir = TempDir::new().expect("failed to create temp dir");
        let cache_tag = "fk_reverse";
        setup_cache_for_tag(&temp_dir, cache_tag, 100);

        let dns = make_fakeipdns("test", cache_tag, "198.18.0.0/15", Some("fc00::/18"));

        let ipv4 = dns.resolve_v4("ipv4.reverse.test").expect("should resolve");
        let domain = dns.reverse_lookup(&IpAddr::V4(ipv4));
        assert_eq!(
            domain.as_deref(),
            Some("ipv4.reverse.test"),
            "IPv4 reverse lookup should return the original domain"
        );

        let ipv6 = dns.resolve_v6("ipv6.reverse.test").expect("should resolve");
        let domain6 = dns.reverse_lookup(&IpAddr::V6(ipv6));
        assert_eq!(
            domain6.as_deref(),
            Some("ipv6.reverse.test"),
            "IPv6 reverse lookup should return the original domain"
        );

        let unknown = dns.reverse_lookup(&IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)));
        assert_eq!(unknown, None, "unknown IP should return None");

        let unknown_v6 =
            dns.reverse_lookup(&IpAddr::V6("2001:db8::1".parse().unwrap()));
        assert_eq!(unknown_v6, None, "unknown IPv6 should return None");
    })
    .await
    .expect("test timed out");
}

#[tokio::test]
async fn test_fakeipdns_reverse_after_reopen() {
    tokio::time::timeout(TEST_TIMEOUT, async {
        let temp_dir = TempDir::new().expect("failed to create temp dir");
        let cache_tag = "fk_reverse_reopen";
        let dns_tag = "fakeip_rev_reopen";
        setup_cache_for_tag(&temp_dir, cache_tag, 100);

        let dns1 = make_fakeipdns(dns_tag, cache_tag, "198.18.0.0/15", None);

        let domains: Vec<&str> = vec!["alpha.test", "beta.test", "gamma.test"];
        let mut ip_map: Vec<(String, Ipv4Addr)> = Vec::new();

        for domain in &domains {
            let ip = dns1.resolve_v4(domain).expect("should resolve");
            ip_map.push((domain.to_string(), ip));
        }
        let _ = dns1.cache.set("fakeip_ipv4_cursor_index", &dns1.ipv4_cursor.load(std::sync::atomic::Ordering::Relaxed).to_string());
        let _ = dns1.cache.set("fakeip_ipv6_cursor_index", &dns1.ipv6_cursor.load(std::sync::atomic::Ordering::Relaxed).to_string());
        drop(dns1);

        let dns2 = make_fakeipdns(dns_tag, cache_tag, "198.18.0.0/15", None);

        for (domain, ip) in &ip_map {
            let reversed = dns2.reverse_lookup(&IpAddr::V4(*ip));
            assert_eq!(
                reversed.as_deref(),
                Some(domain.as_str()),
                "reverse lookup after reopen should still work for {domain}"
            );
        }

        let new_ip = dns2.resolve_v4("delta.test").expect("should resolve new");
        let reversed_new = dns2.reverse_lookup(&IpAddr::V4(new_ip));
        assert_eq!(
            reversed_new.as_deref(),
            Some("delta.test"),
            "reverse lookup should work for newly allocated IP"
        );
    })
    .await
    .expect("test timed out");
}

#[tokio::test]
async fn test_fakeipdns_full_roundtrip_v4_and_v6() {
    tokio::time::timeout(TEST_TIMEOUT, async {
        let temp_dir = TempDir::new().expect("failed to create temp dir");
        let cache_tag = "fk_full_roundtrip";
        let dns_tag = "fakeip_full";
        setup_cache_for_tag(&temp_dir, cache_tag, 100);

        let dns1 =
            make_fakeipdns(dns_tag, cache_tag, "198.18.0.0/15", Some("fc00::/18"));

        let v4_domain = "v4.full.test";
        let v6_domain = "v6.full.test";

        let ip_v4 = dns1.resolve_v4(v4_domain).expect("v4 resolve");
        let ip_v6 = dns1.resolve_v6(v6_domain).expect("v6 resolve");

        assert!(dns1.ipv4_cidr.contains(&ip_v4));
        assert!(dns1.ipv6_cidr.contains(&ip_v6));

        assert_eq!(
            dns1.reverse_lookup(&IpAddr::V4(ip_v4)).as_deref(),
            Some(v4_domain)
        );
        assert_eq!(
            dns1.reverse_lookup(&IpAddr::V6(ip_v6)).as_deref(),
            Some(v6_domain)
        );

        let _ = dns1.cache.set("fakeip_ipv4_cursor_index", &dns1.ipv4_cursor.load(std::sync::atomic::Ordering::Relaxed).to_string());
        let _ = dns1.cache.set("fakeip_ipv6_cursor_index", &dns1.ipv6_cursor.load(std::sync::atomic::Ordering::Relaxed).to_string());
        drop(dns1);

        let dns2 =
            make_fakeipdns(dns_tag, cache_tag, "198.18.0.0/15", Some("fc00::/18"));

        assert_eq!(
            dns2.resolve_v4(v4_domain).expect("v4 from cache"),
            ip_v4,
            "v4 cache should survive reopen"
        );
        assert_eq!(
            dns2.resolve_v6(v6_domain).expect("v6 from cache"),
            ip_v6,
            "v6 cache should survive reopen"
        );

        assert_eq!(
            dns2.reverse_lookup(&IpAddr::V4(ip_v4)).as_deref(),
            Some(v4_domain),
            "v4 reverse should survive reopen"
        );
        assert_eq!(
            dns2.reverse_lookup(&IpAddr::V6(ip_v6)).as_deref(),
            Some(v6_domain),
            "v6 reverse should survive reopen"
        );

        let new_v4 = dns2.resolve_v4("new.v4.full.test").expect("new v4");
        assert_ne!(new_v4, ip_v4, "new v4 should not collide with cached v4");
        assert_eq!(
            dns2.reverse_lookup(&IpAddr::V4(new_v4)).as_deref(),
            Some("new.v4.full.test")
        );

        let new_v6 = dns2.resolve_v6("new.v6.full.test").expect("new v6");
        assert_ne!(new_v6, ip_v6, "new v6 should not collide with cached v6");
        assert_eq!(
            dns2.reverse_lookup(&IpAddr::V6(new_v6)).as_deref(),
            Some("new.v6.full.test")
        );
    })
    .await
    .expect("test timed out");
}

#[tokio::test]
async fn test_fakeipdns_anydns_reverse_trait() {
    tokio::time::timeout(TEST_TIMEOUT, async {
        let temp_dir = TempDir::new().expect("failed to create temp dir");
        let cache_tag = "fk_anydns_rev";
        setup_cache_for_tag(&temp_dir, cache_tag, 100);

        let dns = make_fakeipdns("test", cache_tag, "198.18.0.0/15", None);

        let ip = dns.lookup_ipv4("trait.rev.test").await.unwrap().expect("should resolve");
        let domain = dns.reverse(&IpAddr::V4(ip)).await;
        assert_eq!(domain.as_deref(), Some("trait.rev.test"));

        let unknown = dns.reverse(&IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))).await;
        assert_eq!(unknown, None);
    })
    .await
    .expect("test timed out");
}
