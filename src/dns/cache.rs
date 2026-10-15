//! Response cache for one DNS server.
//!
//! A bounded in-memory map sits in front of the redb table, so a hit costs a hash lookup
//! instead of a database read. The table stores each response as raw bytes behind an
//! 8-byte expiry. Concurrent misses for the same question share one upstream query.

use crate::cache::RawCache;
use crate::utils::now_timestamp;
use anyhow::Result;
use dashmap::DashMap;
use std::sync::Arc;
use tokio::sync::watch;

/// Upper bound on responses kept in memory. When full, expired entries are dropped first;
/// if that is not enough the map is emptied and refills from the table.
const MEMORY_ENTRIES: usize = 2048;

const EXPIRY_LEN: usize = 8;

/// The result of an upstream query, as shared with the queries that waited for it:
/// the response packet, or the error message.
pub type Outcome = Result<Arc<[u8]>, Arc<str>>;

#[derive(Clone)]
struct Entry {
    response: Arc<[u8]>,
    expiry: u64,
}

pub struct DnsCache {
    memory: DashMap<String, Entry>,
    disk: RawCache,
    inflight: DashMap<String, watch::Sender<Option<Outcome>>>,
}

/// Whether this caller sends the upstream query or waits for someone else's.
pub enum Flight<'a> {
    Leader(FlightLeader<'a>),
    Follower(watch::Receiver<Option<Outcome>>),
}

/// Held by the caller that sends the query. Dropping it without [`FlightLeader::finish`]
/// (an error before the query, or a cancelled task) releases the followers, which then
/// query on their own.
pub struct FlightLeader<'a> {
    cache: &'a DnsCache,
    key: &'a str,
}

impl FlightLeader<'_> {
    /// Whether anyone is waiting for this query's result.
    pub fn has_followers(&self) -> bool {
        self.cache
            .inflight
            .get(self.key)
            .is_some_and(|tx| tx.receiver_count() > 0)
    }

    pub fn finish(self, outcome: Outcome) {
        if let Some((_, tx)) = self.cache.inflight.remove(self.key) {
            tx.send_replace(Some(outcome));
        }
        std::mem::forget(self);
    }
}

impl Drop for FlightLeader<'_> {
    fn drop(&mut self) {
        self.cache.inflight.remove(self.key);
    }
}

impl DnsCache {
    pub fn new_with_tag(cache_tag: &str, dns_tag: &str) -> Result<Self> {
        let disk = RawCache::new_with_tag(cache_tag, format!("{dns_tag}_bytes_v2"))?;
        // Responses used to be stored JSON-encoded in this table; they are only a cache.
        if let Err(e) = disk.delete_table(&format!("{dns_tag}_bytes")) {
            tracing::debug!("failed to drop old dns cache table for {dns_tag}: {e:#}");
        }
        Ok(Self::with_disk(disk))
    }

    fn with_disk(disk: RawCache) -> Self {
        Self {
            memory: DashMap::new(),
            disk,
            inflight: DashMap::new(),
        }
    }

    /// The cached response for `key` and its expiry time, while it is still fresh.
    pub fn get(&self, key: &str) -> Option<(Arc<[u8]>, u64)> {
        let now = now_timestamp();
        if let Some(entry) = self.memory.get(key) {
            if entry.expiry > now {
                return Some((entry.response.clone(), entry.expiry));
            }
        }
        self.memory.remove_if(key, |_, entry| entry.expiry <= now);

        match self.disk.get(key) {
            Ok(Some(raw)) if raw.len() > EXPIRY_LEN => {
                let expiry = u64::from_be_bytes(raw[..EXPIRY_LEN].try_into().unwrap());
                if expiry > now {
                    let response: Arc<[u8]> = raw[EXPIRY_LEN..].into();
                    self.remember(key, response.clone(), expiry, now);
                    return Some((response, expiry));
                }
                let _ = self.disk.delete(key);
            }
            Ok(Some(_)) => {
                let _ = self.disk.delete(key);
            }
            Ok(None) => {}
            Err(e) => tracing::debug!("dns cache read failed for {key}: {e:#}"),
        }
        None
    }

    pub fn set(&self, key: &str, response: &[u8], ttl: u64) -> Result<()> {
        let now = now_timestamp();
        let expiry = now + ttl;
        self.remember(key, response.into(), expiry, now);

        let mut raw = Vec::with_capacity(EXPIRY_LEN + response.len());
        raw.extend_from_slice(&expiry.to_be_bytes());
        raw.extend_from_slice(response);
        self.disk.set(key, &raw)
    }

    fn remember(&self, key: &str, response: Arc<[u8]>, expiry: u64, now: u64) {
        if self.memory.len() >= MEMORY_ENTRIES && !self.memory.contains_key(key) {
            self.memory.retain(|_, entry| entry.expiry > now);
            if self.memory.len() >= MEMORY_ENTRIES {
                self.memory.clear();
            }
        }
        self.memory
            .insert(key.to_string(), Entry { response, expiry });
    }

    /// Joins the in-flight query for `key`, or becomes the one that sends it.
    pub fn join<'a>(&'a self, key: &'a str) -> Flight<'a> {
        match self.inflight.entry(key.to_string()) {
            dashmap::Entry::Occupied(entry) => Flight::Follower(entry.get().subscribe()),
            dashmap::Entry::Vacant(entry) => {
                entry.insert(watch::channel(None).0);
                Flight::Leader(FlightLeader { cache: self, key })
            }
        }
    }
}

/// Waits for the leader's outcome. `None` if the leader gave up without one.
pub async fn follow(mut rx: watch::Receiver<Option<Outcome>>) -> Option<Outcome> {
    rx.wait_for(Option::is_some)
        .await
        .ok()
        .and_then(|outcome| outcome.clone())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cache(dir: &tempfile::TempDir) -> DnsCache {
        let path = dir.path().join("dns.db").to_string_lossy().into_owned();
        DnsCache::with_disk(RawCache::new(path, "dns_bytes_v2".to_string(), 1).unwrap())
    }

    #[test]
    fn hits_come_from_memory_then_disk() {
        let dir = tempfile::tempdir().unwrap();
        let dns = cache(&dir);
        dns.set("k", b"response", 60).unwrap();

        let (response, expiry) = dns.get("k").unwrap();
        assert_eq!(&response[..], b"response");
        assert!(expiry > now_timestamp());

        // A fresh process only has the table.
        dns.memory.clear();
        let (response, _) = dns.get("k").unwrap();
        assert_eq!(&response[..], b"response");
        assert!(dns.memory.contains_key("k"), "disk hit is promoted");

        assert!(dns.get("missing").is_none());
    }

    #[test]
    fn expired_entries_are_dropped() {
        let dir = tempfile::tempdir().unwrap();
        let dns = cache(&dir);
        dns.set("k", b"response", 0).unwrap();
        assert!(dns.get("k").is_none());
        assert!(!dns.memory.contains_key("k"));
        assert!(dns.disk.get("k").unwrap().is_none());
    }

    #[test]
    fn memory_stays_bounded() {
        let dir = tempfile::tempdir().unwrap();
        let dns = cache(&dir);
        let now = now_timestamp();
        for i in 0..MEMORY_ENTRIES + 10 {
            dns.remember(&i.to_string(), Arc::from(&b"r"[..]), now + 60, now);
        }
        assert!(dns.memory.len() <= MEMORY_ENTRIES);
    }

    #[tokio::test]
    async fn followers_share_the_leaders_outcome() {
        let dir = tempfile::tempdir().unwrap();
        let dns = cache(&dir);

        let Flight::Leader(leader) = dns.join("q") else {
            panic!("first caller leads");
        };
        let Flight::Follower(rx) = dns.join("q") else {
            panic!("second caller follows");
        };
        assert!(leader.has_followers());
        let follower = tokio::spawn(follow(rx));
        leader.finish(Ok(Arc::from(&b"answer"[..])));
        let outcome = follower.await.unwrap().unwrap().unwrap();
        assert_eq!(&outcome[..], b"answer");

        // A leader that gives up releases its followers empty-handed.
        let Flight::Leader(leader) = dns.join("q") else {
            panic!("flight was cleared");
        };
        let Flight::Follower(rx) = dns.join("q") else {
            panic!("second caller follows");
        };
        drop(leader);
        assert!(follow(rx).await.is_none());
        assert!(matches!(dns.join("q"), Flight::Leader(_)));
    }
}
