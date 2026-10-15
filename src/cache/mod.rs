use anyhow::{Result, ensure};
use dashmap::DashMap;
use redb_store::RedbStore;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::marker::PhantomData;
use std::sync::LazyLock;

use crate::config::{CacheConfig, Config};
use crate::utils::now_timestamp;

mod redb_store;

pub use redb_store::DEFAULT_MEMORY_SIZE_MB;

/// cache tag -> cache config
static CACHE_MAP: LazyLock<DashMap<String, CacheConfig>> = LazyLock::new(DashMap::new);

/// 关闭所有缓存数据库，释放文件锁，避免进程重启时卡死。
pub fn shutdown_cache() {
    redb_store::shutdown_redb();
}

pub fn init_cache(cfg: &Config) -> Result<()> {
    for (name, item) in cfg.cache.iter() {
        ensure!(
            item.path.is_some(),
            "cache '{name}' must configure `path`: memory-only cache is not supported, \
             redb's built-in page cache keeps hot data in memory"
        );
        CACHE_MAP.insert(name.clone(), item.clone());
    }
    Ok(())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExpiringValue<T> {
    pub value: T,
    pub expiry: u64,
}

pub struct CacheWithExpire<T> {
    inner: Cache<ExpiringValue<T>>,
}

impl<T> CacheWithExpire<T>
where
    T: Serialize + DeserializeOwned + Send + Sync + Clone + 'static,
{
    pub fn new(path: String, table_name: String, memory_size_mb: usize) -> Result<Self> {
        Ok(Self {
            inner: Cache::new(path, table_name, memory_size_mb)?,
        })
    }

    pub fn new_with_tag(tag: &str, table_name: String) -> Result<Self> {
        Ok(Self {
            inner: Cache::new_with_tag(tag, table_name)?,
        })
    }

    pub fn get(&self, key: &str) -> Result<Option<(T, u64)>> {
        let now = now_timestamp();

        match self.inner.get(key)? {
            Some(expiring_val) => {
                if expiring_val.expiry > now {
                    Ok(Some((expiring_val.value, expiring_val.expiry)))
                } else {
                    let _ = self.inner.delete(key)?;
                    Ok(None)
                }
            }
            None => Ok(None),
        }
    }

    pub fn set(&self, key: &str, value: &T, ttl: u64) -> Result<()> {
        let expiry = now_timestamp() + ttl;
        let expiring_val = ExpiringValue {
            value: value.clone(),
            expiry,
        };
        self.inner.set(key, &expiring_val)
    }

    pub fn delete(&self, key: &str) -> Result<Option<T>> {
        Ok(self.inner.delete(key)?.map(|v| v.value))
    }

    pub fn list(&self) -> Result<Vec<(String, T)>> {
        let now = now_timestamp();
        let entries = self.inner.list()?;

        Ok(entries
            .into_iter()
            .filter(|(_, v)| v.expiry > now)
            .map(|(k, v)| (k, v.value))
            .collect())
    }

    pub fn inner(&self) -> &Cache<ExpiringValue<T>> {
        &self.inner
    }
}

/// A cache table whose values are stored as raw bytes, without the JSON encoding of
/// [`Cache`]. For byte blobs, where JSON would write every byte as a decimal number.
pub struct RawCache {
    db: RedbStore,
    table_name: Box<str>,
}

impl RawCache {
    pub fn new(path: String, table_name: String, memory_size_mb: usize) -> Result<Self> {
        Ok(Self {
            db: RedbStore::with_cache_size(path, memory_size_mb)?,
            table_name: table_name.into_boxed_str(),
        })
    }

    pub fn new_with_tag(tag: &str, table_name: String) -> Result<Self> {
        let (path, memory_size_mb) = cache_location(tag)?;
        Self::new(path, table_name, memory_size_mb)
    }

    pub fn get(&self, key: &str) -> Result<Option<Vec<u8>>> {
        self.db.get_raw(&self.table_name, key)
    }

    pub fn set(&self, key: &str, value: &[u8]) -> Result<()> {
        self.db.set_raw(&self.table_name, key, value)
    }

    pub fn delete(&self, key: &str) -> Result<()> {
        self.db.delete_raw(&self.table_name, key)
    }

    /// Drops another table in the same database, e.g. one in an older format.
    pub fn delete_table(&self, table_name: &str) -> Result<bool> {
        self.db.delete_table(table_name)
    }
}

/// The database path and page cache size configured for cache `tag`.
fn cache_location(tag: &str) -> Result<(String, usize)> {
    let config = CACHE_MAP
        .get(tag)
        .map(|item| item.value().clone())
        .ok_or_else(|| anyhow::anyhow!("can not find cache config for tag: {tag}"))?;
    let path = config
        .path
        .ok_or_else(|| anyhow::anyhow!("cache '{tag}' must configure `path`"))?;
    Ok((path, config.memory_size_mb))
}

pub struct Cache<T> {
    db: RedbStore,
    table_name_for_disk_db: Box<str>,
    _marker: PhantomData<T>,
}

impl<T> Cache<T>
where
    T: Serialize + DeserializeOwned + Send + Sync + Clone + 'static,
{
    pub fn new(path: String, table_name: String, memory_size_mb: usize) -> Result<Self> {
        Ok(Self {
            db: RedbStore::with_cache_size(path, memory_size_mb)?,
            table_name_for_disk_db: table_name.into_boxed_str(),
            _marker: PhantomData,
        })
    }

    pub fn new_with_tag(tag: &str, table_name: String) -> Result<Self> {
        let (path, memory_size_mb) = cache_location(tag)?;
        Self::new(path, table_name, memory_size_mb)
    }

    pub fn get(&self, key: &str) -> Result<Option<T>> {
        self.db.get_entry::<T>(&self.table_name_for_disk_db, key)
    }

    pub fn delete(&self, key: &str) -> Result<Option<T>> {
        self.db.delete_entry::<T>(&self.table_name_for_disk_db, key)
    }

    pub fn set(&self, key: &str, value: &T) -> Result<()> {
        self.db.set_entry(&self.table_name_for_disk_db, key, value)
    }

    pub fn list(&self) -> Result<Vec<(String, T)>> {
        self.db.get_all_entries::<T>(&self.table_name_for_disk_db)
    }

    pub fn merge_many<F>(&self, items: Vec<(String, T)>, merge: F) -> Result<()>
    where
        F: Fn(&mut T, T),
    {
        self.db
            .merge_entries(&self.table_name_for_disk_db, items, merge)
    }

    pub fn drain(&self) -> Result<Vec<(String, T)>> {
        self.db.drain_entries::<T>(&self.table_name_for_disk_db)
    }
}
