use anyhow::Result;
use dashmap::DashMap;
use redb_store::RedbStore;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::marker::PhantomData;
use std::sync::LazyLock;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::config::Config;
use crate::utils::now_timestamp;

mod redb_store;

/// cache tag -> redb 数据库文件路径
static CACHE_MAP: LazyLock<DashMap<String, String>> = LazyLock::new(DashMap::new);

/// 关闭所有缓存数据库，释放文件锁，避免进程重启时卡死。
pub fn shutdown_cache() {
    redb_store::shutdown_redb();
}

pub fn init_cache(cfg: &Config) -> Result<()> {
    for (name, item) in cfg.cache.iter() {
        let path = item.path.as_deref().ok_or_else(|| {
            anyhow::anyhow!(
                "cache '{name}' must configure `path`: memory-only cache is not supported, \
                 redb's built-in page cache keeps hot data in memory"
            )
        })?;
        CACHE_MAP.insert(name.clone(), path.to_string());
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
    pub fn new(path: String, table_name: String) -> Result<Self> {
        Ok(Self {
            inner: Cache::new(path, table_name)?,
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
        let expiry = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or_else(|e| {
                tracing::error!("System clock error in CacheWithExpire::set: {}", e);
                0
            })
            + ttl;
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
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or_else(|e| {
                tracing::error!("System clock error in CacheWithExpire::list: {}", e);
                0
            });
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

pub struct Cache<T> {
    db: RedbStore,
    table_name_for_disk_db: Box<str>,
    _marker: PhantomData<T>,
}

impl<T> Cache<T>
where
    T: Serialize + DeserializeOwned + Send + Sync + Clone + 'static,
{
    pub fn new(path: String, table_name: String) -> Result<Self> {
        Ok(Self {
            db: RedbStore::new(path)?,
            table_name_for_disk_db: table_name.into_boxed_str(),
            _marker: PhantomData,
        })
    }

    pub fn new_with_tag(tag: &str, table_name: String) -> Result<Self> {
        let path = CACHE_MAP
            .get(tag)
            .ok_or_else(|| anyhow::anyhow!("can not find cache config for tag: {tag}"))?;

        Self::new(path.value().clone(), table_name)
    }

    pub fn get(&self, key: &str) -> Result<Option<T>> {
        Ok(self.db.get_entry::<T>(&self.table_name_for_disk_db, key)?)
    }

    pub fn delete(&self, key: &str) -> Result<Option<T>> {
        Ok(self
            .db
            .delete_entry::<T>(&self.table_name_for_disk_db, key)?)
    }

    pub fn set(&self, key: &str, value: &T) -> Result<()> {
        self.db
            .set_entry(&self.table_name_for_disk_db, key, value)?;
        Ok(())
    }

    pub fn list(&self) -> Result<Vec<(String, T)>> {
        Ok(self.db.get_all_entries::<T>(&self.table_name_for_disk_db)?)
    }
}
