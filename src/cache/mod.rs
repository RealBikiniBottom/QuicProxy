use dashmap::DashMap;
use lru::LruCache;
use redb::Error;
use redb_store::RedbStore;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::num::NonZeroUsize;
use std::sync::{LazyLock, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::config::Config;
use crate::utils::now_timestamp;

mod redb_store;

static CACHE_MAP: LazyLock<DashMap<String, AnyCache>> = LazyLock::new(DashMap::new);

struct AnyCache {
    memory_size: u64,
    path: Option<String>,
}

/// 关闭所有缓存数据库，释放文件锁，避免进程重启时卡死。
pub fn shutdown_cache() {
    redb_store::shutdown_redb();
}

pub fn init_cache(cfg: &Config) -> anyhow::Result<()> {
    for (name, item) in cfg.cache.iter() {
        let cache_entry = AnyCache {
            memory_size: item.memory_size,
            path: item.path.clone(),
        };

        CACHE_MAP.insert(name.clone(), cache_entry);
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum CacheSource {
    Memory,
    Disk,
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
    pub fn new(
        path: Option<String>,
        table_name: String,
        memory_cache_size: usize,
    ) -> Result<Self, Error> {
        Ok(Self {
            inner: Cache::new(path, table_name, memory_cache_size)?,
        })
    }

    pub fn new_with_tag(tag: &str, table_name: String) -> Result<Self, Error> {
        Ok(Self {
            inner: Cache::new_with_tag(tag, table_name)?,
        })
    }

    pub fn get(&self, key: &str) -> Result<Option<(T, u64, CacheSource)>, Error> {
        let now = now_timestamp();

        match self.inner.get(key)? {
            Some((expiring_val, source)) => {
                if expiring_val.expiry > now {
                    Ok(Some((expiring_val.value, expiring_val.expiry, source)))
                } else {
                    let _ = self.inner.delete(key)?;
                    Ok(None)
                }
            }
            None => Ok(None),
        }
    }

    pub fn set(&self, key: &str, value: &T, ttl: u64) -> Result<(), Error> {
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

    pub fn delete(&self, key: &str) -> Result<Option<T>, Error> {
        Ok(self.inner.delete(key)?.map(|v| v.value))
    }

    pub fn list(&self) -> Result<Vec<(String, T)>, Error> {
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
    disk_db: Option<RedbStore>,
    memory_db: Option<Mutex<LruCache<String, T>>>,
    table_name_for_disk_db: Box<str>,
}

impl<T> Cache<T>
where
    T: Serialize + DeserializeOwned + Send + Sync + Clone + 'static,
{
    pub fn new(
        path: Option<String>,
        table_name: String,
        memory_cache_size: usize,
    ) -> Result<Self, Error> {
        // 修复点：只有在 path 为 Some 时才初始化 RedbStore
        let disk_db = if let Some(p) = path {
            // 此时 p 是 String，String 实现了 AsRef<Path>，符合 RedbStore::new 的要求
            Some(RedbStore::new(p)?)
        } else {
            None
        };

        let memory_db = if memory_cache_size > 0 {
            let cap = NonZeroUsize::new(memory_cache_size).unwrap_or_else(|| {
                tracing::error!("Invalid memory_cache_size: {}", memory_cache_size);
                NonZeroUsize::new(1).unwrap()
            });
            Some(Mutex::new(LruCache::new(cap)))
        } else {
            None
        };

        Ok(Self {
            disk_db,
            memory_db,
            table_name_for_disk_db: table_name.into_boxed_str(),
        })
    }

    pub fn new_with_tag(tag: &str, table_name: String) -> Result<Self, Error> {
        let (path, memory_size) = {
            let guard = CACHE_MAP.get(tag).unwrap_or_else(|| {
                tracing::error!("can not find cache config for tag: {}", tag);
                std::process::exit(1);
            });

            (guard.path.clone(), guard.memory_size)
        };

        Self::new(path, table_name, memory_size as usize)
    }

    pub fn get(&self, key: &str) -> Result<Option<(T, CacheSource)>, Error> {
        if let Some(mem_db) = &self.memory_db {
            let mut map = mem_db.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(val) = map.get(key) {
                return Ok(Some((val.clone(), CacheSource::Memory)));
            }
        }

        if let Some(db) = &self.disk_db {
            if let Some(val) = db.get_entry::<T>(&self.table_name_for_disk_db, key)? {
                if let Some(mem_db) = &self.memory_db {
                    let mut map = mem_db.lock().unwrap_or_else(|e| e.into_inner());
                    map.put(key.to_string(), val.clone());
                }
                return Ok(Some((val, CacheSource::Disk)));
            }
        }

        Ok(None)
    }

    pub fn delete(&self, key: &str) -> Result<Option<T>, Error> {
        let mem_res = if let Some(mem_db) = &self.memory_db {
            let mut map = mem_db.lock().unwrap_or_else(|e| e.into_inner());
            map.pop(key)
        } else {
            None
        };

        let db_res = if let Some(db) = &self.disk_db {
            db.delete_entry(&self.table_name_for_disk_db, key)?
        } else {
            None
        };

        if let Some(val) = mem_res {
            Ok(Some(val))
        } else {
            Ok(db_res)
        }
    }

    pub fn set(&self, key: &str, value: &T) -> Result<(), Error> {
        if let Some(mem_db) = &self.memory_db {
            let mut map = mem_db.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(existing) = map.get_mut(key) {
                *existing = value.clone();
            } else {
                map.put(key.to_string(), value.clone());
            }
        }

        if let Some(db) = &self.disk_db {
            db.set_entry(&self.table_name_for_disk_db, key, value)?;
        }
        Ok(())
    }

    pub fn list(&self) -> Result<Vec<(String, T)>, Error> {
        if let Some(db) = &self.disk_db {
            db.get_all_entries(&self.table_name_for_disk_db)
        } else if let Some(mem_db) = &self.memory_db {
            let map = mem_db.lock().unwrap_or_else(|e| e.into_inner());
            let mut result = Vec::with_capacity(map.len());
            result.extend(map.iter().map(|(k, v)| (k.clone(), v.clone())));
            Ok(result)
        } else {
            Ok(Vec::new())
        }
    }
}
