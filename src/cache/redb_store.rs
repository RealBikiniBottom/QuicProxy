use dashmap::DashMap;
use redb::{Database, Error, ReadableDatabase, ReadableTable, TableDefinition, TableError};
use serde::{Serialize, de::DeserializeOwned};
use std::path::{Path, PathBuf};
use std::sync::{Arc, LazyLock};

pub static REDB_CACHE: LazyLock<DashMap<PathBuf, Arc<Database>>> = LazyLock::new(DashMap::new);

pub struct RedbStore {
    db: Arc<Database>,
}

/// 显式关闭并释放所有 redb 数据库连接。
/// 调用前应确保所有持有 RedbStore 的静态变量（如 DNS_MAP）已被清空。
pub fn shutdown_redb() {
    REDB_CACHE.clear();
}

#[allow(dead_code)]
impl RedbStore {
    pub fn new<P: AsRef<Path>>(path: P) -> Result<Self, Error> {
        let path = path.as_ref();

        // Resolve absolute path consistently, regardless of whether file exists
        // Canonicalize parent dir if possible, then join filename
        let key = if let Some(parent) = path.parent() {
            match parent.canonicalize() {
                Ok(p) => p.join(path.file_name().unwrap_or_default()),
                Err(_) => {
                    if let Ok(cwd) = std::env::current_dir() {
                        cwd.join(path)
                    } else {
                        path.to_path_buf()
                    }
                }
            }
        } else {
            if let Ok(cwd) = std::env::current_dir() {
                cwd.join(path)
            } else {
                path.to_path_buf()
            }
        };
        if let Some(db) = REDB_CACHE.get(&key) {
            return Ok(Self { db: db.clone() });
        }

        // redb 在 Linux 上使用 flock，正常退出时通过 shutdown_cache() → REDB_CACHE.clear()
        // 释放所有 Database 引用，lock 会被释放。以下超时机制仅作为保险：
        // 应对 SIGKILL / panic 在 shutdown 之前 / OOM killer 等极端情况下残留的文件锁。
        let path_owned = key.clone();
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let result = redb::Builder::new().set_cache_size(0)
                .create(&path_owned);
            let _ = tx.send(result);
        });

        let db = match rx.recv_timeout(std::time::Duration::from_secs(3)) {
            Ok(Ok(db)) => db,
            Ok(Err(e)) => return Err(e.into()),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                tracing::warn!(
                    "redb database {:?} is locked by another process. \
                     If no other instance is running, delete this file manually.",
                    path
                );
                return Err(Error::Io(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    format!("redb database {:?} is locked by another process. \
                             If no other instance is running, delete this file manually.", path),
                )));
            }
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                return Err(Error::Io(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "redb worker thread panicked",
                )));
            }
        };

        let arc_db = Arc::new(db);
        REDB_CACHE.insert(key, arc_db.clone());

        Ok(Self { db: arc_db })
    }

    pub fn set_entry<T: Serialize>(
        &self,
        table_name: &str,
        key: &str,
        value: &T,
    ) -> Result<(), Error> {
        let write_txn = self.db.begin_write()?;
        {
            let def = TableDefinition::<&str, &[u8]>::new(table_name);
            let mut table = write_txn.open_table(def)?;
            let bytes = serde_json::to_vec(value).map_err(|e| Error::Corrupted(e.to_string()))?;
            table.insert(key, bytes.as_slice())?;
        }
        write_txn.commit()?;
        Ok(())
    }

    pub fn get_entry<T: DeserializeOwned>(
        &self,
        table_name: &str,
        key: &str,
    ) -> Result<Option<T>, Error> {
        let read_txn = self.db.begin_read()?;
        let def = TableDefinition::<&str, &[u8]>::new(table_name);
        let table = match read_txn.open_table(def) {
            Ok(t) => t,
            Err(TableError::TableDoesNotExist(_)) => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        let result = table.get(key)?;
        match result {
            Some(access_guard) => {
                let val = serde_json::from_slice(access_guard.value())
                    .map_err(|e| Error::Corrupted(e.to_string()))?;
                Ok(Some(val))
            }
            None => Ok(None),
        }
    }

    pub fn delete_entry<T: DeserializeOwned>(
        &self,
        table_name: &str,
        key: &str,
    ) -> Result<Option<T>, Error> {
        let write_txn = self.db.begin_write()?;
        let res = {
            let def = TableDefinition::<&str, &[u8]>::new(table_name);
            let mut table = write_txn.open_table(def)?;
            let v = table.remove(key)?;
            match v {
                Some(guard) => {
                    let val = serde_json::from_slice(guard.value())
                        .map_err(|e| Error::Corrupted(e.to_string()))?;
                    Some(val)
                }
                None => None,
            }
        };
        write_txn.commit()?;
        Ok(res)
    }

    pub fn get_all_entries<T: DeserializeOwned>(
        &self,
        table_name: &str,
    ) -> Result<Vec<(String, T)>, Error> {
        let read_txn = self.db.begin_read()?;
        let def = TableDefinition::<&str, &[u8]>::new(table_name);
        let table = match read_txn.open_table(def) {
            Ok(t) => t,
            Err(TableError::TableDoesNotExist(_)) => return Ok(Vec::new()),
            Err(e) => return Err(e.into()),
        };

        // Pre-allocate with estimated capacity to reduce reallocations
        let mut result = Vec::with_capacity(64);
        for item in table.iter()? {
            let (key, value) = item?;
            // Avoid to_string() - use to_owned() which is clearer for str -> String
            let key_str = key.value().to_owned();
            let val: T = serde_json::from_slice(value.value())
                .map_err(|e| Error::Corrupted(e.to_string()))?;
            result.push((key_str, val));
        }
        // Shrink to fit actual size to free unused memory
        result.shrink_to_fit();
        Ok(result)
    }

    pub fn set_string(&self, table_name: &str, key: &str, value: &str) -> Result<(), Error> {
        let write_txn = self.db.begin_write()?;
        {
            let def = TableDefinition::<&str, &str>::new(table_name);
            let mut table = write_txn.open_table(def)?;
            table.insert(key, value)?;
        }
        write_txn.commit()?;
        Ok(())
    }

    pub fn get_string(&self, table_name: &str, key: &str) -> Result<Option<String>, Error> {
        let read_txn = self.db.begin_read()?;
        let def = TableDefinition::<&str, &str>::new(table_name);
        let table = read_txn.open_table(def)?;
        let result = table.get(key)?;
        match result {
            Some(access_guard) => Ok(Some(access_guard.value().to_string())),
            None => Ok(None),
        }
    }

    pub fn set_bytes(&self, table_name: &str, key: &str, value: &[u8]) -> Result<(), Error> {
        let write_txn = self.db.begin_write()?;
        {
            let def = TableDefinition::<&str, &[u8]>::new(table_name);
            let mut table = write_txn.open_table(def)?;
            table.insert(key, value)?;
        }
        write_txn.commit()?;
        Ok(())
    }

    pub fn get_bytes(&self, table_name: &str, key: &str) -> Result<Option<Vec<u8>>, Error> {
        let read_txn = self.db.begin_read()?;
        let def = TableDefinition::<&str, &[u8]>::new(table_name);
        let table = read_txn.open_table(def)?;
        let result = table.get(key)?;
        match result {
            // Use to_owned() instead of to_vec() for clarity (same performance)
            Some(access_guard) => Ok(Some(access_guard.value().to_owned())),
            None => Ok(None),
        }
    }

    pub fn delete_string(&self, table_name: &str, key: &str) -> Result<Option<String>, Error> {
        let write_txn = self.db.begin_write()?;
        let res = {
            let def = TableDefinition::<&str, &str>::new(table_name);
            let mut table = write_txn.open_table(def)?;
            let v = table.remove(key)?;
            v.map(|guard| guard.value().to_string())
        };
        write_txn.commit()?;
        Ok(res)
    }

    pub fn delete_bytes(&self, table_name: &str, key: &str) -> Result<Option<Vec<u8>>, Error> {
        let write_txn = self.db.begin_write()?;
        let res = {
            let def = TableDefinition::<&str, &[u8]>::new(table_name);
            let mut table = write_txn.open_table(def)?;
            let v = table.remove(key)?;
            v.map(|guard| guard.value().to_owned())
        };
        write_txn.commit()?;
        Ok(res)
    }
}
