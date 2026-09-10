use anyhow::{Context, Result, bail};
use dashmap::DashMap;
use redb::{Database, ReadableDatabase, ReadableTable, TableDefinition, TableError};
use serde::{Serialize, de::DeserializeOwned};
use std::path::{Path, PathBuf};
use std::sync::mpsc::RecvTimeoutError;
use std::sync::{Arc, LazyLock};
use std::time::Duration;

static REDB_CACHE: LazyLock<DashMap<PathBuf, Arc<Database>>> = LazyLock::new(DashMap::new);

pub const DEFAULT_MEMORY_SIZE_MB: usize = 1;

const OPEN_TIMEOUT: Duration = Duration::from_secs(3);

pub struct RedbStore {
    db: Arc<Database>,
}

pub fn shutdown_redb() {
    REDB_CACHE.clear();
}

impl RedbStore {
    pub fn with_cache_size(path: String, memory_size_mb: usize) -> Result<Self> {
        let key = resolve_db_path(&path);
        if let Some(db) = REDB_CACHE.get(&key) {
            return Ok(Self { db: db.clone() });
        }

        // redb holds an exclusive file lock (flock on Linux). shutdown_cache() clears
        // REDB_CACHE so the lock is released on a clean exit; the timeout below only guards
        // against a lock left behind by SIGKILL, a panic before shutdown or the OOM killer.
        let cache_size_bytes = memory_size_mb.saturating_mul(1024 * 1024);
        let (tx, rx) = std::sync::mpsc::channel();
        let db_path = key.clone();
        std::thread::spawn(move || {
            // Page cache budget in bytes; hot pages stay resident in memory.
            let db = redb::Builder::new()
                .set_cache_size(cache_size_bytes)
                .create(&db_path);
            let _ = tx.send(db);
        });

        let db = match rx.recv_timeout(OPEN_TIMEOUT) {
            Ok(Ok(db)) => db,
            Ok(Err(e)) => {
                return Err(e).context(format!("failed to open redb database {path:?}"));
            }
            Err(RecvTimeoutError::Timeout) => bail!(
                "opening redb database {path:?} timed out after {OPEN_TIMEOUT:?}: the file is \
                 locked by another process. If no other instance is running, delete this file \
                 manually."
            ),
            Err(RecvTimeoutError::Disconnected) => bail!("redb worker thread panicked"),
        };

        let arc_db = Arc::new(db);
        REDB_CACHE.insert(key, arc_db.clone());

        Ok(Self { db: arc_db })
    }

    pub fn set_entry<T: Serialize>(&self, table_name: &str, key: &str, value: &T) -> Result<()> {
        let write_txn = self.db.begin_write()?;
        {
            let def = TableDefinition::<&str, &[u8]>::new(table_name);
            let mut table = write_txn.open_table(def)?;
            let bytes = serde_json::to_vec(value)?;
            table.insert(key, bytes.as_slice())?;
        }
        write_txn.commit()?;
        Ok(())
    }

    pub fn get_entry<T: DeserializeOwned>(&self, table_name: &str, key: &str) -> Result<Option<T>> {
        let read_txn = self.db.begin_read()?;
        let def = TableDefinition::<&str, &[u8]>::new(table_name);
        let table = match read_txn.open_table(def) {
            Ok(t) => t,
            Err(TableError::TableDoesNotExist(_)) => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        match table.get(key)? {
            Some(guard) => Ok(Some(serde_json::from_slice(guard.value())?)),
            None => Ok(None),
        }
    }

    pub fn delete_entry<T: DeserializeOwned>(
        &self,
        table_name: &str,
        key: &str,
    ) -> Result<Option<T>> {
        let write_txn = self.db.begin_write()?;
        let value = {
            let def = TableDefinition::<&str, &[u8]>::new(table_name);
            let mut table = write_txn.open_table(def)?;
            match table.remove(key)? {
                Some(guard) => Some(serde_json::from_slice(guard.value())?),
                None => None,
            }
        };
        write_txn.commit()?;
        Ok(value)
    }

    pub fn get_all_entries<T: DeserializeOwned>(
        &self,
        table_name: &str,
    ) -> Result<Vec<(String, T)>> {
        let read_txn = self.db.begin_read()?;
        let def = TableDefinition::<&str, &[u8]>::new(table_name);
        let table = match read_txn.open_table(def) {
            Ok(t) => t,
            Err(TableError::TableDoesNotExist(_)) => return Ok(Vec::new()),
            Err(e) => return Err(e.into()),
        };

        let mut entries = Vec::new();
        for item in table.iter()? {
            let (key, value) = item?;
            entries.push((
                key.value().to_owned(),
                serde_json::from_slice(value.value())?,
            ));
        }
        Ok(entries)
    }
}

/// Resolve `path` against the current directory so that the same database file always maps to
/// the same cache key, no matter how the configured path was spelled.
fn resolve_db_path(path: &str) -> PathBuf {
    let path = Path::new(path);
    match path.parent().and_then(|parent| parent.canonicalize().ok()) {
        Some(parent) => parent.join(path.file_name().unwrap_or_default()),
        None => std::env::current_dir()
            .map(|cwd| cwd.join(path))
            .unwrap_or_else(|_| path.to_path_buf()),
    }
}
