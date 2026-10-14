use anyhow::{Context, Result, bail};
use dashmap::DashMap;
use redb::{
    Database, Durability, ReadableDatabase, ReadableTable, TableDefinition, TableError,
    WriteTransaction,
};
use serde::{Serialize, de::DeserializeOwned};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::RecvTimeoutError;
use std::sync::{Arc, LazyLock, Once};
use std::time::Duration;
use tracing::warn;

static REDB_CACHE: LazyLock<DashMap<PathBuf, Arc<SharedDb>>> = LazyLock::new(DashMap::new);

pub const DEFAULT_MEMORY_SIZE_MB: usize = 1;

const OPEN_TIMEOUT: Duration = Duration::from_secs(10);

/// Cache writes commit without fsync (`Durability::None`); this is how often the
/// accumulated writes are made durable. A crash loses at most this much cache.
const FLUSH_INTERVAL: Duration = Duration::from_secs(500);

static FLUSHER: Once = Once::new();

/// A database plus whether it has non-durable commits that still need an fsync.
struct SharedDb {
    db: Database,
    dirty: AtomicBool,
}

impl SharedDb {
    fn begin_cache_write(&self) -> Result<WriteTransaction> {
        let mut txn = self.db.begin_write()?;
        txn.set_durability(Durability::None)?;
        Ok(txn)
    }

    fn commit_cache_write(&self, txn: WriteTransaction) -> Result<()> {
        txn.commit()?;
        self.dirty.store(true, Ordering::Release);
        Ok(())
    }

    /// An empty durable commit persists every non-durable commit before it.
    fn flush(&self) -> Result<()> {
        if !self.dirty.swap(false, Ordering::AcqRel) {
            return Ok(());
        }
        let result = self
            .db
            .begin_write()
            .map_err(anyhow::Error::from)
            .and_then(|txn| txn.commit().map_err(anyhow::Error::from));
        if result.is_err() {
            self.dirty.store(true, Ordering::Release);
        }
        result
    }
}

impl Drop for SharedDb {
    fn drop(&mut self) {
        if let Err(e) = self.flush() {
            warn!("failed to flush cache database on close: {e:#}");
        }
    }
}

fn start_flusher() {
    FLUSHER.call_once(|| {
        let spawned = std::thread::Builder::new()
            .name("redb-flush".into())
            .spawn(|| {
                loop {
                    std::thread::sleep(FLUSH_INTERVAL);
                    flush_all();
                }
            });
        if let Err(e) = spawned {
            warn!("failed to start cache flush thread: {e}");
        }
    });
}

fn flush_all() {
    let dbs: Vec<_> = REDB_CACHE
        .iter()
        .map(|entry| entry.value().clone())
        .collect();
    for db in dbs {
        if let Err(e) = db.flush() {
            warn!("failed to flush cache database: {e:#}");
        }
    }
}

pub struct RedbStore {
    db: Arc<SharedDb>,
}

/// Persist pending cache writes and close every database. The last handle to
/// each database flushes it on drop, which also releases its file lock.
pub fn shutdown_redb() {
    flush_all();
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

        let shared = Arc::new(SharedDb {
            db,
            dirty: AtomicBool::new(false),
        });
        REDB_CACHE.insert(key, shared.clone());
        start_flusher();

        Ok(Self { db: shared })
    }

    pub fn set_entry<T: Serialize>(&self, table_name: &str, key: &str, value: &T) -> Result<()> {
        let write_txn = self.db.begin_cache_write()?;
        {
            let def = TableDefinition::<&str, &[u8]>::new(table_name);
            let mut table = write_txn.open_table(def)?;
            let bytes = serde_json::to_vec(value)?;
            table.insert(key, bytes.as_slice())?;
        }
        self.db.commit_cache_write(write_txn)
    }

    pub fn get_entry<T: DeserializeOwned>(&self, table_name: &str, key: &str) -> Result<Option<T>> {
        let read_txn = self.db.db.begin_read()?;
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
        let write_txn = self.db.begin_cache_write()?;
        let value = {
            let def = TableDefinition::<&str, &[u8]>::new(table_name);
            let mut table = write_txn.open_table(def)?;
            match table.remove(key)? {
                Some(guard) => Some(serde_json::from_slice(guard.value())?),
                None => None,
            }
        };
        self.db.commit_cache_write(write_txn)?;
        Ok(value)
    }

    pub fn get_all_entries<T: DeserializeOwned>(
        &self,
        table_name: &str,
    ) -> Result<Vec<(String, T)>> {
        let read_txn = self.db.db.begin_read()?;
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

    /// Merges a batch into the table in a single write transaction, so the whole batch costs one
    /// commit instead of one per entry.
    pub fn merge_entries<T, F>(
        &self,
        table_name: &str,
        items: Vec<(String, T)>,
        merge: F,
    ) -> Result<()>
    where
        T: Serialize + DeserializeOwned,
        F: Fn(&mut T, T),
    {
        if items.is_empty() {
            return Ok(());
        }
        let write_txn = self.db.begin_cache_write()?;
        {
            let def = TableDefinition::<&str, &[u8]>::new(table_name);
            let mut table = write_txn.open_table(def)?;
            for (key, value) in items {
                let existing: Option<T> = match table.get(key.as_str())? {
                    Some(guard) => serde_json::from_slice(guard.value()).ok(),
                    None => None,
                };
                let merged = match existing {
                    Some(mut current) => {
                        merge(&mut current, value);
                        current
                    }
                    None => value,
                };
                let bytes = serde_json::to_vec(&merged)?;
                table.insert(key.as_str(), bytes.as_slice())?;
            }
        }
        self.db.commit_cache_write(write_txn)?;
        Ok(())
    }

    /// Reads and removes every entry in one write transaction. Undecodable entries are removed
    /// too, otherwise a single corrupt row would make the table grow forever.
    pub fn drain_entries<T: DeserializeOwned>(&self, table_name: &str) -> Result<Vec<(String, T)>> {
        let write_txn = self.db.begin_cache_write()?;
        let entries = {
            let def = TableDefinition::<&str, &[u8]>::new(table_name);
            let mut table = write_txn.open_table(def)?;
            let mut keys = Vec::new();
            let mut entries = Vec::new();
            for item in table.iter()? {
                let (key, value) = item?;
                let key = key.value().to_owned();
                if let Ok(value) = serde_json::from_slice::<T>(value.value()) {
                    entries.push((key.clone(), value));
                }
                keys.push(key);
            }
            for key in &keys {
                table.remove(key.as_str())?;
            }
            entries
        };
        self.db.commit_cache_write(write_txn)?;
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

#[cfg(test)]
mod tests {
    use super::*;

    const TABLE: &str = "flush_test";

    fn read_back(path: &Path, key: &str) -> Option<String> {
        let db = Database::open(path).unwrap();
        let read_txn = db.begin_read().unwrap();
        let table = read_txn
            .open_table(TableDefinition::<&str, &[u8]>::new(TABLE))
            .unwrap();
        table
            .get(key)
            .unwrap()
            .map(|guard| serde_json::from_slice(guard.value()).unwrap())
    }

    #[test]
    fn cache_writes_are_marked_dirty_until_flushed() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("dirty.db");
        let store = RedbStore::with_cache_size(path.to_string_lossy().into_owned(), 1).unwrap();

        store.set_entry(TABLE, "k", &"v".to_string()).unwrap();
        assert!(store.db.dirty.load(Ordering::Acquire));
        assert_eq!(
            store.get_entry::<String>(TABLE, "k").unwrap().as_deref(),
            Some("v")
        );

        store.db.flush().unwrap();
        assert!(!store.db.dirty.load(Ordering::Acquire));

        REDB_CACHE.remove(&resolve_db_path(&path.to_string_lossy()));
        drop(store);
        assert_eq!(read_back(&path, "k").as_deref(), Some("v"));
    }

    /// Simulates a crash: the database is never closed, and only what is on
    /// disk at that moment survives (read from a copy of the file).
    fn crash_and_read(store: RedbStore, path: &Path, key: &str) -> Option<String> {
        REDB_CACHE.remove(&resolve_db_path(&path.to_string_lossy()));
        std::mem::forget(store);
        let copy = path.with_extension("crashed");
        std::fs::copy(path, &copy).unwrap();
        read_back(&copy, key)
    }

    #[test]
    fn unflushed_cache_writes_are_lost_on_crash() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("lost.db");
        let store = RedbStore::with_cache_size(path.to_string_lossy().into_owned(), 1).unwrap();
        store.set_entry(TABLE, "durable", &"1".to_string()).unwrap();
        store.db.flush().unwrap();

        store.set_entry(TABLE, "pending", &"2".to_string()).unwrap();

        assert_eq!(crash_and_read(store, &path, "pending"), None);
        assert_eq!(
            read_back(&path.with_extension("crashed"), "durable").as_deref(),
            Some("1")
        );
    }

    #[test]
    fn flushed_cache_writes_survive_a_crash() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("kept.db");
        let store = RedbStore::with_cache_size(path.to_string_lossy().into_owned(), 1).unwrap();
        store.set_entry(TABLE, "a", &"1".to_string()).unwrap();
        store.set_entry(TABLE, "b", &"2".to_string()).unwrap();
        store.delete_entry::<String>(TABLE, "a").unwrap();

        flush_all();

        assert_eq!(crash_and_read(store, &path, "b").as_deref(), Some("2"));
        assert_eq!(read_back(&path.with_extension("crashed"), "a"), None);
    }
}
