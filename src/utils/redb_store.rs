use hashbrown::HashMap;
use redb::{
    Database, Error, ReadableDatabase, ReadableTable, ReadableTableMetadata, TableDefinition,
    TableError,
};
use serde::{Serialize, de::DeserializeOwned};
use std::path::{Path, PathBuf};
use std::sync::{Arc, LazyLock, Mutex};

static DB_CACHE: LazyLock<Mutex<HashMap<PathBuf, Arc<Database>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

pub struct RedbStore {
    db: Arc<Database>,
}

impl RedbStore {
    pub fn new<P: AsRef<Path>>(path: P) -> Result<Self, Error> {
        let path = path.as_ref();

        // Resolve absolute path consistently, regardless of whether file exists
        // Canonicalize parent dir if possible, then join filename
        let key = if let Some(parent) = path.parent() {
            match parent.canonicalize() {
                Ok(p) => p.join(path.file_name().unwrap_or_default()),
                Err(_) => {
                    // Parent doesn't exist or error, fallback to cwd join
                    if let Ok(cwd) = std::env::current_dir() {
                        cwd.join(path)
                    } else {
                        path.to_path_buf()
                    }
                }
            }
        } else {
            // No parent (just filename), use cwd
            if let Ok(cwd) = std::env::current_dir() {
                cwd.join(path)
            } else {
                path.to_path_buf()
            }
        };

        let mut map = DB_CACHE.lock().unwrap_or_else(|e| {
            tracing::error!("DB_CACHE lock poisoned: {:?}", e);
            e.into_inner()
        });

        if let Some(db) = map.get(&key) {
            return Ok(Self { db: db.clone() });
        }

        let db = redb::Builder::new().set_cache_size(0).create(path)?;

        let arc_db = Arc::new(db);
        map.insert(key, arc_db.clone());

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

    pub fn table_entry_count(&self, table_name: &str) -> Result<u64, Error> {
        let read_txn = self.db.begin_read()?;
        let def = TableDefinition::<&str, &[u8]>::new(table_name);
        let table = match read_txn.open_table(def) {
            Ok(t) => t,
            Err(TableError::TableDoesNotExist(_)) => return Ok(0),
            Err(e) => return Err(e.into()),
        };
        Ok(table.len()?)
    }
}
