use crate::cache::Cache;
use crate::config::Config;
use crate::config::GeoipDBConfig;
use crate::proxy::outbound::{AnyOutbound, get_default_outbound, get_outbound_by_tag};
use crate::utils::format_duration;
use crate::utils::http_outbound::request_via_outbound_with_dns;
use crate::utils::now;
use crate::utils::now_timestamp;
use crate::utils::shutdown;
use crate::utils::time::parse_duration;
use anyhow::Context;
use anyhow::Result;
use anyhow::bail;
use dashmap::DashMap;
use hyper::http::Method;
use memmap2::Mmap;
use std::path::Path;
use std::sync::{Arc, LazyLock};
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::sync::Mutex;
use tracing::{error, info, warn};

pub type GeoIpReader = maxminddb::Reader<Mmap>;
pub type SharedGeoIpReader = Mutex<Arc<Option<GeoIpReader>>>;

pub static GEOIP_DB_MAP: LazyLock<DashMap<String, Arc<GeoipDB>>> = LazyLock::new(DashMap::new);

pub async fn init_geoip_db(cfg: &Config) -> Result<()> {
    for (tag, db_cfg) in cfg.router.geoip_db.iter() {
        let name_clone = tag.clone();
        let db = Arc::new(GeoipDB::new(name_clone.clone(), db_cfg)?);
        db.ensure_db().await?;
        db.spawn_updater();
        GEOIP_DB_MAP.insert(name_clone, db);
    }
    Ok(())
}

pub fn shutdown_geoip_db() {
    GEOIP_DB_MAP.clear();
}

pub fn get_geoip_db_by_tag(tag: &str) -> Result<Arc<GeoipDB>> {
    match GEOIP_DB_MAP.get(tag) {
        Some(r) => Ok(r.clone()),
        None => bail!("can not find db: {}", tag),
    }
}

pub fn load_db_file(path: &str) -> Result<Arc<Option<GeoIpReader>>> {
    if !Path::new(path).exists() {
        bail!("path does not exists.")
    }
    let reader = unsafe { maxminddb::Reader::open_mmap(&path) }
        .context(format!("failed to load db:{}", path))?;
    return Ok(Arc::new(Some(reader)));
}

pub struct GeoipDB {
    pub tag: String,
    pub path: String,
    pub url: Option<String>,
    pub cache: Option<Arc<Cache<u64>>>,
    pub download_outbound: Arc<dyn AnyOutbound>,
    pub update_interval: Duration,
    pub reader: SharedGeoIpReader,
}

impl GeoipDB {
    pub fn new(tag: String, cfg: &GeoipDBConfig) -> Result<Self> {
        let path = cfg.path.clone();
        if path.is_empty() {
            bail!("geoip_db '{}' requires a path", tag);
        }
        let update_interval =
            parse_duration(&cfg.update_interval.clone().unwrap_or("48h".to_string()));
        let mut cache = None;
        if let Some(cache_name) = cfg.cache.clone() {
            cache = Some(Arc::new(
                Cache::new_with_tag(&cache_name, "geoip_db".to_string())
                    .map_err(|e| anyhow::anyhow!("can not find cache tag: {:?}", e))?,
            ));
        }

        let mut download_outbound = get_default_outbound();
        if let Some(out) = cfg.download_outbound.clone() {
            download_outbound = get_outbound_by_tag(&out);
        }

        Ok(Self {
            tag,
            path,
            update_interval,
            download_outbound,
            cache,
            url: cfg.url.clone(),
            reader: Mutex::new(Arc::new(None)),
        })
    }

    pub async fn ensure_db(&self) -> Result<bool> {
        let start = now();
        match load_db_file(&self.path) {
            Ok(reader) => {
                *self.reader.lock().await = reader;
            }
            Err(e) => {
                if self.url.is_some() {
                    warn!(
                        "GeoIP db '{}' at {} is missing or invalid: {}; downloading it now",
                        self.tag, self.path, e
                    );
                    self.update_db().await?;
                }
            }
        }

        info!(
            "Loaded GeoIP db '{}' from {} (cost: {})",
            self.tag,
            self.path,
            format_duration(start.elapsed())
        );
        Ok(true)
    }

    pub async fn lookup(&self, ip: std::net::IpAddr) -> Result<String> {
        let start = now();

        let shared_reader = self.reader.lock().await.clone();
        let reader = shared_reader
            .as_ref()
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("GeoIP db '{}' is not loaded", self.tag))?;

        let result = match reader
            .lookup(ip)
            .and_then(|r| r.decode::<maxminddb::geoip2::Country>())
        {
            Ok(Some(country)) => country
                .country
                .iso_code
                .map(|s| s.to_string())
                .unwrap_or_else(|| "unknown".to_string()),
            Ok(None) => "unknown".to_string(),
            Err(e) => {
                bail!(
                    "GeoIP lookup failed for IP {} (took {:?}): {}",
                    ip,
                    start.elapsed(),
                    e
                );
            }
        };

        info!(
            "GeoIP result for {}: {} (cost: {})",
            ip,
            result,
            format_duration(start.elapsed())
        );

        Ok(result)
    }

    pub async fn close_reader(&self) -> Result<()> {
        let mut lock = self.reader.lock().await;
        *lock = Arc::new(None); // 用一个新的 Arc(None) 替换旧的
        Ok(())
    }

    fn record_update_success(&self) {
        if let (Some(cache), Some(url)) = (&self.cache, &self.url) {
            let key = format!("tag:{},url:{},path:{}", self.tag, url, self.path);
            let now_secs = now_timestamp();
            if let Err(e) = cache.set(&key, &now_secs) {
                warn!(
                    "Failed to persist GeoIP '{}' update timestamp: {}",
                    self.tag, e
                );
            }
        }
        info!("GeoIP update for '{}' succeeded", self.tag);
    }

    fn next_update_delay(&self) -> Duration {
        let Some(cache) = &self.cache else {
            return self.update_interval;
        };

        let key = self.get_key();

        match cache.get(&key) {
            Ok(Some((last_update, _))) => {
                let elapsed = Duration::from_secs(now_timestamp().saturating_sub(last_update));
                self.update_interval.saturating_sub(elapsed)
            }
            Ok(None) => {
                let now_secs = now_timestamp();
                if let Err(e) = cache.set(&key, &now_secs) {
                    warn!(
                        "Failed to persist initial GeoIP '{}' update timestamp: {}",
                        self.tag, e
                    );
                }
                self.update_interval
            }
            Err(e) => {
                warn!(
                    "Failed to read GeoIP '{}' update timestamp: {}",
                    self.tag, e
                );
                self.update_interval
            }
        }
    }

    fn get_key(&self) -> String {
        return format!("tag:{},url:{:?},path:{}", self.tag, self.url, self.path);
    }

    pub async fn update_db(&self) -> Result<()> {
        if self.url.is_none() {
            bail!("missing url for remote db")
        }
        self.record_update_success();
        let tmp_path = format!("{}.tmp", self.path);

        if let Err(e) = self.download_db(&tmp_path).await {
            let _ = tokio::fs::remove_file(&tmp_path).await;
            return Err(e);
        }

        info!("Verifying downloaded GeoIP db '{}'...", self.tag);
        let reader = match load_db_file(&tmp_path) {
            Ok(reader) => reader,
            Err(e) => {
                let _ = tokio::fs::remove_file(&tmp_path).await;
                bail!("Downloaded GeoIP db '{}' is invalid: {}", self.tag, e);
            }
        };
        drop(reader);

        if let Err(e) = tokio::fs::rename(&tmp_path, &self.path).await {
            let _ = tokio::fs::remove_file(&tmp_path).await;
            return Err(e).context(format!(
                "failed to replace GeoIP db '{}' at {}",
                self.tag, self.path
            ));
        }

        let reader = load_db_file(&self.path)?;
        *self.reader.lock().await = reader;
        Ok(())
    }

    pub async fn download_db(&self, path: &str) -> Result<()> {
        let url = self
            .url
            .as_ref()
            .context(format!("GeoIP db '{}' has no download url", self.tag))?;

        info!(
            "Downloading GeoIP db '{}' from {} via {}",
            self.tag,
            url,
            self.download_outbound.tag()
        );

        let response = request_via_outbound_with_dns(
            self.download_outbound.clone(),
            self.download_outbound.dns_server_name(),
            Method::GET,
            url,
            std::time::Duration::from_secs(60),
            5,
            None,
        )
        .await?;

        if !response.status.is_success() {
            bail!(
                "HTTP Error downloading GeoIP db '{}': {}",
                self.tag,
                response.status
            );
        }

        let mut file = tokio::fs::File::create(path).await?;
        file.write_all(&response.body).await?;
        file.flush().await?;
        file.sync_all().await?;

        if response.body.is_empty() {
            bail!("Downloaded GeoIP db '{}' is empty", self.tag);
        }

        info!("Downloaded GeoIP db '{}' to {}", self.tag, path);
        Ok(())
    }

    pub fn spawn_updater(self: &Arc<Self>) {
        if self.url.is_none() {
            return;
        }

        if self.update_interval.is_zero() {
            warn!(
                "Invalid update_interval for GeoIP db '{}', updater not started",
                self.tag
            );
            return;
        }

        let db = Arc::clone(self);

        shutdown::spawn(async move {
            let mut wait = db.next_update_delay();

            loop {
                if !wait.is_zero() {
                    info!(
                        "Next GeoIP db '{}' update in {}",
                        db.tag,
                        format_duration(wait)
                    );
                    tokio::time::sleep(wait).await;
                }

                info!("Starting GeoIP update for '{}'...", db.tag);
                if let Err(e) = db.update_db().await {
                    error!("Failed to update GeoIP db '{}': {}", db.tag, e);
                }
                wait = db.update_interval;
            }
        });
    }
}
