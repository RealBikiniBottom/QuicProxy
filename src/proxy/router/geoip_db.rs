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
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::io::AsyncWriteExt;
use tokio::sync::RwLock;
use tracing::{error, info, warn};

pub type GeoIpReader = maxminddb::Reader<Mmap>;
pub type SharedGeoIpReader = Arc<RwLock<Option<Arc<GeoIpReader>>>>;

pub static GEOIP_DB_MAP: LazyLock<DashMap<String, Arc<GeoipDB>>> = LazyLock::new(DashMap::new);

pub async fn init_geoip_db(cfg: &Config) -> Result<()> {
    for (tag, db_cfg) in cfg.router.geoip_db.iter() {
        let name_clone = tag.clone();
        let db = Arc::new(GeoipDB::new(name_clone.clone(), db_cfg)?);
        db.ensure_db().await?;
        if db.url.is_some() {
            db.spawn_updater();
        }
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
            reader: Arc::new(RwLock::new(None)),
        })
    }

    pub async fn lookup(&self, ip: std::net::IpAddr) -> Option<String> {
        let start = now();

        let lock = self.reader.read().await;
        let reader = lock.as_ref()?;

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
                error!(
                    "GeoIP lookup failed for IP {} (took {:?}): {}",
                    ip,
                    start.elapsed(),
                    e
                );
                return None;
            }
        };

        info!(
            "GeoIP result for {}: {} (cost: {})",
            ip,
            result,
            format_duration(start.elapsed())
        );

        Some(result)
    }

    pub fn validate_db_file(&self) -> bool {
        if !Path::new(&self.path).exists() {
            return false;
        }
        match unsafe { maxminddb::Reader::open_mmap(&self.path) } {
            Ok(_) => true,
            Err(e) => {
                warn!(
                    "GeoIP db '{}' file '{}' is invalid: {}",
                    self.tag, self.path, e
                );
                false
            }
        }
    }

    pub async fn ensure_db(&self) -> Result<()> {
        if self.validate_db_file() {
            let reader = unsafe { maxminddb::Reader::open_mmap(&self.path) }
                .context("failed to open_mmap")?;
            *self.reader.write().await = Some(Arc::new(reader));
            info!("Loaded GeoIP db '{}' from {}", self.tag, self.path);
            return Ok(());
        }

        match &self.url {
            Some(url) => {
                info!(
                    "GeoIP db '{}' not found or invalid at {}, downloading from {}",
                    self.tag, self.path, url
                );
                if Path::new(&self.path).exists() {
                    let _ = tokio::fs::remove_file(&self.path).await;
                }
                self.download_db().await?;
                Ok(())
            }
            None => bail!(
                "Local GeoIP db '{}' not found or invalid at {}",
                self.tag,
                self.path
            ),
        }
    }

    pub async fn download_db(&self) -> Result<()> {
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

        let tmp_path = format!("{}.tmp", self.path);
        let mut file = tokio::fs::File::create(&tmp_path).await?;
        file.write_all(&response.body).await?;
        let bytes_written = response.body.len() as u64;
        file.flush().await?;
        file.sync_all().await?;
        drop(file);

        if bytes_written == 0 {
            let _ = tokio::fs::remove_file(&tmp_path).await;
            bail!("Downloaded GeoIP db '{}' is empty", self.tag);
        }

        info!("Verifying downloaded GeoIP db '{}'...", self.tag);
        match unsafe { maxminddb::Reader::open_mmap(&tmp_path) } {
            Ok(_) => {
                tokio::fs::rename(&tmp_path, &self.path).await?;
                info!(
                    "GeoIP db '{}' updated successfully to {}",
                    self.tag, self.path
                );

                match unsafe { maxminddb::Reader::open_mmap(&self.path) } {
                    Ok(new_reader) => {
                        *self.reader.write().await = Some(Arc::new(new_reader));
                        info!("GeoIP db '{}' reader reloaded.", self.tag);
                        Ok(())
                    }
                    Err(e) => {
                        bail!("Failed to reload GeoIP db '{}' reader: {:?}", self.tag, e)
                    }
                }
            }
            Err(e) => {
                let _ = tokio::fs::remove_file(&tmp_path).await;
                bail!("Downloaded GeoIP db '{}' is invalid: {:?}", self.tag, e)
            }
        }
    }

    pub fn spawn_updater(self: &Arc<Self>) {
        let url = match &self.url {
            Some(u) => u.clone(),
            None => return,
        };

        if self.update_interval.is_zero() {
            warn!(
                "Invalid update_interval for GeoIP db '{}', updater not started",
                self.tag
            );
            return;
        }

        let tag = self.tag.clone();
        let interval = self.update_interval;
        let cache = self.cache.clone();
        let db = self.clone();
        let key = format!("tag:{},url:{},path:{}", self.tag, url, self.path);

        shutdown::spawn(async move {
            loop {
                tokio::time::sleep(interval).await;

                let last_update = cache.as_ref().and_then(|c| c.get(&key).ok());
                if let Some(Some((secs, _))) = last_update {
                    let last = UNIX_EPOCH + Duration::from_secs(secs);
                    if let Ok(elapsed) = SystemTime::now().duration_since(last)
                        && elapsed < interval
                    {
                        let wait = interval - elapsed;
                        info!(
                            "GeoIP db '{}' is up to date. Next update in {}",
                            tag,
                            format_duration(wait)
                        );
                        tokio::time::sleep(wait).await;
                        continue;
                    }
                }

                info!("Starting scheduled GeoIP update for '{}'...", tag);
                match db.download_db().await {
                    Ok(_) => {
                        if let Some(c) = &cache {
                            let now_secs = now_timestamp();
                            if let Err(e) = c.set(&key, &now_secs) {
                                warn!("Failed to persist GeoIP '{}' update timestamp: {}", tag, e);
                            }
                        }
                    }
                    Err(e) => {
                        error!("Failed to update GeoIP db '{}': {}", tag, e);
                    }
                }
            }
        });
    }
}
