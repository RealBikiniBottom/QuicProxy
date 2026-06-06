use crate::cache::CacheWithExpire;
use crate::config::Config;
use crate::config::GeoipConfig;
use crate::dns::AnyDNS;
use crate::dns::get_dns_by_tag;
use crate::dns::resolve_target_base2;
use crate::proxy::TargetAddr;
use crate::utils::format_duration;
use crate::utils::now_timestamp;
use anyhow::{Context, Result, bail};
use dashmap::DashMap;
use memmap2::Mmap;
use std::sync::{Arc, LazyLock};
use std::time::Duration;
use tokio::sync::RwLock;
use tracing::info;
use tracing::warn;

use super::geoip_db::GeoipDB;
use super::geoip_db::get_geoip_db_by_tag;

pub type GeoIpReader = maxminddb::Reader<Mmap>;
pub type SharedGeoIpReader = Arc<RwLock<Option<Arc<GeoIpReader>>>>;

pub static GEOIP_MAP: LazyLock<DashMap<String, Arc<Geoip>>> = LazyLock::new(DashMap::new);

pub async fn init_geoip(cfg: &Config) -> anyhow::Result<()> {
    for (tag, db_cfg) in cfg.router.geoip.iter() {
        let name_clone = tag.clone();
        let db = Arc::new(Geoip::new(name_clone.clone(), db_cfg)?);
        GEOIP_MAP.insert(name_clone, db);
    }
    Ok(())
}

pub fn shutdown_geoip() {
    GEOIP_MAP.clear();
}

pub fn get_geoip_by_tag(tag: &str) -> Result<Arc<Geoip>> {
    match GEOIP_MAP.get(tag) {
        Some(r) => Ok(r.clone()),
        None => bail!("can not find geoip: {}", tag),
    }
}

pub struct Geoip {
    pub tag: String,
    pub ttl: u64,
    pub cache: Option<Arc<CacheWithExpire<bool>>>,
    pub db: Arc<GeoipDB>,
    pub dns: Arc<dyn AnyDNS>,
    pub ip_country: Vec<String>,
}

impl Geoip {
    pub fn new(tag: String, cfg: &GeoipConfig) -> anyhow::Result<Self> {
        let dns_name = cfg
            .dns
            .clone()
            .context(format!("geoip '{}' requires dns", tag))?;

        let dns = get_dns_by_tag(&dns_name)?;
        let ip_country: Vec<String> = cfg.ip_country.iter().map(|s| s.to_uppercase()).collect();

        let mut cache = None;
        if let Some(cache_name) = cfg.cache.clone() {
            let table = format!(
                "geoip|tag:{},dns:{},ip_country:{}",
                tag.clone(),
                dns_name,
                ip_country.join("/")
            );
            cache = Some(Arc::new(
                CacheWithExpire::new_with_tag(&cache_name, table)
                    .with_context(|| format!("geoip '{}' can not find cache tag", tag))?,
            ));
        }

        Ok(Self {
            tag,
            ttl: cfg.ttl.clone(),
            cache,
            db: get_geoip_db_by_tag(&cfg.db)?,
            dns,
            ip_country,
        })
    }

    pub async fn lookup(&self, addr: &TargetAddr) -> anyhow::Result<bool> {
        let start = std::time::Instant::now();
        let key = addr.host();

        if let Some(cache) = &self.cache {
            if let Ok(Some((res, remaining_ttl, source))) = cache.get(&key) {
                let remaining = Duration::from_secs(remaining_ttl.saturating_sub(now_timestamp()));
                info!(
                    "Cache HIT from {:?} for {}({})[{}], cost: {}",
                    source,
                    key,
                    res,
                    format_duration(remaining),
                    format_duration(start.elapsed())
                );
                return Ok(res);
            }
        }

        let ip = resolve_target_base2(addr, self.dns.clone()).await?;

        let result = self
            .db
            .lookup(ip)
            .await
            .map(|r| self.ip_country.contains(&r))
            .unwrap_or(false);

        info!(
            "Cache MISS for {}({}), Geoip Result: {}, cost: {}",
            key,
            ip,
            result,
            format_duration(start.elapsed())
        );

        if let Some(cache) = &self.cache {
            if let Err(e) = cache.set(&key, &result, self.ttl) {
                warn!("Failed to update cache for {}: {}", key, e);
            }
        }

        Ok(result)
    }
}
