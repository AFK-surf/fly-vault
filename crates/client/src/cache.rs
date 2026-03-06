use crate::{TransportConfig, VaultConfig};
use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::fs::OpenOptions;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const CACHE_FILE_NAME: &str = "attestation-cache-v1.json";
const LOCK_FILE_NAME: &str = "attestation-cache-v1.lock";
const LOCK_RETRY_DELAY: Duration = Duration::from_millis(10);
const LOCK_RETRY_ATTEMPTS: usize = 100;

#[derive(Debug, Clone)]
pub struct AttestationCache {
    path: Option<PathBuf>,
    entries: Vec<CacheEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CacheEntry {
    pub org: String,
    pub app: String,
    pub machine_id: String,
    pub fingerprint: String,
    pub verified_at: u64,
    pub last_seen_at: u64,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct StoredAttestationCache {
    #[serde(default)]
    entries: Vec<CacheEntry>,
}

impl Default for AttestationCache {
    fn default() -> Self {
        Self {
            path: None,
            entries: Vec::new(),
        }
    }
}

impl AttestationCache {
    pub fn load_default() -> Result<Self> {
        let base =
            dirs::cache_dir().ok_or_else(|| anyhow!("unable to determine cache directory"))?;
        Self::load_from(base.join("fly-vault").join(CACHE_FILE_NAME))
    }

    pub fn load_from(path: PathBuf) -> Result<Self> {
        match fs::read_to_string(&path) {
            Ok(raw) => {
                let stored: StoredAttestationCache =
                    serde_json::from_str(&raw).context("parse attestation cache json")?;
                Ok(Self {
                    path: Some(path),
                    entries: stored.entries,
                })
            }
            Err(err) if err.kind() == ErrorKind::NotFound => Ok(Self {
                path: Some(path),
                entries: Vec::new(),
            }),
            Err(err) => Err(err).with_context(|| format!("read cache file {}", path.display())),
        }
    }

    pub fn lookup(
        &self,
        cfg: &VaultConfig,
        transport: &TransportConfig,
        fingerprint: &str,
    ) -> Option<&CacheEntry> {
        self.entries
            .iter()
            .find(|entry| cache_entry_matches(entry, cfg, transport, fingerprint))
    }

    pub fn record_verified(
        &mut self,
        cfg: &VaultConfig,
        machine_id: &str,
        fingerprint: &str,
    ) -> Result<()> {
        let now = unix_timestamp_now()?;
        if let Some(entry) = self.entries.iter_mut().find(|entry| {
            entry.org == cfg.org
                && entry.app == cfg.app
                && entry.machine_id == machine_id
                && entry.fingerprint == fingerprint
        }) {
            entry.verified_at = now;
            entry.last_seen_at = now;
        } else {
            self.entries.push(CacheEntry {
                org: cfg.org.clone(),
                app: cfg.app.clone(),
                machine_id: machine_id.to_string(),
                fingerprint: fingerprint.to_string(),
                verified_at: now,
                last_seen_at: now,
            });
        }

        self.persist()
    }

    pub fn record_cache_hit(
        &mut self,
        cfg: &VaultConfig,
        transport: &TransportConfig,
        fingerprint: &str,
    ) -> Result<Option<CacheEntry>> {
        let now = unix_timestamp_now()?;
        let entry = self
            .entries
            .iter_mut()
            .find(|entry| cache_entry_matches(entry, cfg, transport, fingerprint));

        match entry {
            Some(entry) => {
                entry.last_seen_at = now;
                let matched = entry.clone();
                self.persist()?;
                Ok(Some(matched))
            }
            None => Ok(None),
        }
    }

    fn persist(&self) -> Result<()> {
        let Some(path) = &self.path else {
            return Ok(());
        };
        let parent = path
            .parent()
            .ok_or_else(|| anyhow!("cache path {} has no parent", path.display()))?;
        fs::create_dir_all(parent)
            .with_context(|| format!("create cache dir {}", parent.display()))?;

        let lock = CacheLock::acquire(parent.join(LOCK_FILE_NAME))?;
        let serialized = serde_json::to_vec_pretty(&StoredAttestationCache {
            entries: self.entries.clone(),
        })
        .context("serialize attestation cache")?;
        let temp_path = temp_cache_path(parent);
        fs::write(&temp_path, serialized)
            .with_context(|| format!("write temp cache file {}", temp_path.display()))?;
        fs::rename(&temp_path, path).with_context(|| {
            format!(
                "rename temp cache file {} to {}",
                temp_path.display(),
                path.display()
            )
        })?;
        drop(lock);
        Ok(())
    }
}

fn cache_entry_matches(
    entry: &CacheEntry,
    cfg: &VaultConfig,
    transport: &TransportConfig,
    fingerprint: &str,
) -> bool {
    if entry.org != cfg.org || entry.app != cfg.app || entry.fingerprint != fingerprint {
        return false;
    }

    match transport {
        TransportConfig::Direct => true,
        TransportConfig::Proxy { machine_id } => entry.machine_id == *machine_id,
    }
}

fn unix_timestamp_now() -> Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock before unix epoch")?
        .as_secs())
}

fn temp_cache_path(parent: &Path) -> PathBuf {
    let unique = format!(
        "{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or_default()
    );
    parent.join(format!("{CACHE_FILE_NAME}.{unique}.tmp"))
}

struct CacheLock {
    path: PathBuf,
}

impl CacheLock {
    fn acquire(path: PathBuf) -> Result<Self> {
        for _ in 0..LOCK_RETRY_ATTEMPTS {
            match OpenOptions::new().write(true).create_new(true).open(&path) {
                Ok(_) => return Ok(Self { path }),
                Err(err) if err.kind() == ErrorKind::AlreadyExists => {
                    thread::sleep(LOCK_RETRY_DELAY);
                }
                Err(err) => {
                    return Err(err)
                        .with_context(|| format!("create cache lock {}", path.display()));
                }
            }
        }

        Err(anyhow!("timed out acquiring cache lock {}", path.display()))
    }
}

impl Drop for CacheLock {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

#[cfg(test)]
mod tests {
    use super::{AttestationCache, CACHE_FILE_NAME};
    use crate::{TransportConfig, VaultConfig};
    use anyhow::Result;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    fn temp_dir() -> PathBuf {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "fly-vault-client-cache-test-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create temp test dir");
        dir
    }

    fn make_cfg(machine_id: Option<&str>) -> VaultConfig {
        VaultConfig {
            address: "127.0.0.1:8443".to_string(),
            org: "test-org".to_string(),
            app: "test-app".to_string(),
            machine_id: machine_id.map(str::to_string),
            forward: Vec::new(),
            rootfs: None,
            rootfs_url: None,
            access_token: None,
        }
    }

    #[test]
    fn proxy_lookup_requires_matching_machine_id() -> Result<()> {
        let dir = temp_dir();
        let path = dir.join(CACHE_FILE_NAME);
        let mut cache = AttestationCache::load_from(path)?;
        let cfg = make_cfg(Some("machine-123"));
        cache.record_verified(&cfg, "machine-123", "fingerprint-a")?;

        let hit = cache.lookup(&cfg, &cfg.transport(), "fingerprint-a");
        assert!(hit.is_some(), "expected exact proxy cache hit");

        let miss_cfg = make_cfg(Some("machine-999"));
        let miss = cache.lookup(&miss_cfg, &miss_cfg.transport(), "fingerprint-a");
        assert!(
            miss.is_none(),
            "unexpected proxy cache hit for wrong machine"
        );
        Ok(())
    }

    #[test]
    fn direct_lookup_reuses_cached_machine_for_same_fingerprint() -> Result<()> {
        let dir = temp_dir();
        let path = dir.join(CACHE_FILE_NAME);
        let mut cache = AttestationCache::load_from(path)?;
        let proxy_cfg = make_cfg(Some("machine-123"));
        cache.record_verified(&proxy_cfg, "machine-123", "fingerprint-a")?;

        let direct_cfg = make_cfg(None);
        let hit = cache
            .lookup(&direct_cfg, &TransportConfig::Direct, "fingerprint-a")
            .expect("expected direct cache hit");
        assert_eq!(hit.machine_id, "machine-123");
        Ok(())
    }

    #[test]
    fn record_verified_persists_and_reloads() -> Result<()> {
        let dir = temp_dir();
        let path = dir.join(CACHE_FILE_NAME);
        let mut cache = AttestationCache::load_from(path.clone())?;
        let cfg = make_cfg(Some("machine-123"));

        cache.record_verified(&cfg, "machine-123", "fingerprint-a")?;

        let reloaded = AttestationCache::load_from(path)?;
        let entry = reloaded
            .lookup(&cfg, &cfg.transport(), "fingerprint-a")
            .expect("expected reloaded cache entry");
        assert!(entry.verified_at > 0);
        assert_eq!(entry.last_seen_at, entry.verified_at);
        Ok(())
    }

    #[test]
    fn record_cache_hit_updates_last_seen() -> Result<()> {
        let dir = temp_dir();
        let path = dir.join(CACHE_FILE_NAME);
        let mut cache = AttestationCache::load_from(path.clone())?;
        let cfg = make_cfg(Some("machine-123"));
        cache.record_verified(&cfg, "machine-123", "fingerprint-a")?;

        let before = cache
            .lookup(&cfg, &cfg.transport(), "fingerprint-a")
            .expect("cache entry before hit")
            .last_seen_at;
        std::thread::sleep(std::time::Duration::from_secs(1));
        let hit = cache
            .record_cache_hit(&cfg, &cfg.transport(), "fingerprint-a")?
            .expect("cache hit should return entry");
        assert!(hit.last_seen_at > before);

        let reloaded = AttestationCache::load_from(path)?;
        let persisted = reloaded
            .lookup(&cfg, &cfg.transport(), "fingerprint-a")
            .expect("persisted cache entry");
        assert!(persisted.last_seen_at > before);
        Ok(())
    }

    #[test]
    fn load_missing_file_starts_empty() -> Result<()> {
        let dir = temp_dir();
        let path = dir.join(CACHE_FILE_NAME);
        let cache = AttestationCache::load_from(path)?;
        assert_eq!(
            cache.lookup(&make_cfg(None), &TransportConfig::Direct, "missing"),
            None
        );
        Ok(())
    }

    #[test]
    fn record_cache_hit_returns_none_for_miss() -> Result<()> {
        let dir = temp_dir();
        let path = dir.join(CACHE_FILE_NAME);
        let mut cache = AttestationCache::load_from(path)?;
        let cfg = make_cfg(Some("machine-123"));
        let hit = cache.record_cache_hit(&cfg, &cfg.transport(), "missing")?;
        assert!(
            hit.is_none(),
            "missing cache entry should not be treated as a hit"
        );
        Ok(())
    }
}
