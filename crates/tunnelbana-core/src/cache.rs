//! A TTL cache with optional disk persistence.
//!
//! Used for SAML metadata, federation entity configurations and resolved
//! metadata. Entries carry an absolute expiry. The cache can snapshot itself to
//! a JSON file and reload it at startup; a background task (driven by the
//! binary) refreshes entries as they near expiry.

use crate::util::now_secs;
use serde::{de::DeserializeOwned, Serialize};
use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::RwLock;

/// Floor for the opportunistic-prune watermark: never sweep a map smaller than
/// this, so low-traffic caches don't pay for scans.
const PRUNE_FLOOR: usize = 1024;

/// A single cached entry with absolute expiry (unix seconds).
#[derive(Clone, Serialize, serde::Deserialize)]
struct Entry<V> {
    value: V,
    expires_at: u64,
}

/// Thread-safe TTL cache keyed by `String`.
pub struct TtlCache<V> {
    inner: RwLock<HashMap<String, Entry<V>>>,
    default_ttl: u64,
    /// Map size at which the next opportunistic prune of expired entries fires.
    /// Without this an append-only key space (e.g. DPoP `jti`s) would grow the
    /// map without bound until restart.
    prune_at: AtomicUsize,
}

impl<V> TtlCache<V>
where
    V: Clone + Serialize + DeserializeOwned,
{
    pub fn new(default_ttl: u64) -> Self {
        Self {
            inner: RwLock::new(HashMap::new()),
            default_ttl,
            prune_at: AtomicUsize::new(PRUNE_FLOOR),
        }
    }

    /// Number of entries currently held (live or not-yet-pruned).
    pub fn len(&self) -> usize {
        self.inner.read().map(|g| g.len()).unwrap_or(0)
    }

    /// Whether the cache holds no entries.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Drop every entry whose TTL has elapsed. Called opportunistically by
    /// [`Self::put_if_absent`]; also safe to invoke directly (e.g. from a
    /// periodic maintenance task).
    pub fn prune_expired(&self) {
        let now = now_secs();
        if let Ok(mut guard) = self.inner.write() {
            guard.retain(|_, e| e.expires_at > now);
        }
    }

    /// Fetch a live (non-expired) value.
    pub fn get(&self, key: &str) -> Option<V> {
        let now = now_secs();
        let guard = self.inner.read().ok()?;
        let entry = guard.get(key)?;
        if entry.expires_at > now {
            Some(entry.value.clone())
        } else {
            None
        }
    }

    /// Insert with the default TTL.
    pub fn put(&self, key: impl Into<String>, value: V) {
        self.put_with_ttl(key, value, self.default_ttl);
    }

    /// Insert with an explicit TTL (seconds).
    pub fn put_with_ttl(&self, key: impl Into<String>, value: V, ttl: u64) {
        if let Ok(mut guard) = self.inner.write() {
            guard.insert(
                key.into(),
                Entry {
                    value,
                    expires_at: now_secs() + ttl,
                },
            );
        }
    }

    /// Atomically insert `value` only if no live entry exists for `key`. Returns
    /// `true` if the value was newly inserted, `false` if a live entry already
    /// held the key (an expired entry is overwritten and counts as newly
    /// inserted). The check and insert happen under one write lock, so this is a
    /// race-free check-and-set — used for DPoP `jti` replay protection.
    pub fn put_if_absent(&self, key: impl Into<String>, value: V, ttl: u64) -> bool {
        let now = now_secs();
        let Ok(mut guard) = self.inner.write() else {
            // A poisoned lock means we cannot vouch for freshness; treat as
            // "already present" so the caller fails closed (rejects as replay).
            tracing::error!(
                "TtlCache lock poisoned in put_if_absent; failing closed (treating key as present)"
            );
            return false;
        };
        let key = key.into();
        if let Some(entry) = guard.get(&key) {
            if entry.expires_at > now {
                return false;
            }
        }
        guard.insert(
            key,
            Entry {
                value,
                expires_at: now + ttl,
            },
        );
        // Amortized cleanup: when the map outgrows the watermark, sweep expired
        // entries and re-arm at twice the surviving size. This bounds memory for
        // an append-only key space such as DPoP `jti` replay records, whose keys
        // are never re-inserted and so would otherwise accumulate forever.
        if guard.len() >= self.prune_at.load(Ordering::Relaxed) {
            guard.retain(|_, e| e.expires_at > now);
            let next = guard.len().saturating_mul(2).max(PRUNE_FLOOR);
            self.prune_at.store(next, Ordering::Relaxed);
        }
        true
    }

    /// Keys whose entries expire within `window` seconds (refresh candidates).
    pub fn expiring_within(&self, window: u64) -> Vec<String> {
        let cutoff = now_secs() + window;
        self.inner
            .read()
            .map(|g| {
                g.iter()
                    .filter(|(_, e)| e.expires_at <= cutoff)
                    .map(|(k, _)| k.clone())
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Snapshot all entries to a JSON file for restart persistence.
    pub fn persist(&self, path: &str) -> std::io::Result<()> {
        let guard = self
            .inner
            .read()
            .map_err(|_| std::io::Error::other("cache lock poisoned"))?;
        let snapshot: HashMap<&String, &Entry<V>> = guard.iter().collect();
        let json =
            serde_json::to_vec(&snapshot).map_err(|e| std::io::Error::other(e.to_string()))?;
        std::fs::write(path, json)
    }

    /// Load entries from a JSON snapshot (ignores already-expired entries).
    pub fn load(&self, path: &str) -> std::io::Result<()> {
        let bytes = std::fs::read(path)?;
        let snapshot: HashMap<String, Entry<V>> =
            serde_json::from_slice(&bytes).map_err(|e| std::io::Error::other(e.to_string()))?;
        let now = now_secs();
        if let Ok(mut guard) = self.inner.write() {
            for (k, e) in snapshot {
                if e.expires_at > now {
                    guard.insert(k, e);
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn put_get_and_expiry() {
        let cache: TtlCache<String> = TtlCache::new(60);
        cache.put("a", "value-a".to_string());
        assert_eq!(cache.get("a").as_deref(), Some("value-a"));

        // Expired entry is not returned.
        cache.put_with_ttl("b", "value-b".to_string(), 0);
        assert!(cache.get("b").is_none());
    }

    #[test]
    fn put_if_absent_bounds_memory_for_expired_keys() {
        // Simulate a high-churn replay store: many unique, immediately-expired
        // keys. The opportunistic prune must keep the map from growing without
        // bound rather than retaining one entry per key ever seen.
        let cache: TtlCache<()> = TtlCache::new(60);
        for i in 0..(PRUNE_FLOOR * 8) {
            assert!(cache.put_if_absent(format!("jti-{i}"), (), 0));
        }
        // Every inserted entry had ttl=0 (already expired), so after the
        // amortized sweeps the surviving set is far below the total inserted.
        assert!(
            cache.len() <= PRUNE_FLOOR,
            "expected bounded map, got {}",
            cache.len()
        );
    }

    #[test]
    fn put_if_absent_is_check_and_set() {
        let cache: TtlCache<()> = TtlCache::new(60);
        // First insert wins.
        assert!(cache.put_if_absent("jti-1", (), 60));
        // Second insert of a live key is refused.
        assert!(!cache.put_if_absent("jti-1", (), 60));
        // An expired key is re-insertable.
        assert!(cache.put_if_absent("jti-2", (), 0));
        assert!(cache.put_if_absent("jti-2", (), 60));
    }

    #[test]
    fn persist_and_load_roundtrip() {
        let dir = std::env::temp_dir();
        let path = dir.join("tb_cache_test.json");
        let path = path.to_str().unwrap();

        let cache: TtlCache<String> = TtlCache::new(300);
        cache.put("k", "v".to_string());
        cache.persist(path).unwrap();

        let cache2: TtlCache<String> = TtlCache::new(300);
        cache2.load(path).unwrap();
        assert_eq!(cache2.get("k").as_deref(), Some("v"));

        let _ = std::fs::remove_file(path);
    }
}
