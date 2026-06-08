//! A TTL cache with optional disk persistence.
//!
//! Used for SAML metadata, federation entity configurations and resolved
//! metadata. Entries carry an absolute expiry. The cache can snapshot itself to
//! a JSON file and reload it at startup; a background task (driven by the
//! binary) refreshes entries as they near expiry.

use crate::util::now_secs;
use serde::{de::DeserializeOwned, Serialize};
use std::collections::HashMap;
use std::sync::RwLock;

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
}

impl<V> TtlCache<V>
where
    V: Clone + Serialize + DeserializeOwned,
{
    pub fn new(default_ttl: u64) -> Self {
        Self {
            inner: RwLock::new(HashMap::new()),
            default_ttl,
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
        let json = serde_json::to_vec(&snapshot)
            .map_err(|e| std::io::Error::other(e.to_string()))?;
        std::fs::write(path, json)
    }

    /// Load entries from a JSON snapshot (ignores already-expired entries).
    pub fn load(&self, path: &str) -> std::io::Result<()> {
        let bytes = std::fs::read(path)?;
        let snapshot: HashMap<String, Entry<V>> = serde_json::from_slice(&bytes)
            .map_err(|e| std::io::Error::other(e.to_string()))?;
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
