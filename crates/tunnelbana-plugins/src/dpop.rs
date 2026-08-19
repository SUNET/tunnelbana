//! DPoP (RFC 9449) runtime glue for the frontends.
//!
//! `tunnelbana-oidc` owns the protocol logic but stays stateless: it validates a
//! proof's crypto and claims and then delegates replay protection to a
//! [`ReplayStore`]. This module supplies the concrete store (backed by the core
//! TTL cache) and the per-frontend [`DpopRuntime`] that bundles the validated
//! config with that store, plus the TOML config shape.

use std::sync::Arc;

use serde::Deserialize;
use tunnelbana_core::cache::TtlCache;
use tunnelbana_core::mac::hmac_sha256;
use tunnelbana_oidc::dpop::{DpopConfig, ReplayStore};

/// A [`ReplayStore`] backed by the core TTL cache: a `jti` is recorded for the
/// proof's freshness window, and a re-presentation within that window is a
/// replay. Single-process; for a horizontally-scaled deployment back this with
/// a shared store instead.
pub struct CacheReplayStore {
    seen: TtlCache<()>,
}

/// Upper bound on the `jti` length retained in the replay cache. Longer ids
/// are rejected as replays, so attacker-controlled input cannot grow the
/// cache's keys without bound.
const MAX_JTI_LEN: usize = 256;

impl CacheReplayStore {
    pub fn new(default_ttl: u64) -> Self {
        Self {
            seen: TtlCache::new(default_ttl),
        }
    }
}

#[async_trait::async_trait]
impl ReplayStore for CacheReplayStore {
    async fn record(&self, jti: &str, ttl_secs: u64) -> Result<bool, String> {
        if jti.len() > MAX_JTI_LEN {
            tracing::debug!(len = jti.len(), "rejecting over-long DPoP jti");
            return Ok(false);
        }
        // Atomic check-and-set: true iff this jti was not already live.
        Ok(self.seen.put_if_absent(jti, (), ttl_secs))
    }
}

/// Validated DPoP settings + the replay store, held by a frontend that has DPoP
/// enabled.
pub struct DpopRuntime {
    pub config: DpopConfig,
    pub store: Arc<dyn ReplayStore>,
}

/// TOML config for DPoP under a frontend's `[frontend.config.dpop]` table.
#[derive(Debug, Clone, Deserialize)]
pub struct DpopSettings {
    /// Master switch. When false (the default) DPoP is not offered and proofs
    /// are ignored.
    #[serde(default)]
    pub enabled: bool,
    /// Maximum age of a proof's `iat`, and the replay window for its `jti`.
    #[serde(default = "default_proof_max_age")]
    pub proof_max_age_secs: i64,
    /// Require a valid `DPoP-Nonce` (RFC 9449 §8); when a proof lacks one the
    /// token endpoint replies `400 use_dpop_nonce` with a fresh challenge.
    #[serde(default)]
    pub require_nonce: bool,
    /// Lifetime of an issued nonce.
    #[serde(default = "default_nonce_lifetime")]
    pub nonce_lifetime_secs: i64,
}

impl Default for DpopSettings {
    fn default() -> Self {
        Self {
            enabled: false,
            proof_max_age_secs: default_proof_max_age(),
            require_nonce: false,
            nonce_lifetime_secs: default_nonce_lifetime(),
        }
    }
}

fn default_proof_max_age() -> i64 {
    300
}
fn default_nonce_lifetime() -> i64 {
    300
}

impl DpopSettings {
    /// Build the runtime from the settings, deriving a dedicated nonce HMAC key
    /// from `secret` (domain-separated — never the raw signing/sealing key) and
    /// mixed with the frontend `instance` name, so nonces issued by one
    /// frontend are not accepted by another sharing the same master secret.
    /// Returns `None` when DPoP is disabled.
    pub fn build_runtime(
        &self,
        secret: &str,
        instance: &str,
    ) -> tunnelbana_core::error::Result<Option<DpopRuntime>> {
        if !self.enabled {
            return Ok(None);
        }
        // A zero (or negative) max age would silently disable the replay
        // store's TTL, so reject it instead of building a broken runtime.
        if self.proof_max_age_secs <= 0 {
            return Err(tunnelbana_core::error::Error::Config(
                "dpop.proof_max_age_secs must be positive".into(),
            ));
        }
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;
        let nonce_secret = URL_SAFE_NO_PAD.encode(hmac_sha256(
            secret.as_bytes(),
            format!("tunnelbana-dpop-nonce-v1:{instance}").as_bytes(),
        ));

        let config = DpopConfig {
            proof_max_age_secs: self.proof_max_age_secs,
            require_nonce: self.require_nonce,
            nonce_lifetime_secs: self.nonce_lifetime_secs,
            nonce_secret,
        };
        let ttl = self.proof_max_age_secs.max(0) as u64;
        // The cache-backed replay store is per-process. In a horizontally-scaled
        // deployment a proof replayed against a *different* replica is not caught,
        // so operators must front it with a shared store (or pin to a single
        // instance). Surface that caveat at startup.
        tracing::info!(
            require_nonce = self.require_nonce,
            proof_max_age_secs = self.proof_max_age_secs,
            "DPoP enabled: replay protection is per-process; use a shared ReplayStore when running multiple replicas"
        );
        Ok(Some(DpopRuntime {
            config,
            store: Arc::new(CacheReplayStore::new(ttl)),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn cache_store_detects_replay() {
        let store = CacheReplayStore::new(60);
        assert!(store.record("jti-a", 60).await.unwrap());
        assert!(!store.record("jti-a", 60).await.unwrap());
        assert!(store.record("jti-b", 60).await.unwrap());
    }

    #[tokio::test]
    async fn overlong_jti_is_rejected_without_retention() {
        let store = CacheReplayStore::new(60);
        let long = "x".repeat(MAX_JTI_LEN + 1);
        // Not recorded, and reported as a replay so validation fails closed.
        assert!(!store.record(&long, 60).await.unwrap());
        assert!(!store.record(&long, 60).await.unwrap());
        // The boundary itself still works.
        let max = "y".repeat(MAX_JTI_LEN);
        assert!(store.record(&max, 60).await.unwrap());
        assert!(!store.record(&max, 60).await.unwrap());
    }

    #[test]
    fn disabled_settings_yield_no_runtime() {
        assert!(DpopSettings::default()
            .build_runtime("s", "fe")
            .unwrap()
            .is_none());
    }

    #[test]
    fn enabled_settings_derive_nonce_secret() {
        let s = DpopSettings {
            enabled: true,
            ..Default::default()
        };
        let rt = s.build_runtime("op-secret", "fe").unwrap().unwrap();
        assert!(!rt.config.nonce_secret.is_empty());
        assert_eq!(rt.config.proof_max_age_secs, 300);
    }

    #[test]
    fn zero_proof_max_age_is_a_config_error() {
        let s = DpopSettings {
            enabled: true,
            proof_max_age_secs: 0,
            ..Default::default()
        };
        let err = s.build_runtime("op-secret", "fe").err().expect("must fail");
        assert!(err.to_string().contains("proof_max_age_secs"), "got: {err}");
    }

    #[test]
    fn nonce_secret_is_scoped_per_frontend_instance() {
        let s = DpopSettings {
            enabled: true,
            ..Default::default()
        };
        let a = s.build_runtime("op-secret", "fe-a").unwrap().unwrap();
        let b = s.build_runtime("op-secret", "fe-b").unwrap().unwrap();
        assert_ne!(a.config.nonce_secret, b.config.nonce_secret);
    }
}
