//! Configuration loading from `proxy.toml`.
//!
//! Supports `${ENV}` interpolation, per-plugin `[[frontend]]`/`[[backend]]`/
//! `[[microservice]]` tables, and an `include` directive to pull a plugin's
//! config out into its own file. Plugin configs are exposed to plugins as
//! `serde_json::Value` so each plugin deserializes its own typed config.

use crate::error::{Error, Result};
use serde::Deserialize;
use std::path::{Path, PathBuf};

/// Logging configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct LoggingConfig {
    #[serde(default = "default_level")]
    pub level: String,
    #[serde(default = "default_format")]
    pub format: String,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: default_level(),
            format: default_format(),
        }
    }
}

fn default_level() -> String {
    "info".to_string()
}
fn default_format() -> String {
    "pretty".to_string()
}
fn default_cookie_name() -> String {
    "TUNNELBANA_STATE".to_string()
}
fn default_cookie_same_site() -> String {
    "None".to_string()
}
fn default_state_cookie_max_age() -> u64 {
    crate::state::DEFAULT_TTL_SECONDS
}

/// Minimum accepted length (in bytes) of `state_encryption_key`. A 32-byte
/// high-entropy secret is required so the HKDF-derived AEAD key cannot be
/// recovered by offline brute-force of a short/low-entropy passphrase.
const MIN_STATE_KEY_LEN: usize = 32;
fn empty_toml_table() -> toml::Value {
    toml::Value::Table(toml::map::Map::new())
}

/// One plugin instance configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct PluginConfig {
    /// The registered module type, e.g. `saml2`, `oidc`, `oidc_federation`.
    #[serde(rename = "type")]
    pub kind: String,
    /// Unique instance name used for routing.
    pub name: String,
    /// Inline plugin config (TOML table).
    #[serde(default = "empty_toml_table")]
    pub config: toml::Value,
    /// Optional path to a file whose contents become the plugin config.
    #[serde(default)]
    pub include: Option<String>,
}

impl PluginConfig {
    /// The plugin config as a `serde_json::Value`.
    pub fn config_json(&self) -> serde_json::Value {
        toml_to_json(&self.config)
    }
}

/// The top-level proxy configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct ProxyConfig {
    /// Public base URL of the proxy (no trailing slash).
    pub base_url: String,
    /// Secret used to derive the state-cookie encryption key. Must be at least
    /// 32 bytes of high-entropy material (see [`MIN_STATE_KEY_LEN`]).
    pub state_encryption_key: String,
    /// Previous state-encryption secrets, retained for decryption only so that
    /// cookies sealed before a key rotation keep working. Never used to seal.
    #[serde(default)]
    pub previous_state_encryption_keys: Vec<String>,
    /// State cookie name.
    #[serde(default = "default_cookie_name")]
    pub cookie_name: String,
    /// Whether to mark the state cookie Secure (set false for local http).
    #[serde(default = "default_true")]
    pub cookie_secure: bool,
    /// `SameSite` attribute for the state cookie (`None`, `Lax`, or `Strict`).
    #[serde(default = "default_cookie_same_site")]
    pub cookie_same_site: String,
    /// Maximum age of sealed state, in seconds. Enforced both as the cookie
    /// `Max-Age` and as a server-side freshness check on `unseal`. A value of
    /// `0` disables expiry (not recommended).
    #[serde(default = "default_state_cookie_max_age")]
    pub state_cookie_max_age: u64,
    /// Path to the attribute map (relative to the config file).
    #[serde(default)]
    pub attributes: Option<String>,
    /// Directory for cache persistence snapshots.
    #[serde(default)]
    pub cache_dir: Option<String>,
    /// Optional path (relative to the config file, or absolute) to a custom HTML
    /// file served verbatim at `/`. When unset, the binary serves its built-in
    /// landing page. The file is read once at boot; an unreadable path aborts
    /// startup (fail-fast), it is never re-read per request.
    #[serde(default)]
    pub index_html: Option<String>,
    #[serde(default)]
    pub logging: LoggingConfig,
    #[serde(rename = "frontend", default)]
    pub frontends: Vec<PluginConfig>,
    #[serde(rename = "backend", default)]
    pub backends: Vec<PluginConfig>,
    #[serde(rename = "microservice", default)]
    pub microservices: Vec<PluginConfig>,
}

fn default_true() -> bool {
    true
}

impl ProxyConfig {
    /// Load and fully resolve the configuration from a file path.
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let base_dir = path
            .parent()
            .map(|p| p.to_path_buf())
            .unwrap_or_else(|| PathBuf::from("."));
        let raw = std::fs::read_to_string(path)
            .map_err(|e| Error::Config(format!("reading {}: {e}", path.display())))?;
        let interpolated = interpolate_env(&raw);
        let mut cfg: ProxyConfig = toml::from_str(&interpolated)
            .map_err(|e| Error::Config(format!("parsing {}: {e}", path.display())))?;
        cfg.resolve_includes(&base_dir)?;
        cfg.validate()?;
        Ok(cfg)
    }

    /// Parse from a TOML string (no include resolution).
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Result<Self> {
        let interpolated = interpolate_env(s);
        let cfg: ProxyConfig = toml::from_str(&interpolated)
            .map_err(|e| Error::Config(format!("parsing config: {e}")))?;
        cfg.validate()?;
        Ok(cfg)
    }

    fn resolve_includes(&mut self, base_dir: &Path) -> Result<()> {
        for plugin in self
            .frontends
            .iter_mut()
            .chain(self.backends.iter_mut())
            .chain(self.microservices.iter_mut())
        {
            if let Some(include) = plugin.include.clone() {
                let inc_path = base_dir.join(&include);
                let raw = std::fs::read_to_string(&inc_path).map_err(|e| {
                    Error::Config(format!("reading include {}: {e}", inc_path.display()))
                })?;
                let interpolated = interpolate_env(&raw);
                let value: toml::Value = toml::from_str(&interpolated).map_err(|e| {
                    Error::Config(format!("parsing include {}: {e}", inc_path.display()))
                })?;
                plugin.config = value;
            }
        }
        Ok(())
    }

    fn validate(&self) -> Result<()> {
        if self.base_url.is_empty() {
            return Err(Error::Config("base_url must be set".into()));
        }
        if self.state_encryption_key.is_empty() {
            return Err(Error::Config("state_encryption_key must be set".into()));
        }
        if self.state_encryption_key.len() < MIN_STATE_KEY_LEN {
            return Err(Error::Config(format!(
                "state_encryption_key must be at least {MIN_STATE_KEY_LEN} bytes of \
                 high-entropy secret (got {} bytes)",
                self.state_encryption_key.len()
            )));
        }
        Ok(())
    }
}

/// Replace `${VAR}` occurrences with the value of environment variable `VAR`.
/// Unknown variables are replaced with the empty string.
pub fn interpolate_env(input: &str) -> String {
    let re = regex::Regex::new(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}").unwrap();
    re.replace_all(input, |caps: &regex::Captures| {
        std::env::var(&caps[1]).unwrap_or_default()
    })
    .into_owned()
}

/// Convert a `toml::Value` to a `serde_json::Value`.
pub fn toml_to_json(value: &toml::Value) -> serde_json::Value {
    use serde_json::Value as J;
    match value {
        toml::Value::String(s) => J::String(s.clone()),
        toml::Value::Integer(i) => J::Number((*i).into()),
        toml::Value::Float(f) => serde_json::Number::from_f64(*f)
            .map(J::Number)
            .unwrap_or(J::Null),
        toml::Value::Boolean(b) => J::Bool(*b),
        toml::Value::Datetime(dt) => J::String(dt.to_string()),
        toml::Value::Array(arr) => J::Array(arr.iter().map(toml_to_json).collect()),
        toml::Value::Table(tbl) => {
            let mut map = serde_json::Map::new();
            for (k, v) in tbl {
                map.insert(k.clone(), toml_to_json(v));
            }
            J::Object(map)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_basic_config_with_plugins() {
        let toml_str = r#"
            base_url = "https://proxy.example.com"
            state_encryption_key = "a-32-byte-or-longer-test-secret!!"

            [logging]
            level = "debug"

            [[frontend]]
            type = "oidc"
            name = "OIDC"
            [frontend.config]
            signing_algorithm = "ES256"

            [[backend]]
            type = "saml2"
            name = "Saml2"
        "#;
        let cfg = ProxyConfig::from_str(toml_str).unwrap();
        assert_eq!(cfg.base_url, "https://proxy.example.com");
        assert_eq!(cfg.frontends.len(), 1);
        assert_eq!(cfg.frontends[0].kind, "oidc");
        let json = cfg.frontends[0].config_json();
        assert_eq!(json["signing_algorithm"], "ES256");
        assert_eq!(cfg.backends.len(), 1);
        assert_eq!(cfg.logging.level, "debug");
    }

    #[test]
    fn env_interpolation() {
        std::env::set_var("TB_TEST_KEY", "injected-secret-that-is-32-bytes!");
        let toml_str = r#"
            base_url = "https://x"
            state_encryption_key = "${TB_TEST_KEY}"
        "#;
        let cfg = ProxyConfig::from_str(toml_str).unwrap();
        assert_eq!(
            cfg.state_encryption_key,
            "injected-secret-that-is-32-bytes!"
        );
    }

    #[test]
    fn short_state_key_is_rejected() {
        let toml_str = r#"
            base_url = "https://x"
            state_encryption_key = "too-short"
        "#;
        let err = ProxyConfig::from_str(toml_str).unwrap_err();
        assert!(
            err.to_string().contains("at least"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn cookie_defaults_are_applied() {
        let toml_str = r#"
            base_url = "https://x"
            state_encryption_key = "a-32-byte-or-longer-test-secret!!"
        "#;
        let cfg = ProxyConfig::from_str(toml_str).unwrap();
        assert_eq!(cfg.cookie_same_site, "None");
        assert_eq!(cfg.state_cookie_max_age, crate::state::DEFAULT_TTL_SECONDS);
        assert!(cfg.cookie_secure);
        assert!(cfg.previous_state_encryption_keys.is_empty());
    }
}
