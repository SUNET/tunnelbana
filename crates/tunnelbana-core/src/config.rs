//! Configuration loading from `proxy.toml`.
//!
//! Supports `${ENV}` interpolation, per-plugin `[[frontend]]`/`[[backend]]`/
//! `[[microservice]]` tables, and an `include` directive to pull a plugin's
//! config out into its own file. Plugin configs are exposed to plugins as
//! `serde_json::Value` so each plugin deserializes its own typed config.

use crate::error::{Error, Result};
use serde::Deserialize;
use std::collections::HashSet;
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
fn default_http_connect_timeout_seconds() -> u64 {
    10
}
fn default_http_read_timeout_seconds() -> u64 {
    15
}
fn default_http_request_timeout_seconds() -> u64 {
    30
}
fn default_http_max_response_bytes() -> usize {
    8 * 1024 * 1024
}
fn default_python_max_concurrent_calls() -> usize {
    16
}
fn default_python_call_timeout_seconds() -> u64 {
    30
}

/// Global controls for embedded synchronous Python micro-services.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PythonConfig {
    /// The sole directory added to Python's import search path.
    pub module_path: String,
    /// Optional virtual environment directory (created with `uv venv` or
    /// `python -m venv`). The embedded interpreter adopts it exactly like a
    /// venv-launched Python: `pyvenv.cfg` is honored and the venv's
    /// site-packages (including `.pth` files) are processed.
    #[serde(default)]
    pub venv: Option<String>,
    /// Maximum number of Python calls admitted across all micro-services.
    #[serde(default = "default_python_max_concurrent_calls")]
    pub max_concurrent_calls: usize,
    /// Total deadline for permit acquisition and synchronous execution.
    #[serde(default = "default_python_call_timeout_seconds")]
    pub call_timeout_seconds: u64,
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
    /// Outbound HTTP connection establishment timeout.
    #[serde(default = "default_http_connect_timeout_seconds")]
    pub http_connect_timeout_seconds: u64,
    /// Maximum idle interval between chunks of an outbound response body.
    #[serde(default = "default_http_read_timeout_seconds")]
    pub http_read_timeout_seconds: u64,
    /// Total deadline for each outbound HTTP request, including its body.
    #[serde(default = "default_http_request_timeout_seconds")]
    pub http_request_timeout_seconds: u64,
    /// Maximum body buffered from metadata, JWKS, token and UserInfo endpoints.
    #[serde(default = "default_http_max_response_bytes")]
    pub http_max_response_bytes: usize,
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
    /// Embedded Python runtime configuration. Required when a Python
    /// micro-service is configured.
    #[serde(default)]
    pub python: Option<PythonConfig>,
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
        let interpolated = interpolate_env(&raw)?;
        let mut cfg: ProxyConfig = toml::from_str(&interpolated).map_err(|e| {
            Error::Config(format!(
                "parsing {}: {}",
                path.display(),
                toml_parse_error(&interpolated, &e)
            ))
        })?;
        cfg.resolve_includes(&base_dir)?;
        cfg.validate()?;
        Ok(cfg)
    }

    /// Parse from a TOML string (no include resolution).
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Result<Self> {
        let interpolated = interpolate_env(s)?;
        let cfg: ProxyConfig = toml::from_str(&interpolated).map_err(|e| {
            Error::Config(format!(
                "parsing config: {}",
                toml_parse_error(&interpolated, &e)
            ))
        })?;
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
                let interpolated = interpolate_env(&raw)?;
                let value: toml::Value = toml::from_str(&interpolated).map_err(|e| {
                    Error::Config(format!(
                        "parsing include {}: {}",
                        inc_path.display(),
                        toml_parse_error(&interpolated, &e)
                    ))
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
        if !matches!(
            self.cookie_same_site.to_ascii_lowercase().as_str(),
            "none" | "lax" | "strict"
        ) {
            return Err(Error::Config(format!(
                "cookie_same_site must be one of None, Lax, or Strict (got {:?})",
                self.cookie_same_site
            )));
        }
        if self.state_encryption_key.len() < MIN_STATE_KEY_LEN {
            return Err(Error::Config(format!(
                "state_encryption_key must be at least {MIN_STATE_KEY_LEN} bytes of \
                 high-entropy secret (got {} bytes)",
                self.state_encryption_key.len()
            )));
        }
        // Rotation keys authenticate old state and token material just like the
        // primary key does. Applying a weaker rule here would turn rotation
        // compatibility into an alternate, guessable authentication key.
        for (index, key) in self.previous_state_encryption_keys.iter().enumerate() {
            if key.len() < MIN_STATE_KEY_LEN {
                return Err(Error::Config(format!(
                    "previous_state_encryption_keys[{index}] must be at least \
                     {MIN_STATE_KEY_LEN} bytes of high-entropy secret (got {} bytes)",
                    key.len()
                )));
            }
        }
        if self.http_connect_timeout_seconds == 0
            || self.http_read_timeout_seconds == 0
            || self.http_request_timeout_seconds == 0
        {
            return Err(Error::Config(
                "outbound HTTP timeouts must be greater than zero".into(),
            ));
        }
        if self.http_max_response_bytes == 0 {
            return Err(Error::Config(
                "http_max_response_bytes must be greater than zero".into(),
            ));
        }
        let has_python_microservice = self.microservices.iter().any(|p| p.kind == "python");
        if has_python_microservice && self.python.is_none() {
            return Err(Error::Config(
                "[python] is required when a microservice has type = \"python\"".into(),
            ));
        }
        if let Some(python) = &self.python {
            if python.module_path.trim().is_empty() {
                return Err(Error::Config("python.module_path must not be empty".into()));
            }
            if let Some(venv) = &python.venv {
                if venv.trim().is_empty() {
                    return Err(Error::Config("python.venv must not be empty".into()));
                }
            }
            if python.max_concurrent_calls == 0 {
                return Err(Error::Config(
                    "python.max_concurrent_calls must be greater than zero".into(),
                ));
            }
            if python.call_timeout_seconds == 0 {
                return Err(Error::Config(
                    "python.call_timeout_seconds must be greater than zero".into(),
                ));
            }
        }

        let mut microservice_names = HashSet::new();
        for microservice in &self.microservices {
            if !microservice_names.insert(microservice.name.as_str()) {
                return Err(Error::Config(format!(
                    "duplicate microservice name: {}",
                    microservice.name
                )));
            }
        }
        Ok(())
    }
}

/// Replace `${VAR}` occurrences with the value of environment variable `VAR`.
/// Fails with an error naming the first unset variable, so a missing or
/// misspelled variable cannot silently turn a secret into the empty string.
pub fn interpolate_env(input: &str) -> Result<String> {
    let re = regex::Regex::new(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}").unwrap();
    let mut out = String::with_capacity(input.len());
    let mut last = 0;
    for caps in re.captures_iter(input) {
        let m = caps.get(0).unwrap();
        out.push_str(&input[last..m.start()]);
        let name = &caps[1];
        let value = std::env::var(name).map_err(|_| {
            Error::Config(format!(
                "environment variable {name} referenced by the configuration is not set"
            ))
        })?;
        out.push_str(&value);
        last = m.end();
    }
    out.push_str(&input[last..]);
    Ok(out)
}

/// Format a TOML parse error with the parser's message and line/column, but
/// without the source snippet: the interpolated source can contain plaintext
/// secrets, which must not be echoed into logs or error output.
fn toml_parse_error(source: &str, error: &toml::de::Error) -> String {
    match error.span() {
        Some(span) => {
            let (line, column) = line_col(source, span.start);
            format!("{} at line {line}, column {column}", error.message())
        }
        None => error.message().to_string(),
    }
}

/// One-based line and column of a byte offset into `source`.
fn line_col(source: &str, offset: usize) -> (usize, usize) {
    let before = &source[..offset.min(source.len())];
    let line = before.matches('\n').count() + 1;
    let column = before.rsplit('\n').next().map_or(0, |l| l.len()) + 1;
    (line, column)
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
    fn unset_env_var_fails_config_load() {
        // Deliberately unique name so no other test (or the environment) sets it.
        let toml_str = r#"
            base_url = "https://x"
            state_encryption_key = "${TB_TEST_DEFINITELY_UNSET_VAR}"
        "#;
        let err = ProxyConfig::from_str(toml_str).unwrap_err();
        assert!(
            err.to_string().contains("TB_TEST_DEFINITELY_UNSET_VAR"),
            "error must name the unset variable: {err}"
        );
    }

    #[test]
    fn toml_parse_error_omits_source_snippet() {
        let toml_str = r#"
            base_url = "https://x"
            state_encryption_key = "plaintext-secret-do-not-leak!!"
            broken = [unclosed
        "#;
        let err = ProxyConfig::from_str(toml_str).unwrap_err();
        let msg = err.to_string();
        assert!(
            !msg.contains("plaintext-secret-do-not-leak"),
            "parse error must not echo source lines: {msg}"
        );
        assert!(
            msg.contains("line") && msg.contains("column"),
            "parse error keeps line/column: {msg}"
        );
    }

    #[test]
    fn cookie_same_site_is_validated() {
        for value in ["None", "lax", "STRICT"] {
            let toml_str = format!(
                r#"
                    base_url = "https://x"
                    state_encryption_key = "a-32-byte-or-longer-test-secret!!"
                    cookie_same_site = "{value}"
                "#
            );
            let cfg = ProxyConfig::from_str(&toml_str).unwrap();
            assert_eq!(cfg.cookie_same_site, value);
        }

        let toml_str = r#"
            base_url = "https://x"
            state_encryption_key = "a-32-byte-or-longer-test-secret!!"
            cookie_same_site = "Bogus"
        "#;
        let err = ProxyConfig::from_str(toml_str).unwrap_err();
        assert!(
            err.to_string().contains("cookie_same_site"),
            "unexpected error: {err}"
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
    fn short_previous_state_key_is_rejected() {
        let toml_str = r#"
            base_url = "https://x"
            state_encryption_key = "a-32-byte-or-longer-primary-secret"
            previous_state_encryption_keys = ["weak"]
        "#;
        let err = ProxyConfig::from_str(toml_str).unwrap_err();
        assert!(
            err.to_string()
                .contains("previous_state_encryption_keys[0]"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn sufficiently_long_previous_state_key_is_accepted() {
        let toml_str = r#"
            base_url = "https://x"
            state_encryption_key = "a-32-byte-or-longer-primary-secret"
            previous_state_encryption_keys = ["a-32-byte-or-longer-previous-secret"]
        "#;
        let cfg = ProxyConfig::from_str(toml_str).unwrap();
        assert_eq!(cfg.previous_state_encryption_keys.len(), 1);
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
        assert_eq!(cfg.http_connect_timeout_seconds, 10);
        assert_eq!(cfg.http_read_timeout_seconds, 15);
        assert_eq!(cfg.http_request_timeout_seconds, 30);
        assert_eq!(cfg.http_max_response_bytes, 8 * 1024 * 1024);
    }

    #[test]
    fn zero_outbound_http_limits_are_rejected() {
        let toml_str = r#"
            base_url = "https://x"
            state_encryption_key = "a-32-byte-or-longer-test-secret!!"
            http_max_response_bytes = 0
        "#;
        assert!(ProxyConfig::from_str(toml_str).is_err());
    }

    #[test]
    fn python_defaults_are_applied() {
        let cfg = ProxyConfig::from_str(
            r#"
                base_url = "https://x"
                state_encryption_key = "a-32-byte-or-longer-test-secret!!"

                [python]
                module_path = "python"

                [[microservice]]
                type = "python"
                name = "example"
            "#,
        )
        .unwrap();
        let python = cfg.python.unwrap();
        assert_eq!(python.module_path, "python");
        assert_eq!(python.venv, None);
        assert_eq!(python.max_concurrent_calls, 16);
        assert_eq!(python.call_timeout_seconds, 30);
    }

    #[test]
    fn python_configuration_is_required_and_strict() {
        let base = r#"
            base_url = "https://x"
            state_encryption_key = "a-32-byte-or-longer-test-secret!!"

            [[microservice]]
            type = "python"
            name = "example"
        "#;
        assert!(ProxyConfig::from_str(base).is_err());

        for field in [
            "module_path = \"\"",
            "module_path = \"python\"\nvenv = \"\"",
            "module_path = \"python\"\nmax_concurrent_calls = 0",
            "module_path = \"python\"\ncall_timeout_seconds = 0",
            "module_path = \"python\"\nunknown = true",
        ] {
            let value = format!("{base}\n[python]\n{field}");
            assert!(ProxyConfig::from_str(&value).is_err(), "accepted {field}");
        }
    }

    #[test]
    fn duplicate_microservice_names_are_rejected() {
        let err = ProxyConfig::from_str(
            r#"
                base_url = "https://x"
                state_encryption_key = "a-32-byte-or-longer-test-secret!!"

                [[microservice]]
                type = "first"
                name = "duplicate"

                [[microservice]]
                type = "second"
                name = "duplicate"
            "#,
        )
        .unwrap_err();
        assert!(err.to_string().contains("duplicate microservice name"));
    }
}
