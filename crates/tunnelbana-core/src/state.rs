//! Stateless session state, sealed into an encrypted cookie.
//!
//! All per-flow session data lives in the cookie — there is no server-side
//! store, so any worker can serve any request (matching SATOSA's design, but
//! with a clean modern AEAD scheme instead of LZMA+AES-CBC). The state is a
//! JSON object, deflate-compressed and then encrypted as a JWE compact token
//! (`dir` + `A256GCM`) using a 256-bit key derived from the configured
//! encryption secret via HKDF-SHA256. Compression happens *inside* the seal
//! (not via the JWE `zip` header, which grindvakt rejects for tokens crossing
//! trust boundaries): AEAD authentication runs before decompression, so only
//! self-sealed bytes ever reach the decompressor, and inflation is capped as
//! defense in depth.
//!
//! The sealed payload is an [`Envelope`] carrying an `iat` timestamp and a
//! format version alongside the state map, so a captured cookie is only valid
//! for a bounded window (the freshness check happens on every `unseal`). The
//! sealer also supports multiple decryption keys to allow zero-downtime key
//! rotation, and pins the accepted JWE algorithms to `dir` + `A256GCM`.

use crate::error::{Error, Result};
use hkdf::Hkdf;
use jose_rs::algorithm::{JweAlgorithm, JweEncryption};
use jose_rs::jwe::JweDecryptOptions;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::Sha256;

/// Default maximum lifetime of a sealed state cookie, in seconds (30 minutes).
/// A login handshake should complete well within this window.
pub const DEFAULT_TTL_SECONDS: u64 = 1800;

/// Maximum size of the cookie `name=value` pair, in bytes. Browsers cap a
/// single cookie at ~4 KB; sealing more than this would be silently dropped by
/// the client, so we fail loudly instead.
const MAX_COOKIE_BYTES: usize = 4096;

/// Current sealed-envelope format version.
const ENVELOPE_VERSION: u8 = 1;

/// Plaintext format tag prefixed to a deflate-compressed envelope. Legacy
/// (pre-compression) plaintexts are bare JSON and start with `{`, so the two
/// formats are distinguishable byte-for-byte and cookies sealed before a
/// deploy keep unsealing.
const PLAINTEXT_TAG_DEFLATE: u8 = 0x02;

/// Upper bound on the decompressed envelope size. The decompressor only ever
/// sees AEAD-authenticated bytes this proxy sealed itself, so this is defense
/// in depth against a decompression bomb, not a load-bearing control; the
/// cookie transport already caps the compressed input at ~4 KB.
const MAX_INFLATED_BYTES: usize = 64 * 1024;

/// Maximum accepted clock skew for an envelope `iat` ahead of the local clock.
/// A state cookie dated further into the future than this is rejected rather
/// than having its age clamped to zero, which would let a forged `iat` extend
/// a cookie's effective lifetime.
const MAX_IAT_SKEW_SECONDS: u64 = 60;

/// HKDF salt and info for state-key derivation. Fixed, public domain-separation
/// constants — they bind the derived key to this specific use.
const HKDF_SALT: &[u8] = b"tunnelbana-state-cookie-v1";
const HKDF_INFO: &[u8] = b"tunnelbana state seal: dir+A256GCM";

/// `__Host-` cookie prefix: the browser enforces `Secure`, `Path=/` and the
/// absence of a `Domain` attribute for any cookie whose name begins with this.
const HOST_PREFIX: &str = "__Host-";

/// The mutable per-request state map.
#[derive(Debug, Clone, Default)]
pub struct State {
    data: Map<String, Value>,
    /// Original issue time of an unsealed envelope. This is deliberately kept
    /// out of the public state map so request handlers cannot extend a flow's
    /// absolute lifetime by rewriting protocol data.
    issued_at: Option<u64>,
    /// When true, the state cookie is cleared in the response.
    pub delete: bool,
}

impl State {
    /// Create an empty state.
    pub fn new() -> Self {
        Self::default()
    }

    /// Get a namespaced sub-object (creating an empty view if absent).
    pub fn get(&self, namespace: &str) -> Option<&Value> {
        self.data.get(namespace)
    }

    /// Get a string value within a namespace.
    pub fn get_str(&self, namespace: &str, key: &str) -> Option<String> {
        self.data
            .get(namespace)?
            .as_object()?
            .get(key)?
            .as_str()
            .map(|s| s.to_string())
    }

    /// Set a string value within a namespace.
    pub fn set_str(&mut self, namespace: &str, key: &str, value: impl Into<String>) {
        let ns = self
            .data
            .entry(namespace.to_string())
            .or_insert_with(|| Value::Object(Map::new()));
        if let Some(obj) = ns.as_object_mut() {
            obj.insert(key.to_string(), Value::String(value.into()));
        }
    }

    /// Store an arbitrary JSON value within a namespace.
    pub fn set_value(&mut self, namespace: &str, key: &str, value: Value) {
        let ns = self
            .data
            .entry(namespace.to_string())
            .or_insert_with(|| Value::Object(Map::new()));
        if let Some(obj) = ns.as_object_mut() {
            obj.insert(key.to_string(), value);
        }
    }

    /// Fetch an arbitrary JSON value within a namespace.
    pub fn get_value(&self, namespace: &str, key: &str) -> Option<&Value> {
        self.data.get(namespace)?.as_object()?.get(key)
    }

    /// Remove a namespace entirely.
    pub fn clear_namespace(&mut self, namespace: &str) {
        self.data.remove(namespace);
    }
}

/// The sealed cookie payload: the state map plus freshness metadata. Serialized
/// as JSON and then encrypted; the `iat`/`v` fields are validated on `unseal`.
#[derive(Serialize, Deserialize)]
struct Envelope {
    /// Envelope format version.
    v: u8,
    /// Issued-at, Unix seconds. Used to enforce the cookie TTL.
    iat: u64,
    /// The opaque per-flow state map.
    data: Map<String, Value>,
}

/// Derive a 256-bit AEAD key from the configured secret via HKDF-SHA256.
///
/// HKDF (rather than a bare SHA-256) provides domain separation and is the
/// standard extract-then-expand KDF; combined with the minimum-length check
/// enforced at config load it resists offline brute-force of low-entropy
/// secrets far better than a single unsalted hash.
fn derive_key(secret: &str) -> Vec<u8> {
    let hk = Hkdf::<Sha256>::new(Some(HKDF_SALT), secret.as_bytes());
    let mut okm = [0u8; 32];
    hk.expand(HKDF_INFO, &mut okm)
        .expect("32 is a valid HKDF-SHA256 output length");
    okm.to_vec()
}

/// Deflate-compress a serialized envelope for sealing (ADR 0054).
///
/// Returns `[PLAINTEXT_TAG_DEFLATE] || deflate(json)`. The tag byte is what
/// lets [`StateSealer::decode_envelope`] tell this format apart from a legacy
/// bare-JSON plaintext (which always starts with `{`), so both formats can be
/// unsealed during a rolling upgrade. The result is what gets JWE-encrypted;
/// compression is deliberately *inside* the seal rather than a JWE `zip`
/// header, which grindvakt rejects.
fn compress_envelope(json: &[u8]) -> Result<Vec<u8>> {
    use std::io::Write;
    let mut encoder = flate2::write::DeflateEncoder::new(
        vec![PLAINTEXT_TAG_DEFLATE],
        flate2::Compression::default(),
    );
    encoder
        .write_all(json)
        .and_then(|()| encoder.finish())
        .map_err(|e| Error::State(format!("state compression failed: {e}")))
}

/// Inflate a deflate-compressed envelope back to its JSON bytes.
///
/// The input is the decrypted plaintext with the format tag already stripped.
/// Reading stops at [`MAX_INFLATED_BYTES`] + 1: the `take` bounds how much a
/// (theoretically) pathological stream could allocate, and landing past the
/// cap is reported as an error rather than truncated - a truncated envelope
/// must never parse as a smaller, valid one. Errors are returned as strings
/// because the caller only logs them and falls back to an empty state.
fn inflate_envelope(deflated: &[u8]) -> std::result::Result<Vec<u8>, String> {
    use std::io::Read;
    let mut json = Vec::new();
    flate2::read::DeflateDecoder::new(deflated)
        .take(MAX_INFLATED_BYTES as u64 + 1)
        .read_to_end(&mut json)
        .map_err(|e| e.to_string())?;
    if json.len() > MAX_INFLATED_BYTES {
        return Err(format!(
            "decompressed state exceeds the {MAX_INFLATED_BYTES}-byte cap"
        ));
    }
    Ok(json)
}

/// Current time as Unix seconds (saturating at 0 if the clock is before epoch).
fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Encrypts/decrypts [`State`] to/from a cookie value.
#[derive(Clone)]
pub struct StateSealer {
    /// 32-byte AEAD keys derived from the configured secret(s). `keys[0]` is the
    /// primary, used for sealing; every key is tried on `unseal` so that cookies
    /// sealed under a previous secret remain decryptable during key rotation.
    keys: Vec<Vec<u8>>,
    /// The operator-configured cookie name (before any `__Host-` prefix).
    raw_cookie_name: String,
    /// The effective cookie name actually emitted/read (may carry `__Host-`).
    cookie_name: String,
    secure: bool,
    same_site: String,
    /// Maximum age of sealed state. `None` disables the freshness check.
    ttl_seconds: Option<u64>,
    /// Maximum size of the cookie `name=value` pair.
    max_cookie_bytes: usize,
}

impl StateSealer {
    /// Build a sealer from the raw configured secret.
    pub fn new(secret: &str, cookie_name: impl Into<String>) -> Self {
        let raw = cookie_name.into();
        let mut sealer = Self {
            keys: vec![derive_key(secret)],
            raw_cookie_name: raw.clone(),
            cookie_name: raw,
            secure: true,
            same_site: "None".to_string(),
            ttl_seconds: Some(DEFAULT_TTL_SECONDS),
            max_cookie_bytes: MAX_COOKIE_BYTES,
        };
        sealer.recompute_name();
        sealer
    }

    /// Override cookie attributes (e.g. for local http testing).
    ///
    /// When `secure` is true the effective cookie name is given the `__Host-`
    /// prefix (the prefix requires `Secure`, so it is dropped when not secure).
    pub fn with_secure(mut self, secure: bool) -> Self {
        self.secure = secure;
        self.recompute_name();
        self
    }

    /// Set the `SameSite` attribute (`None`, `Lax`, or `Strict`).
    pub fn with_same_site(mut self, same_site: impl Into<String>) -> Self {
        self.same_site = same_site.into();
        self
    }

    /// Set the maximum age of sealed state. `None` (or a zero TTL) disables the
    /// server-side freshness check and the cookie `Max-Age` attribute.
    pub fn with_ttl_seconds(mut self, ttl_seconds: Option<u64>) -> Self {
        self.ttl_seconds = ttl_seconds.filter(|&t| t > 0);
        self
    }

    /// Register additional, decryption-only secrets (previous keys retained to
    /// allow cookies sealed before a rotation to keep decrypting). These are
    /// never used for sealing.
    pub fn with_previous_secrets(mut self, secrets: &[String]) -> Self {
        for s in secrets {
            if !s.is_empty() {
                self.keys.push(derive_key(s));
            }
        }
        self
    }

    /// Recompute the effective cookie name, applying or stripping the `__Host-`
    /// prefix to match the current `secure` setting.
    fn recompute_name(&mut self) {
        let base = self
            .raw_cookie_name
            .strip_prefix(HOST_PREFIX)
            .unwrap_or(&self.raw_cookie_name);
        self.cookie_name = if self.secure {
            format!("{HOST_PREFIX}{base}")
        } else {
            base.to_string()
        };
    }

    pub fn cookie_name(&self) -> &str {
        &self.cookie_name
    }

    /// Decode the state from a raw cookie value. Returns an empty state if the
    /// value is missing, undecryptable, or expired (treated as a fresh session).
    ///
    /// Decryption pins `dir` + `A256GCM` and tries every configured key. Failures
    /// are logged (without leaking plaintext) so that tampering, brute-force
    /// probing, and botched key rotations are observable rather than silent.
    pub fn unseal(&self, cookie_value: Option<&str>) -> State {
        let Some(token) = cookie_value else {
            return State::new();
        };
        if token.is_empty() {
            return State::new();
        }

        let opts = JweDecryptOptions::new(vec![JweAlgorithm::Dir], vec![JweEncryption::A256GCM]);

        let mut last_err = None;
        for key in &self.keys {
            match jose_rs::jwe::decrypt_with_options(key, token, &opts) {
                Ok(plaintext) => return self.decode_envelope(&plaintext),
                Err(e) => last_err = Some(e),
            }
        }

        // A non-empty cookie that decrypts under no key is a genuine anomaly
        // (tampering, a foreign cookie, or a key-rotation gap) — surface it.
        if let Some(e) = last_err {
            tracing::warn!(
                error = %e,
                "state cookie failed to decrypt under all keys; treating as fresh session"
            );
        }
        State::new()
    }

    /// Parse a decrypted envelope, enforcing version and freshness. Any problem
    /// yields a fresh empty state (fail-closed to "unauthenticated").
    fn decode_envelope(&self, plaintext: &[u8]) -> State {
        // Dispatch on the plaintext format: legacy (pre-compression) cookies
        // are bare JSON and start with `{`; current cookies carry the deflate
        // tag. The bytes are AEAD-authenticated, so only self-sealed data is
        // ever inflated.
        let json: std::borrow::Cow<'_, [u8]> = match plaintext.first() {
            Some(b'{') => std::borrow::Cow::Borrowed(plaintext),
            Some(&PLAINTEXT_TAG_DEFLATE) => match inflate_envelope(&plaintext[1..]) {
                Ok(json) => std::borrow::Cow::Owned(json),
                Err(e) => {
                    tracing::debug!(error = %e, "state cookie decrypted but failed to inflate");
                    return State::new();
                }
            },
            _ => {
                tracing::debug!("state cookie decrypted but plaintext format unrecognized");
                return State::new();
            }
        };
        let envelope: Envelope = match serde_json::from_slice(&json) {
            Ok(e) => e,
            Err(e) => {
                tracing::debug!(error = %e, "state cookie decrypted but envelope invalid");
                return State::new();
            }
        };

        if envelope.v != ENVELOPE_VERSION {
            tracing::debug!(version = envelope.v, "unrecognized state envelope version");
            return State::new();
        }

        if let Some(ttl) = self.ttl_seconds {
            let now = now_unix();
            if envelope.iat > now + MAX_IAT_SKEW_SECONDS {
                tracing::debug!(
                    iat = envelope.iat,
                    now,
                    "state cookie issued in the future beyond skew; treating as fresh session"
                );
                return State::new();
            }
            let age = now.saturating_sub(envelope.iat);
            if age >= ttl {
                tracing::debug!(age, ttl, "state cookie expired; treating as fresh session");
                return State::new();
            }
        }

        State {
            data: envelope.data,
            issued_at: Some(envelope.iat),
            delete: false,
        }
    }

    /// Seal the state into a `Set-Cookie` header value.
    pub fn seal(&self, state: &State) -> Result<String> {
        if state.delete {
            return Ok(self.clear_cookie());
        }
        let now = now_unix();
        // A response may update and reseal state many times during a login.
        // Preserve the first envelope's timestamp so the configured TTL is an
        // absolute bound, rather than a sliding window refreshed per request.
        let issued_at = state.issued_at.unwrap_or(now);
        let envelope = Envelope {
            v: ENVELOPE_VERSION,
            iat: issued_at,
            data: state.data.clone(),
        };
        let json = serde_json::to_vec(&envelope)?;
        // Enforce the inflation cap at seal time too: a highly compressible
        // envelope past the cap could still deflate under the cookie budget,
        // seal "successfully", and then be unconditionally dropped by the next
        // unseal - a silently unusable cookie that strands the flow. Failing
        // here turns that into an explicit error on the response that caused
        // it.
        if json.len() > MAX_INFLATED_BYTES {
            return Err(Error::State(format!(
                "state envelope is {} bytes, exceeds the {MAX_INFLATED_BYTES}-byte \
                 inflation cap; reduce the amount of state stored in the flow",
                json.len()
            )));
        }
        let plaintext = compress_envelope(&json)?;
        let token = jose_rs::jwe::encrypt(
            &self.keys[0],
            &plaintext,
            JweAlgorithm::Dir,
            JweEncryption::A256GCM,
        )
        .map_err(|e| Error::State(format!("seal failed: {e}")))?;

        // Guard against silently-dropped oversized cookies: check the
        // `name=value` pair length the browser actually limits.
        let pair_len = self.cookie_name.len() + 1 + token.len();
        if pair_len > self.max_cookie_bytes {
            return Err(Error::State(format!(
                "sealed state cookie is {pair_len} bytes, exceeds the {} byte limit; \
                 reduce the amount of state stored in the flow",
                self.max_cookie_bytes
            )));
        }

        let max_age = self.ttl_seconds.map(|ttl| {
            let elapsed = now.saturating_sub(issued_at);
            ttl.saturating_sub(elapsed) as i64
        });
        Ok(self.cookie_header(&token, max_age))
    }

    fn cookie_header(&self, value: &str, max_age: Option<i64>) -> String {
        let mut parts = vec![
            format!("{}={}", self.cookie_name, value),
            "Path=/".to_string(),
            "HttpOnly".to_string(),
            format!("SameSite={}", self.same_site),
        ];
        if self.secure {
            parts.push("Secure".to_string());
        }
        if let Some(age) = max_age {
            parts.push(format!("Max-Age={age}"));
        }
        parts.join("; ")
    }

    fn clear_cookie(&self) -> String {
        self.cookie_header("", Some(0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_cookie_roundtrip() {
        let sealer = StateSealer::new("a-very-secret-key", "TB_STATE").with_secure(false);
        let mut state = State::new();
        state.set_str("SATOSA_BASE", "requester", "https://sp.example.com");
        state.set_str("Saml2", "relay_state", "abc123");

        let cookie = sealer.seal(&state).unwrap();
        // Extract just the token value from "NAME=token; Path=/; ...".
        let token = cookie
            .split(';')
            .next()
            .unwrap()
            .strip_prefix("TB_STATE=")
            .unwrap();

        let restored = sealer.unseal(Some(token));
        assert_eq!(
            restored.get_str("SATOSA_BASE", "requester").as_deref(),
            Some("https://sp.example.com")
        );
        assert_eq!(
            restored.get_str("Saml2", "relay_state").as_deref(),
            Some("abc123")
        );
    }

    #[test]
    fn tampered_cookie_yields_empty_state() {
        let sealer = StateSealer::new("secret", "TB_STATE").with_secure(false);
        let restored = sealer.unseal(Some("not-a-valid-jwe-token"));
        assert!(restored.get_str("SATOSA_BASE", "requester").is_none());
    }

    #[test]
    fn delete_produces_clearing_cookie() {
        let sealer = StateSealer::new("secret", "TB_STATE").with_secure(false);
        let mut state = State::new();
        state.delete = true;
        let cookie = sealer.seal(&state).unwrap();
        assert!(cookie.contains("Max-Age=0"));
    }

    #[test]
    fn expired_cookie_yields_empty_state() {
        // TTL of 1 second; backdate the issued-at so it is already stale.
        let sealer = StateSealer::new("a-long-enough-test-secret-value", "TB_STATE")
            .with_secure(false)
            .with_ttl_seconds(Some(1));
        let mut state = State::new();
        state.set_str("ns", "k", "v");

        // Manually seal an envelope with a stale `iat`.
        let envelope = Envelope {
            v: ENVELOPE_VERSION,
            iat: now_unix().saturating_sub(10),
            data: {
                let mut m = Map::new();
                m.insert("ns".to_string(), serde_json::json!({ "k": "v" }));
                m
            },
        };
        let plaintext = serde_json::to_vec(&envelope).unwrap();
        let token = jose_rs::jwe::encrypt(
            &sealer.keys[0],
            &plaintext,
            JweAlgorithm::Dir,
            JweEncryption::A256GCM,
        )
        .unwrap();

        let restored = sealer.unseal(Some(&token));
        assert!(
            restored.get_str("ns", "k").is_none(),
            "expired cookie must be rejected"
        );
    }

    #[test]
    fn future_iat_beyond_skew_yields_empty_state() {
        let sealer = StateSealer::new("a-long-enough-test-secret-value", "TB_STATE")
            .with_secure(false)
            .with_ttl_seconds(Some(3600));

        // An `iat` far in the future must be rejected, not clamped to age 0.
        let envelope = Envelope {
            v: ENVELOPE_VERSION,
            iat: now_unix() + MAX_IAT_SKEW_SECONDS + 300,
            data: {
                let mut m = Map::new();
                m.insert("ns".to_string(), serde_json::json!({ "k": "v" }));
                m
            },
        };
        let plaintext = serde_json::to_vec(&envelope).unwrap();
        let token = jose_rs::jwe::encrypt(
            &sealer.keys[0],
            &plaintext,
            JweAlgorithm::Dir,
            JweEncryption::A256GCM,
        )
        .unwrap();

        let restored = sealer.unseal(Some(&token));
        assert!(
            restored.get_str("ns", "k").is_none(),
            "cookie dated beyond the accepted skew must be rejected"
        );
    }

    #[test]
    fn iat_within_skew_survives() {
        let sealer = StateSealer::new("a-long-enough-test-secret-value", "TB_STATE")
            .with_secure(false)
            .with_ttl_seconds(Some(3600));

        let envelope = Envelope {
            v: ENVELOPE_VERSION,
            iat: now_unix() + 5,
            data: {
                let mut m = Map::new();
                m.insert("ns".to_string(), serde_json::json!({ "k": "v" }));
                m
            },
        };
        let plaintext = serde_json::to_vec(&envelope).unwrap();
        let token = jose_rs::jwe::encrypt(
            &sealer.keys[0],
            &plaintext,
            JweAlgorithm::Dir,
            JweEncryption::A256GCM,
        )
        .unwrap();

        let restored = sealer.unseal(Some(&token));
        assert_eq!(restored.get_str("ns", "k").as_deref(), Some("v"));
    }

    #[test]
    fn fresh_cookie_within_ttl_survives() {
        let sealer = StateSealer::new("a-long-enough-test-secret-value", "TB_STATE")
            .with_secure(false)
            .with_ttl_seconds(Some(3600));
        let mut state = State::new();
        state.set_str("ns", "k", "v");
        let cookie = sealer.seal(&state).unwrap();
        let token = cookie
            .split(';')
            .next()
            .unwrap()
            .strip_prefix("TB_STATE=")
            .unwrap();
        let restored = sealer.unseal(Some(token));
        assert_eq!(restored.get_str("ns", "k").as_deref(), Some("v"));
    }

    #[test]
    fn ttl_appears_as_max_age() {
        let sealer = StateSealer::new("a-long-enough-test-secret-value", "TB_STATE")
            .with_secure(false)
            .with_ttl_seconds(Some(900));
        let cookie = sealer.seal(&State::new()).unwrap();
        assert!(cookie.contains("Max-Age=900"), "cookie: {cookie}");
    }

    #[test]
    fn resealing_preserves_absolute_expiry() {
        let sealer = StateSealer::new("a-long-enough-test-secret-value", "TB_STATE")
            .with_secure(false)
            .with_ttl_seconds(Some(900));
        let original_iat = now_unix().saturating_sub(300);
        let state = State {
            data: Map::new(),
            issued_at: Some(original_iat),
            delete: false,
        };

        let cookie = sealer.seal(&state).unwrap();
        assert!(cookie.contains("Max-Age=600"), "cookie: {cookie}");

        let token = cookie
            .split(';')
            .next()
            .unwrap()
            .strip_prefix("TB_STATE=")
            .unwrap();
        let restored = sealer.unseal(Some(token));
        assert_eq!(restored.issued_at, Some(original_iat));
    }

    #[test]
    fn host_prefix_applied_when_secure() {
        let secure = StateSealer::new("a-long-enough-test-secret-value", "TB_STATE");
        assert_eq!(secure.cookie_name(), "__Host-TB_STATE");
        // Idempotent: an already-prefixed configured name is not doubled.
        let prefixed = StateSealer::new("a-long-enough-test-secret-value", "__Host-TB_STATE");
        assert_eq!(prefixed.cookie_name(), "__Host-TB_STATE");
        // Dropped when not secure (so the prefix's Secure requirement holds).
        let insecure = secure.with_secure(false);
        assert_eq!(insecure.cookie_name(), "TB_STATE");
    }

    /// Rolling-upgrade compatibility (ADR 0054): a cookie sealed by a
    /// pre-compression proxy contains a bare JSON envelope (first byte `{`).
    /// `unseal` must recognize that legacy plaintext and restore the state,
    /// so in-flight logins survive a deploy that introduces compression.
    #[test]
    fn legacy_uncompressed_cookie_still_unseals() {
        let sealer = StateSealer::new("a-long-enough-test-secret-value", "TB_STATE")
            .with_secure(false)
            .with_ttl_seconds(Some(3600));

        // A cookie sealed before compression landed: bare JSON plaintext.
        let envelope = Envelope {
            v: ENVELOPE_VERSION,
            iat: now_unix(),
            data: {
                let mut m = Map::new();
                m.insert("ns".to_string(), serde_json::json!({ "k": "v" }));
                m
            },
        };
        let plaintext = serde_json::to_vec(&envelope).unwrap();
        assert_eq!(plaintext[0], b'{');
        let token = jose_rs::jwe::encrypt(
            &sealer.keys[0],
            &plaintext,
            JweAlgorithm::Dir,
            JweEncryption::A256GCM,
        )
        .unwrap();

        let restored = sealer.unseal(Some(&token));
        assert_eq!(restored.get_str("ns", "k").as_deref(), Some("v"));
    }

    /// The point of ADR 0054: state whose bare-JSON JWE would exceed the
    /// 4096-byte browser cookie cap seals successfully once deflated, and
    /// still round-trips intact. The payload mimics real state (many long,
    /// similar URLs), which is exactly what deflate compresses well.
    #[test]
    fn compression_shrinks_the_sealed_cookie() {
        let sealer =
            StateSealer::new("a-long-enough-test-secret-value", "TB_STATE").with_secure(false);
        // Repetitive, URL-heavy state whose bare-JSON JWE would blow the 4 KB
        // cookie budget; deflated it seals and round-trips.
        let mut state = State::new();
        for i in 0..40 {
            state.set_str(
                "requests",
                &format!("entity-{i}"),
                format!("https://very-long-idp-hostname-{i}.federation.example.org/idp/profile/SAML2/Redirect/SSO"),
            );
        }
        let uncompressed_len = serde_json::to_vec(state.get("requests").unwrap())
            .unwrap()
            .len();
        assert!(
            uncompressed_len > 3500,
            "payload too small: {uncompressed_len}"
        );

        let cookie = sealer.seal(&state).unwrap();
        assert!(cookie.len() < uncompressed_len, "no compression win");
        let token = cookie
            .split(';')
            .next()
            .unwrap()
            .strip_prefix("TB_STATE=")
            .unwrap();
        let restored = sealer.unseal(Some(token));
        assert_eq!(
            restored.get_str("requests", "entity-39").as_deref(),
            Some("https://very-long-idp-hostname-39.federation.example.org/idp/profile/SAML2/Redirect/SSO")
        );
    }

    /// Defense-in-depth check on the inflation cap: a correctly tagged,
    /// correctly encrypted plaintext that would decompress past
    /// `MAX_INFLATED_BYTES` is discarded (empty, unauthenticated state)
    /// instead of being buffered without bound. Only the proxy itself could
    /// ever produce such a token (AEAD blocks forgeries), so this guards
    /// against our own bugs, not attackers.
    #[test]
    fn oversized_inflation_yields_empty_state() {
        use std::io::Write;
        let sealer =
            StateSealer::new("a-long-enough-test-secret-value", "TB_STATE").with_secure(false);

        // A (self-sealed-format) plaintext that inflates past the cap must be
        // dropped, not buffered without bound.
        let bomb_json = format!(
            r#"{{"v":1,"iat":{},"data":{{"ns":{{"k":"{}"}}}}}}"#,
            now_unix(),
            "x".repeat(MAX_INFLATED_BYTES)
        );
        let mut encoder = flate2::write::DeflateEncoder::new(
            vec![PLAINTEXT_TAG_DEFLATE],
            flate2::Compression::default(),
        );
        encoder.write_all(bomb_json.as_bytes()).unwrap();
        let plaintext = encoder.finish().unwrap();
        let token = jose_rs::jwe::encrypt(
            &sealer.keys[0],
            &plaintext,
            JweAlgorithm::Dir,
            JweEncryption::A256GCM,
        )
        .unwrap();

        let restored = sealer.unseal(Some(&token));
        assert!(restored.get_str("ns", "k").is_none());
    }

    /// The inflation cap is enforced at seal time too: a highly compressible
    /// envelope past `MAX_INFLATED_BYTES` (e.g. ~64 KiB of repeated data
    /// deflates to a handful of bytes) would otherwise seal under the cookie
    /// budget and then be unconditionally dropped by the next unseal - a
    /// silently unusable cookie. Sealing it must fail loudly instead.
    #[test]
    fn oversized_envelope_fails_at_seal_time() {
        let sealer =
            StateSealer::new("a-long-enough-test-secret-value", "TB_STATE").with_secure(false);
        let mut state = State::new();
        // Repeated data past the cap: compresses to well under 4 KB.
        state.set_str("ns", "k", "x".repeat(MAX_INFLATED_BYTES + 1));
        let err = sealer.seal(&state).unwrap_err();
        assert!(
            err.to_string().contains("inflation cap"),
            "unexpected error: {err}"
        );
    }

    /// A decrypted plaintext that is neither legacy JSON (`{`) nor the
    /// deflate format (`0x02`) - e.g. sealed by some future version - is
    /// treated like any other bad envelope: fail closed to an empty state
    /// rather than guessing at the format.
    #[test]
    fn unrecognized_plaintext_format_yields_empty_state() {
        let sealer =
            StateSealer::new("a-long-enough-test-secret-value", "TB_STATE").with_secure(false);
        let token = jose_rs::jwe::encrypt(
            &sealer.keys[0],
            &[0x7f, 1, 2, 3],
            JweAlgorithm::Dir,
            JweEncryption::A256GCM,
        )
        .unwrap();
        let restored = sealer.unseal(Some(&token));
        assert!(restored.get_str("ns", "k").is_none());
    }

    #[test]
    fn key_rotation_decrypts_old_cookies() {
        // Seal under the old secret.
        let old =
            StateSealer::new("the-old-rotation-secret-value-32b", "TB_STATE").with_secure(false);
        let mut state = State::new();
        state.set_str("ns", "k", "v");
        let cookie = old.seal(&state).unwrap();
        let token = cookie
            .split(';')
            .next()
            .unwrap()
            .strip_prefix("TB_STATE=")
            .unwrap()
            .to_string();

        // New sealer: primary is the new secret, old kept as a previous secret.
        let rotated = StateSealer::new("the-new-rotation-secret-value-32b", "TB_STATE")
            .with_secure(false)
            .with_previous_secrets(&["the-old-rotation-secret-value-32b".to_string()]);

        let restored = rotated.unseal(Some(&token));
        assert_eq!(restored.get_str("ns", "k").as_deref(), Some("v"));
    }
}
