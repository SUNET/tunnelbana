//! Shared helper to load a [`SigningKey`] from plugin config (JWK or PEM file).

use tunnelbana_core::error::{Error, Result};
use tunnelbana_core::keys::{signing_key_from_jwk_json, signing_key_from_pem, SigningKey};

/// Load a signing key from an inline JWK value or a PEM/DER file path.
pub fn load_signing_key(
    jwk: Option<&serde_json::Value>,
    pem_path: Option<&str>,
    jwk_path: Option<&str>,
    alg: Option<&str>,
    kid: Option<&str>,
) -> Result<SigningKey> {
    if let Some(jwk) = jwk {
        let json = serde_json::to_string(jwk)?;
        return signing_key_from_jwk_json(&json, alg, kid);
    }
    if let Some(path) = jwk_path {
        let json = std::fs::read_to_string(path)
            .map_err(|e| Error::Config(format!("reading jwk file {path}: {e}")))?;
        return signing_key_from_jwk_json(&json, alg, kid);
    }
    if let Some(path) = pem_path {
        let bytes = std::fs::read(path)
            .map_err(|e| Error::Config(format!("reading key file {path}: {e}")))?;
        return signing_key_from_pem(&bytes, alg, kid);
    }
    Err(Error::Config(
        "no signing key configured (set signing_jwk, signing_jwk_path or signing_key_path)".into(),
    ))
}
