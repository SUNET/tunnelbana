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

/// Scope a master secret to a plugin instance, for deriving per-instance keys
/// (e.g. the OIDC token-sealing key): material derived from the result cannot
/// be opened by a different instance sharing the same master secret.
pub fn scoped_secret(secret: &str, instance: &str) -> String {
    format!("{secret}:{instance}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use tunnelbana_oidc::tokens::{AuthCodePayload, TokenCodec};

    #[test]
    fn scoped_secret_differs_per_instance() {
        assert_ne!(scoped_secret("s", "a"), scoped_secret("s", "b"));
        assert_eq!(scoped_secret("s", "a"), scoped_secret("s", "a"));
    }

    fn payload() -> AuthCodePayload {
        AuthCodePayload {
            client_id: "rp-1".into(),
            redirect_uri: "https://rp.example.com/cb".into(),
            scope: "openid".into(),
            sub: "user-1".into(),
            nonce: None,
            code_challenge: None,
            code_challenge_method: None,
            claims: Default::default(),
            auth_time: 1,
            exp: u64::MAX,
            acr: None,
        }
    }

    #[test]
    fn tokens_sealed_by_one_instance_do_not_open_in_another() {
        // Two frontends sharing the master secret derive distinct sealing keys.
        let a = TokenCodec::new(&scoped_secret("master", "fe-a"));
        let b = TokenCodec::new(&scoped_secret("master", "fe-b"));
        let token = a.seal_code(&payload()).unwrap();
        assert!(b.open_code(&token).is_err());
        assert!(a.open_code(&token).is_ok());
    }

    #[test]
    fn previous_secrets_are_scoped_to_the_same_instance() {
        // Rotation: the previous secret, mixed with the same instance name,
        // still opens old tokens — but only within that instance.
        let old = TokenCodec::new(&scoped_secret("old-master", "fe-a"));
        let token = old.seal_code(&payload()).unwrap();
        let rotated = TokenCodec::new(&scoped_secret("new-master", "fe-a"))
            .with_previous_secrets(&[scoped_secret("old-master", "fe-a")]);
        assert!(rotated.open_code(&token).is_ok());
        let other = TokenCodec::new(&scoped_secret("new-master", "fe-b"))
            .with_previous_secrets(&[scoped_secret("old-master", "fe-b")]);
        assert!(other.open_code(&token).is_err());
    }
}
