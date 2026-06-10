//! Shared SAML plumbing used by both the SAML2 backend (SP role) and frontend
//! (IdP role): MDQ client construction, PEM cert extraction and verifier
//! assembly from DER certs.

use std::time::Duration;

use serde::Deserialize;

use gamlastan::crypto::keys::loader;
use gamlastan::crypto::{KeysManager, SamlVerifier};
use gamlastan_mdq::{MdqClient, MdqTransform, RequiredRole};

use tunnelbana_core::error::{Error, Result};

/// `[*.config.mdq]` — SAML Metadata Query Protocol source for entity metadata.
#[derive(Debug, Deserialize)]
pub struct MdqConfig {
    /// MDQ server base URL (a trailing slash is added if missing).
    pub url: String,
    /// PEM cert that signs the MDQ entity statements. Required unless
    /// `allow_unverified` is set.
    #[serde(default)]
    pub signing_cert_path: Option<String>,
    /// entityID → request-path transform: `"url_encoded"` (default) or `"sha1"`.
    #[serde(default)]
    pub transform: Option<String>,
    /// Role the fetched metadata must carry: `"idp"` (default), `"sp"`, `"any"`.
    #[serde(default)]
    pub require_role: Option<String>,
    /// Cache TTL (seconds) when the document omits `validUntil`/`cacheDuration`.
    #[serde(default)]
    pub fallback_ttl_secs: Option<u64>,
    /// Accept metadata that cannot be signature-verified (no cert). Insecure;
    /// testing only.
    #[serde(default)]
    pub allow_unverified: bool,
}

/// Build an MDQ client from the `[mdq]` config block.
pub fn build_mdq_client(cfg: &MdqConfig) -> Result<MdqClient> {
    let transform = match cfg.transform.as_deref() {
        None | Some("url_encoded") => MdqTransform::UrlEncoded,
        Some("sha1") => MdqTransform::Sha1,
        Some(other) => return Err(Error::Config(format!("unknown mdq.transform: {other}"))),
    };
    let role = match cfg.require_role.as_deref() {
        None | Some("idp") => RequiredRole::Idp,
        Some("sp") => RequiredRole::Sp,
        Some("any") => RequiredRole::Any,
        Some(other) => return Err(Error::Config(format!("unknown mdq.require_role: {other}"))),
    };

    let mut client = MdqClient::new(cfg.url.clone())
        .with_transform(transform)
        .require_role(role);
    if let Some(ttl) = cfg.fallback_ttl_secs {
        client = client.with_fallback_ttl(Duration::from_secs(ttl));
    }

    // A signing cert makes every fetched document signature-checked; without one
    // the operator must explicitly opt into the insecure unverified mode.
    if let Some(path) = &cfg.signing_cert_path {
        let pem = std::fs::read(path)
            .map_err(|e| Error::Config(format!("reading mdq.signing_cert_path: {e}")))?;
        client = client
            .add_signing_cert_pem(&pem)
            .map_err(|e| Error::Crypto(format!("loading mdq signing cert: {e}")))?;
    } else if cfg.allow_unverified {
        client = client.allow_unverified();
    } else {
        return Err(Error::Config(
            "mdq requires signing_cert_path (or allow_unverified=true for testing)".into(),
        ));
    }
    Ok(client)
}

/// Build a verifier from a set of DER-encoded signing certs: each cert is both
/// a verification key and a trusted chain anchor. Errors if no certs are
/// supplied — callers must fail closed rather than skip verification.
pub fn verifier_from_cert_ders(ders: &[Vec<u8>]) -> Result<SamlVerifier> {
    if ders.is_empty() {
        return Err(Error::Authn(
            "metadata carries no signing certificate".into(),
        ));
    }
    let mut km = KeysManager::new();
    for der in ders {
        let key = loader::load_x509_cert_der(der)
            .map_err(|e| Error::Crypto(format!("parsing signing cert: {e}")))?;
        km.add_key(key);
        km.add_trusted_cert(der.clone());
    }
    Ok(SamlVerifier::new(km))
}

/// Extract the base64 body of the first CERTIFICATE block from PEM.
pub fn extract_cert_b64(pem: &[u8]) -> String {
    let pem_str = String::from_utf8_lossy(pem);
    let mut in_cert = false;
    let mut b64 = String::new();
    for line in pem_str.lines() {
        if line.contains("BEGIN CERTIFICATE") {
            in_cert = true;
            continue;
        }
        if line.contains("END CERTIFICATE") {
            break;
        }
        if in_cert {
            b64.push_str(line.trim());
        }
    }
    b64
}
