//! `pairwiseid` — generate a privacy-preserving per-SP user identifier.
//!
//! Ports eduID's `GeneratePairwiseId` SATOSA micro-service. On the response
//! path it derives a stable-but-unlinkable identifier for the
//! `(requester, user)` pair: `HMAC-SHA256(salt, "{requester}-{subject-id}")`,
//! hex-encoded, with the user's scope re-appended. The result is written to the
//! internal `pairwise-id` attribute (consumed downstream by `nameid` for the
//! persistent NameID).

use std::fmt::Write as _;

use async_trait::async_trait;
use serde::Deserialize;
use tunnelbana_core::context::Context;
use tunnelbana_core::error::{Error, Result};
use tunnelbana_core::internal::InternalData;
use tunnelbana_core::mac::hmac_sha256;
use tunnelbana_core::plugin::{BuildContext, MicroService};

#[derive(Debug, Deserialize)]
struct PairwiseIdConfig {
    /// HMAC key. Required and non-empty: an empty salt would make the
    /// identifier trivially recomputable.
    pairwise_salt: String,
}

/// Generates the `pairwise-id` attribute from the `subject-id` attribute and
/// the requester (SATOSA/eduID: `GeneratePairwiseId`).
pub struct PairwiseId {
    name: String,
    salt: String,
}

impl PairwiseId {
    pub fn build(bx: &BuildContext) -> Result<Box<dyn MicroService>> {
        let cfg: PairwiseIdConfig = bx.parse_config()?;
        if cfg.pairwise_salt.is_empty() {
            return Err(Error::Config(format!(
                "pairwiseid {}: pairwise_salt must not be empty",
                bx.name
            )));
        }
        Ok(Box::new(PairwiseId {
            name: bx.name.clone(),
            salt: cfg.pairwise_salt,
        }))
    }
}

/// Lowercase hex encoding (matching Python's `hexdigest()`).
fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

#[async_trait]
impl MicroService for PairwiseId {
    fn name(&self) -> &str {
        &self.name
    }

    async fn process_response(
        &self,
        _ctx: &mut Context,
        mut data: InternalData,
    ) -> Result<InternalData> {
        let relying_party = data.requester.as_deref().unwrap_or("");
        let subject_id = data.attr_first("subject-id").ok_or_else(|| {
            Error::Authn(format!(
                "pairwiseid {}: no subject-id attribute to derive a pairwise id",
                self.name
            ))
        })?;
        // The scope is everything after the last '@'; falls back to the whole
        // value when unscoped.
        let user_scope = subject_id.rsplit('@').next().unwrap_or(subject_id);

        let sp_user_id = format!("{relying_party}-{subject_id}");
        let digest = hmac_sha256(self.salt.as_bytes(), sp_user_id.as_bytes());
        let pairwise = format!("{}@{user_scope}", hex(&digest));

        data.attributes.insert("pairwise-id".into(), vec![pairwise]);
        Ok(data)
    }
}

#[cfg(test)]
mod tests {
    use super::super::testutil::{bx, ctx, response_from};
    use super::*;

    fn expected(salt: &str, requester: &str, subject_id: &str) -> String {
        let scope = subject_id.rsplit('@').next().unwrap_or(subject_id);
        let digest = hmac_sha256(
            salt.as_bytes(),
            format!("{requester}-{subject_id}").as_bytes(),
        );
        format!("{}@{scope}", hex(&digest))
    }

    #[tokio::test]
    async fn derives_pairwise_id_with_scope() {
        let ms = PairwiseId::build(&bx(
            "pairwiseid",
            serde_json::json!({ "pairwise_salt": "a-secret-salt" }),
        ))
        .unwrap();

        let mut data = response_from("https://sp.example");
        data.set_attr("subject-id", "user@example.org");
        let data = ms.process_response(&mut ctx(), data).await.unwrap();

        assert_eq!(
            data.attr_first("pairwise-id"),
            Some(expected("a-secret-salt", "https://sp.example", "user@example.org").as_str())
        );
        // Scope is preserved.
        assert!(data
            .attr_first("pairwise-id")
            .unwrap()
            .ends_with("@example.org"));
    }

    #[tokio::test]
    async fn differs_per_requester() {
        let ms = PairwiseId::build(&bx(
            "pairwiseid",
            serde_json::json!({ "pairwise_salt": "salt" }),
        ))
        .unwrap();

        let mut a = response_from("https://sp-a.example");
        a.set_attr("subject-id", "user@example.org");
        let a = ms.process_response(&mut ctx(), a).await.unwrap();

        let mut b = response_from("https://sp-b.example");
        b.set_attr("subject-id", "user@example.org");
        let b = ms.process_response(&mut ctx(), b).await.unwrap();

        assert_ne!(a.attr_first("pairwise-id"), b.attr_first("pairwise-id"));
    }

    #[tokio::test]
    async fn missing_subject_id_is_authn_error() {
        let ms = PairwiseId::build(&bx(
            "pairwiseid",
            serde_json::json!({ "pairwise_salt": "salt" }),
        ))
        .unwrap();
        let data = response_from("https://sp.example");
        assert!(ms.process_response(&mut ctx(), data).await.is_err());
    }

    #[test]
    fn requires_non_empty_salt() {
        assert!(PairwiseId::build(&bx("pairwiseid", serde_json::json!({}))).is_err());
        assert!(PairwiseId::build(&bx(
            "pairwiseid",
            serde_json::json!({ "pairwise_salt": "" })
        ))
        .is_err());
    }
}
