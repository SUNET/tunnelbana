//! `pairwiseid` — generate a privacy-preserving per-SP user identifier.
//!
//! Ports eduID's `GeneratePairwiseId` SATOSA micro-service. On the response
//! path it derives a stable-but-unlinkable identifier for the
//! `(requester, user)` pair: `HMAC-SHA256` over a framed
//! `{requester, subject-id}` input, hex-encoded, with the user's scope
//! re-appended. The result is written to the internal `pairwise-id`
//! attribute (consumed downstream by `nameid` for the persistent NameID).
//!
//! Two HMAC input framings exist (ADR 0035):
//!
//! - `legacy` (default): plain `{requester}-{subject-id}` concatenation,
//!   byte-compatible with earlier releases. It is not injective: distinct
//!   pairs such as `("a-b", "c")` and `("a", "b-c")` hash identically,
//!   which can break cross-SP unlinkability.
//! - `v1` (opt-in via `framing = "v1"`): versioned, length-prefixed
//!   `tbpwid-v1:{requester_len}:{requester}:{subject-id}` (cf.
//!   `primary_identifier`), which is injective. Enabling it changes all
//!   derived pairwise identifiers; stored account links must be migrated
//!   before enabling it.

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
    /// HMAC input framing: `legacy` (default, backward-compatible) or `v1`
    /// (injective, length-prefixed; changes all derived identifiers).
    framing: Option<String>,
}

/// Which HMAC input framing to use (ADR 0035).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Framing {
    /// `{requester}-{subject-id}` — byte-compatible with earlier releases.
    Legacy,
    /// `tbpwid-v1:{requester_len}:{requester}:{subject-id}` — injective.
    V1,
}

/// Generates the `pairwise-id` attribute from the `subject-id` attribute and
/// the requester (SATOSA/eduID: `GeneratePairwiseId`).
pub struct PairwiseId {
    name: String,
    salt: String,
    framing: Framing,
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
        let framing = match cfg.framing.as_deref() {
            None | Some("legacy") => Framing::Legacy,
            Some("v1") => Framing::V1,
            Some(other) => {
                return Err(Error::Config(format!(
                    "pairwiseid {}: unknown framing {other:?} (expected \"legacy\" or \"v1\")",
                    bx.name
                )));
            }
        };
        Ok(Box::new(PairwiseId {
            name: bx.name.clone(),
            salt: cfg.pairwise_salt,
            framing,
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

        let sp_user_id = match self.framing {
            // Backward-compatible concatenation; not injective (see module
            // docs), kept as the default so existing account links survive
            // upgrades.
            Framing::Legacy => format!("{relying_party}-{subject_id}"),
            // Versioned, length-prefixed framing (cf. primary_identifier):
            // the requester length makes the requester/subject boundary
            // unambiguous, so distinct (requester, subject-id) pairs cannot
            // collide.
            Framing::V1 => format!(
                "tbpwid-v1:{}:{relying_party}:{subject_id}",
                relying_party.len()
            ),
        };
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
            format!("tbpwid-v1:{}:{requester}:{subject_id}", requester.len()).as_bytes(),
        );
        format!("{}@{scope}", hex(&digest))
    }

    fn expected_legacy(salt: &str, requester: &str, subject_id: &str) -> String {
        let scope = subject_id.rsplit('@').next().unwrap_or(subject_id);
        let digest = hmac_sha256(
            salt.as_bytes(),
            format!("{requester}-{subject_id}").as_bytes(),
        );
        format!("{}@{scope}", hex(&digest))
    }

    #[tokio::test]
    async fn legacy_framing_is_the_default() {
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
            Some(
                expected_legacy("a-secret-salt", "https://sp.example", "user@example.org").as_str()
            )
        );
        // Scope is preserved.
        assert!(data
            .attr_first("pairwise-id")
            .unwrap()
            .ends_with("@example.org"));
    }

    #[tokio::test]
    async fn explicit_legacy_framing_matches_default() {
        let ms = PairwiseId::build(&bx(
            "pairwiseid",
            serde_json::json!({ "pairwise_salt": "salt", "framing": "legacy" }),
        ))
        .unwrap();

        let mut data = response_from("https://sp.example");
        data.set_attr("subject-id", "user@example.org");
        let data = ms.process_response(&mut ctx(), data).await.unwrap();

        assert_eq!(
            data.attr_first("pairwise-id"),
            Some(expected_legacy("salt", "https://sp.example", "user@example.org").as_str())
        );
    }

    #[tokio::test]
    async fn v1_framing_derives_pairwise_id_with_scope() {
        let ms = PairwiseId::build(&bx(
            "pairwiseid",
            serde_json::json!({ "pairwise_salt": "a-secret-salt", "framing": "v1" }),
        ))
        .unwrap();

        let mut data = response_from("https://sp.example");
        data.set_attr("subject-id", "user@example.org");
        let data = ms.process_response(&mut ctx(), data).await.unwrap();

        assert_eq!(
            data.attr_first("pairwise-id"),
            Some(expected("a-secret-salt", "https://sp.example", "user@example.org").as_str())
        );
        assert!(data
            .attr_first("pairwise-id")
            .unwrap()
            .ends_with("@example.org"));
    }

    #[tokio::test]
    async fn differs_per_requester() {
        let ms = PairwiseId::build(&bx(
            "pairwiseid",
            serde_json::json!({ "pairwise_salt": "salt", "framing": "v1" }),
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
    async fn v1_framing_is_unambiguous_across_requester_boundary() {
        // ("a-b", "c") and ("a", "b-c") produced the same HMAC input with the
        // legacy "{requester}-{subject-id}" concatenation.
        let ms = PairwiseId::build(&bx(
            "pairwiseid",
            serde_json::json!({ "pairwise_salt": "salt", "framing": "v1" }),
        ))
        .unwrap();

        let mut a = response_from("a-b");
        a.set_attr("subject-id", "c");
        let a = ms.process_response(&mut ctx(), a).await.unwrap();

        let mut b = response_from("a");
        b.set_attr("subject-id", "b-c");
        let b = ms.process_response(&mut ctx(), b).await.unwrap();

        assert_ne!(a.attr_first("pairwise-id"), b.attr_first("pairwise-id"));
        assert_eq!(
            a.attr_first("pairwise-id"),
            Some(expected("salt", "a-b", "c").as_str())
        );
    }

    #[tokio::test]
    async fn legacy_framing_documents_boundary_collision() {
        // The legacy framing is kept for backward compatibility; this test
        // pins the known collision so the trade-off is explicit.
        let ms = PairwiseId::build(&bx(
            "pairwiseid",
            serde_json::json!({ "pairwise_salt": "salt" }),
        ))
        .unwrap();

        let mut a = response_from("a-b");
        a.set_attr("subject-id", "c");
        let a = ms.process_response(&mut ctx(), a).await.unwrap();

        let mut b = response_from("a");
        b.set_attr("subject-id", "b-c");
        let b = ms.process_response(&mut ctx(), b).await.unwrap();

        // The digest parts collide even though the re-appended scopes differ.
        let digest_of = |data: &InternalData| {
            data.attr_first("pairwise-id")
                .unwrap()
                .split('@')
                .next()
                .unwrap()
                .to_owned()
        };
        assert_eq!(digest_of(&a), digest_of(&b));
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

    #[test]
    fn rejects_unknown_framing() {
        assert!(PairwiseId::build(&bx(
            "pairwiseid",
            serde_json::json!({ "pairwise_salt": "salt", "framing": "V1" })
        ))
        .is_err());
        assert!(PairwiseId::build(&bx(
            "pairwiseid",
            serde_json::json!({ "pairwise_salt": "salt", "framing": "bogus" })
        ))
        .is_err());
    }
}
