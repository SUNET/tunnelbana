//! `legacy_eptid` — generate PySAML2-compatible MD5 eduPersonTargetedID values.
//!
//! This is a migration-only service for deployments that previously used
//! PySAML2's stock `saml2.eptid.Eptid`: `idp!sp!md5(user || sp || secret)`.
//! MD5 is intentionally guarded by `allow_legacy_md5`.

use async_trait::async_trait;
use md5::{Digest, Md5};
use serde::Deserialize;
use tunnelbana_core::context::Context;
use tunnelbana_core::error::{Error, Result};
use tunnelbana_core::internal::{InternalData, SubjectType};
use tunnelbana_core::plugin::{BuildContext, MicroService};

fn default_source_attribute() -> String {
    "subject-id".to_string()
}

fn default_target_attribute() -> String {
    "edupersontargetedid".to_string()
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Deserialize)]
struct LegacyEptidConfig {
    /// IdP entityID used in the legacy `idp!sp!hash` value.
    idp_entity_id: String,
    /// PySAML2 EPTID secret.
    secret: String,
    /// Source attribute whose first value is the PySAML2 `user_id` argument.
    #[serde(default = "default_source_attribute")]
    source_attribute: String,
    /// Use `InternalData.subject_id` instead of `source_attribute`.
    #[serde(default)]
    source_subject_id: bool,
    /// Optional SP entityID override. Defaults to `InternalData.requester`.
    #[serde(default)]
    sp_entity_id: Option<String>,
    /// Optional requester allowlist. Empty means apply to every requester.
    #[serde(default)]
    requesters: Vec<String>,
    /// Internal attribute receiving the EPTID value.
    #[serde(default = "default_target_attribute")]
    target_attribute: String,
    /// Write the generated value to `target_attribute`.
    #[serde(default = "default_true")]
    release_attribute: bool,
    /// Replace `InternalData.subject_id` with the generated EPTID and mark it
    /// persistent. Use only for SPs whose account key is the legacy EPTID.
    #[serde(default)]
    set_subject_id: bool,
    /// Required guard for PySAML2 MD5 compatibility.
    #[serde(default)]
    allow_legacy_md5: bool,
}

/// PySAML2 stock EPTID compatibility.
pub struct LegacyEptid {
    name: String,
    idp_entity_id: String,
    secret: String,
    source_attribute: String,
    source_subject_id: bool,
    sp_entity_id: Option<String>,
    requesters: Vec<String>,
    target_attribute: String,
    release_attribute: bool,
    set_subject_id: bool,
}

impl LegacyEptid {
    pub fn build(bx: &BuildContext) -> Result<Box<dyn MicroService>> {
        let cfg: LegacyEptidConfig = bx.parse_config()?;
        if !cfg.allow_legacy_md5 {
            return Err(Error::Config(format!(
                "legacy_eptid {}: PySAML2 MD5 compatibility requires allow_legacy_md5 = true",
                bx.name
            )));
        }
        if cfg.idp_entity_id.is_empty() {
            return Err(Error::Config(format!(
                "legacy_eptid {}: idp_entity_id must not be empty",
                bx.name
            )));
        }
        if cfg.secret.is_empty() {
            return Err(Error::Config(format!(
                "legacy_eptid {}: secret must not be empty",
                bx.name
            )));
        }
        if cfg.source_attribute.is_empty() && !cfg.source_subject_id {
            return Err(Error::Config(format!(
                "legacy_eptid {}: source_attribute must not be empty",
                bx.name
            )));
        }
        if cfg.target_attribute.is_empty() && cfg.release_attribute {
            return Err(Error::Config(format!(
                "legacy_eptid {}: target_attribute must not be empty when release_attribute = true",
                bx.name
            )));
        }
        if !cfg.release_attribute && !cfg.set_subject_id {
            return Err(Error::Config(format!(
                "legacy_eptid {}: enable release_attribute, set_subject_id, or both",
                bx.name
            )));
        }

        tracing::warn!(
            "legacy_eptid {}: legacy PySAML2 MD5 EPTID compatibility enabled",
            bx.name
        );

        Ok(Box::new(LegacyEptid {
            name: bx.name.clone(),
            idp_entity_id: cfg.idp_entity_id,
            secret: cfg.secret,
            source_attribute: cfg.source_attribute,
            source_subject_id: cfg.source_subject_id,
            sp_entity_id: cfg.sp_entity_id,
            requesters: cfg.requesters,
            target_attribute: cfg.target_attribute,
            release_attribute: cfg.release_attribute,
            set_subject_id: cfg.set_subject_id,
        }))
    }

    fn make(&self, sp_entity_id: &str, user_id: &str) -> String {
        let mut digest = Md5::new();
        digest.update(user_id.as_bytes());
        digest.update(sp_entity_id.as_bytes());
        digest.update(self.secret.as_bytes());
        format!(
            "{}!{}!{:x}",
            self.idp_entity_id,
            sp_entity_id,
            digest.finalize()
        )
    }
}

#[async_trait]
impl MicroService for LegacyEptid {
    fn name(&self) -> &str {
        &self.name
    }

    async fn process_response(
        &self,
        _ctx: &mut Context,
        mut data: InternalData,
    ) -> Result<InternalData> {
        if !self.requesters.is_empty() {
            let Some(requester) = data.requester.as_deref() else {
                return Ok(data);
            };
            if !self.requesters.iter().any(|allowed| allowed == requester) {
                return Ok(data);
            }
        }

        let sp_entity_id = self
            .sp_entity_id
            .as_deref()
            .or(data.requester.as_deref())
            .ok_or_else(|| {
                Error::Authn(format!(
                    "legacy_eptid {}: no requester/SP entityID available",
                    self.name
                ))
            })?;

        let user_id = if self.source_subject_id {
            data.subject_id.as_deref().ok_or_else(|| {
                Error::Authn(format!(
                    "legacy_eptid {}: no subject_id available",
                    self.name
                ))
            })?
        } else {
            data.attr_first(&self.source_attribute).ok_or_else(|| {
                Error::Authn(format!(
                    "legacy_eptid {}: missing source attribute {}",
                    self.name, self.source_attribute
                ))
            })?
        };

        let eptid = self.make(sp_entity_id, user_id);
        if self.release_attribute {
            data.set_attr(self.target_attribute.clone(), eptid.clone());
        }
        if self.set_subject_id {
            data.subject_id = Some(eptid);
            data.subject_type = SubjectType::Persistent;
        }
        Ok(data)
    }
}

#[cfg(test)]
mod tests {
    use super::super::testutil::{bx, ctx, response_from};
    use super::*;

    fn config() -> serde_json::Value {
        serde_json::json!({
            "idp_entity_id": "https://idp.example.com",
            "secret": "s3cr3t",
            "allow_legacy_md5": true
        })
    }

    #[test]
    fn requires_explicit_md5_guard() {
        assert!(LegacyEptid::build(&bx(
            "legacy_eptid",
            serde_json::json!({
                "idp_entity_id": "https://idp.example.com",
                "secret": "s3cr3t"
            })
        ))
        .is_err());
    }

    #[tokio::test]
    async fn emits_pysaml2_md5_eptid_attribute() {
        let service = LegacyEptid::build(&bx("legacy_eptid", config())).unwrap();
        let mut data = response_from("https://sp.example.com");
        data.set_attr("subject-id", "alice");

        let data = service.process_response(&mut ctx(), data).await.unwrap();

        assert_eq!(
            data.attr_first("edupersontargetedid"),
            Some("https://idp.example.com!https://sp.example.com!f6ecff9c9e19881f47d0078989d14d59")
        );
        assert!(data.subject_id.is_none());
    }

    #[tokio::test]
    async fn can_replace_subject_id_for_legacy_persistent_nameid() {
        let mut cfg = config();
        cfg["set_subject_id"] = serde_json::json!(true);
        cfg["release_attribute"] = serde_json::json!(false);
        cfg["source_subject_id"] = serde_json::json!(true);

        let service = LegacyEptid::build(&bx("legacy_eptid", cfg)).unwrap();
        let mut data = response_from("https://sp.example.com");
        data.subject_id = Some("alice".into());

        let data = service.process_response(&mut ctx(), data).await.unwrap();

        assert_eq!(
            data.subject_id.as_deref(),
            Some("https://idp.example.com!https://sp.example.com!f6ecff9c9e19881f47d0078989d14d59")
        );
        assert_eq!(data.subject_type, SubjectType::Persistent);
        assert!(data.attr_first("edupersontargetedid").is_none());
    }

    #[tokio::test]
    async fn requester_allowlist_skips_other_sps() {
        let mut cfg = config();
        cfg["requesters"] = serde_json::json!(["https://legacy-sp.example.com"]);

        let service = LegacyEptid::build(&bx("legacy_eptid", cfg)).unwrap();
        let mut data = response_from("https://new-sp.example.com");
        data.set_attr("subject-id", "alice");

        let data = service.process_response(&mut ctx(), data).await.unwrap();

        assert!(data.attr_first("edupersontargetedid").is_none());
    }
}
