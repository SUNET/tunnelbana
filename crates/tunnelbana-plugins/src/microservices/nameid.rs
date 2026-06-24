//! `nameid` — derive the SAML subject identifier from released attributes
//! according to the requested NameID format.
//!
//! Ports the response half of eduID's `nameid` SATOSA micro-service. tunnelbana's
//! SAML frontend already negotiates the NameID *format* on the request path and
//! generates a fresh opaque value for transient NameIDs, so this service only
//! shapes the subject *value* for the non-transient formats eduID supports:
//!
//! - **persistent** → the hash part of the `pairwise-id` attribute (everything
//!   before the `@scope`), as produced by the [`PairwiseId`](super::PairwiseId)
//!   service.
//! - **emailAddress** → the `mail` attribute.
//! - **transient / unspecified** → leave the value to the frontend (which mints
//!   a fresh opaque id); only the subject *type* is marked transient.
//!
//! The resolved format is read from the shared base state namespace
//! ([`KEY_NAME_ID_FORMAT`]) published by the SAML frontend. When it is absent
//! (e.g. an OIDC flow), the service passes the response through unchanged.

use async_trait::async_trait;
use gamlastan::core::constants;
use tunnelbana_core::context::{Context, KEY_NAME_ID_FORMAT, STATE_KEY_BASE};
use tunnelbana_core::error::{Error, Result};
use tunnelbana_core::internal::{InternalData, SubjectType};
use tunnelbana_core::plugin::{BuildContext, MicroService};

/// Selects the SAML subject id from attributes per the requested NameID format
/// (SATOSA/eduID: `nameid`).
pub struct NameId {
    name: String,
}

impl NameId {
    pub fn build(bx: &BuildContext) -> Result<Box<dyn MicroService>> {
        Ok(Box::new(NameId {
            name: bx.name.clone(),
        }))
    }
}

#[async_trait]
impl MicroService for NameId {
    fn name(&self) -> &str {
        &self.name
    }

    async fn process_response(
        &self,
        ctx: &mut Context,
        mut data: InternalData,
    ) -> Result<InternalData> {
        let Some(format) = ctx.state.get_str(STATE_KEY_BASE, KEY_NAME_ID_FORMAT) else {
            // No SAML NameID format in play (e.g. an OIDC frontend): nothing to do.
            return Ok(data);
        };

        match format.as_str() {
            constants::NAMEID_TRANSIENT | constants::NAMEID_UNSPECIFIED => {
                // The frontend mints a fresh opaque value for transient NameIDs;
                // just mark the subject type.
                data.subject_type = SubjectType::Transient;
            }
            constants::NAMEID_PERSISTENT => {
                let pairwise = data.attr_first("pairwise-id").ok_or_else(|| {
                    Error::Authn(format!(
                        "nameid {}: no pairwise-id to use as persistent NameID",
                        self.name
                    ))
                })?;
                // The persistent NameID is the hash part, without the @scope.
                let value = pairwise.split('@').next().unwrap_or(pairwise).to_string();
                data.subject_id = Some(value);
                data.subject_type = SubjectType::Persistent;
            }
            constants::NAMEID_EMAIL => {
                let mail = data.attr_first("mail").ok_or_else(|| {
                    Error::Authn(format!(
                        "nameid {}: no mail to use as emailAddress NameID",
                        self.name
                    ))
                })?;
                data.subject_id = Some(mail.to_string());
                data.subject_type = SubjectType::Persistent;
            }
            _ => {}
        }
        Ok(data)
    }
}

#[cfg(test)]
mod tests {
    use super::super::testutil::{bx, ctx, response_from};
    use super::*;

    fn ctx_with_format(format: &str) -> Context {
        let mut c = ctx();
        c.state.set_str(STATE_KEY_BASE, KEY_NAME_ID_FORMAT, format);
        c
    }

    fn build() -> Box<dyn MicroService> {
        NameId::build(&bx("nameid", serde_json::json!({}))).unwrap()
    }

    #[tokio::test]
    async fn persistent_uses_pairwise_hash_part() {
        let mut data = response_from("https://sp.example");
        data.set_attr("pairwise-id", "deadbeef@example.org");
        let data = build()
            .process_response(&mut ctx_with_format(constants::NAMEID_PERSISTENT), data)
            .await
            .unwrap();
        assert_eq!(data.subject_id.as_deref(), Some("deadbeef"));
        assert_eq!(data.subject_type, SubjectType::Persistent);
    }

    #[tokio::test]
    async fn email_uses_mail_attribute() {
        let mut data = response_from("https://sp.example");
        data.set_attr("mail", "anna@example.org");
        let data = build()
            .process_response(&mut ctx_with_format(constants::NAMEID_EMAIL), data)
            .await
            .unwrap();
        assert_eq!(data.subject_id.as_deref(), Some("anna@example.org"));
    }

    #[tokio::test]
    async fn transient_marks_subject_type_only() {
        let mut data = response_from("https://sp.example");
        data.subject_id = Some("stable".into());
        let data = build()
            .process_response(&mut ctx_with_format(constants::NAMEID_TRANSIENT), data)
            .await
            .unwrap();
        assert_eq!(data.subject_type, SubjectType::Transient);
        // The frontend mints the opaque value; we don't overwrite subject_id here.
        assert_eq!(data.subject_id.as_deref(), Some("stable"));
    }

    #[tokio::test]
    async fn persistent_without_pairwise_is_authn_error() {
        let data = response_from("https://sp.example");
        assert!(build()
            .process_response(&mut ctx_with_format(constants::NAMEID_PERSISTENT), data)
            .await
            .is_err());
    }

    #[tokio::test]
    async fn no_format_passes_through() {
        let mut data = response_from("https://sp.example");
        data.set_attr("mail", "a@x");
        let data = build().process_response(&mut ctx(), data).await.unwrap();
        assert_eq!(data.attr_first("mail"), Some("a@x"));
    }
}
