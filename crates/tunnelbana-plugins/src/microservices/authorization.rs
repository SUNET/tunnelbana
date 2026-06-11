//! `attribute_authorization` — regex-based allow/deny on response attributes.

use std::collections::BTreeMap;

use async_trait::async_trait;
use regex::Regex;
use serde::Deserialize;
use tunnelbana_core::context::Context;
use tunnelbana_core::error::{Error, Result};
use tunnelbana_core::internal::InternalData;
use tunnelbana_core::plugin::{BuildContext, MicroService};

use super::level;

/// `requester -> provider (issuer) -> attribute -> regex list`, with `""` and
/// `"default"` as synonymous wildcards at the requester and provider levels
/// (SATOSA: `attribute_allow` / `attribute_deny`).
type RawAuthzRules = BTreeMap<String, BTreeMap<String, BTreeMap<String, Vec<String>>>>;
type AuthzRules = BTreeMap<String, BTreeMap<String, BTreeMap<String, Vec<Regex>>>>;

#[derive(Debug, Deserialize)]
struct AttributeAuthorizationConfig {
    #[serde(default)]
    attribute_allow: RawAuthzRules,
    #[serde(default)]
    attribute_deny: RawAuthzRules,
    /// Reject when an attribute named in a matching allow rule is absent.
    #[serde(default)]
    force_attributes_presence_on_allow: bool,
    /// Reject when an attribute named in a matching deny rule is absent.
    #[serde(default)]
    force_attributes_presence_on_deny: bool,
}

/// Regex-based authorization on response attributes. Allow rules pass when
/// any value of the attribute matches any regex (unanchored search); deny
/// rules reject when any value matches. Rules are selected per requester then
/// per provider; rule sets are not merged or inherited.
pub struct AttributeAuthorization {
    name: String,
    attribute_allow: AuthzRules,
    attribute_deny: AuthzRules,
    force_attributes_presence_on_allow: bool,
    force_attributes_presence_on_deny: bool,
}

fn compile_authz(raw: RawAuthzRules, name: &str) -> Result<AuthzRules> {
    let mut compiled = AuthzRules::new();
    for (requester, providers) in raw {
        let mut by_provider = BTreeMap::new();
        for (provider, attrs) in providers {
            let mut by_attr = BTreeMap::new();
            for (attr, patterns) in attrs {
                let regexes = patterns
                    .iter()
                    .map(|p| {
                        Regex::new(p).map_err(|e| {
                            Error::Config(format!(
                                "attribute_authorization {name}: bad pattern {p:?}: {e}"
                            ))
                        })
                    })
                    .collect::<Result<Vec<_>>>()?;
                by_attr.insert(attr, regexes);
            }
            by_provider.insert(provider, by_attr);
        }
        compiled.insert(requester, by_provider);
    }
    Ok(compiled)
}

impl AttributeAuthorization {
    pub fn build(bx: &BuildContext) -> Result<Box<dyn MicroService>> {
        let cfg: AttributeAuthorizationConfig = bx.parse_config()?;
        Ok(Box::new(AttributeAuthorization {
            name: bx.name.clone(),
            attribute_allow: compile_authz(cfg.attribute_allow, &bx.name)?,
            attribute_deny: compile_authz(cfg.attribute_deny, &bx.name)?,
            force_attributes_presence_on_allow: cfg.force_attributes_presence_on_allow,
            force_attributes_presence_on_deny: cfg.force_attributes_presence_on_deny,
        }))
    }

    fn rules<'a>(
        rules: &'a AuthzRules,
        requester: &str,
        provider: &str,
    ) -> Option<&'a BTreeMap<String, Vec<Regex>>> {
        level(rules, requester).and_then(|by_provider| level(by_provider, provider))
    }
}

#[async_trait]
impl MicroService for AttributeAuthorization {
    fn name(&self) -> &str {
        &self.name
    }

    async fn process_response(
        &self,
        _ctx: &mut Context,
        data: InternalData,
    ) -> Result<InternalData> {
        let requester = data.requester.as_deref().unwrap_or("");
        let provider = data.auth_info.issuer.as_deref().unwrap_or("");
        let denied = || {
            Error::Authn(format!(
                "attribute_authorization {}: permission denied",
                self.name
            ))
        };

        if let Some(allow) = Self::rules(&self.attribute_allow, requester, provider) {
            for (attr, regexes) in allow {
                match data.attributes.get(attr) {
                    Some(values) => {
                        if !values
                            .iter()
                            .any(|v| regexes.iter().any(|r| r.is_match(v)))
                        {
                            return Err(denied());
                        }
                    }
                    None if self.force_attributes_presence_on_allow => return Err(denied()),
                    None => {}
                }
            }
        }
        if let Some(deny) = Self::rules(&self.attribute_deny, requester, provider) {
            for (attr, regexes) in deny {
                match data.attributes.get(attr) {
                    Some(values) => {
                        if values
                            .iter()
                            .any(|v| regexes.iter().any(|r| r.is_match(v)))
                        {
                            return Err(denied());
                        }
                    }
                    None if self.force_attributes_presence_on_deny => return Err(denied()),
                    None => {}
                }
            }
        }
        Ok(data)
    }
}

#[cfg(test)]
mod tests {
    use super::super::testutil::{bx, ctx, response_from};
    use super::*;

    /// The production SWAMID config: any requester, any provider — subject-id
    /// must be present (force) and non-empty (regex ".").
    fn production_authz() -> Box<dyn MicroService> {
        AttributeAuthorization::build(&bx(
            "authz",
            serde_json::json!({
                "force_attributes_presence_on_allow": true,
                "attribute_allow": {
                    "default": {
                        "platform": { "subjectid": ["."] },
                        "default":  { "subjectid": ["."] }
                    }
                }
            }),
        ))
        .unwrap()
    }

    #[tokio::test]
    async fn attribute_authorization_allows_when_present_denies_when_absent() {
        let authz = production_authz();

        let mut data = response_from("https://sp.example.org");
        data.set_attr("subjectid", "kushal_sunet");
        assert!(authz
            .process_response(&mut ctx(), data)
            .await
            .is_ok());

        // force_attributes_presence_on_allow: missing subjectid -> denied.
        let mut data = response_from("https://sp.example.org");
        data.set_attr("mail", "a@x");
        let err = authz.process_response(&mut ctx(), data).await.unwrap_err();
        assert!(matches!(err, Error::Authn(_)));
    }

    #[tokio::test]
    async fn attribute_authorization_requester_specific_overrides_default() {
        let authz = AttributeAuthorization::build(&bx(
            "authz",
            serde_json::json!({
                "attribute_allow": {
                    "https://locked.example": { "default": { "affiliation": ["^staff$"] } },
                    "default": { "default": {} }
                }
            }),
        ))
        .unwrap();

        // The specific requester needs affiliation=staff…
        let mut data = response_from("https://locked.example");
        data.set_attr("affiliation", "student");
        assert!(authz.process_response(&mut ctx(), data).await.is_err());

        // …while everyone else has no allow constraints.
        let mut data = response_from("https://open.example");
        data.set_attr("affiliation", "student");
        assert!(authz.process_response(&mut ctx(), data).await.is_ok());
    }

    #[tokio::test]
    async fn attribute_authorization_deny_rule() {
        let authz = AttributeAuthorization::build(&bx(
            "authz",
            serde_json::json!({
                // SATOSA doc example: deny eppn values without an '@'.
                "attribute_deny": {
                    "default": { "default": { "edupersonprincipalname": ["^[^@]+$"] } }
                }
            }),
        ))
        .unwrap();

        let mut data = InternalData::default();
        data.set_attr("edupersonprincipalname", "unscoped-value");
        assert!(authz.process_response(&mut ctx(), data).await.is_err());

        let mut data = InternalData::default();
        data.set_attr("edupersonprincipalname", "anna@example.org");
        assert!(authz.process_response(&mut ctx(), data).await.is_ok());
    }

    #[test]
    fn attribute_authorization_rejects_bad_regex() {
        assert!(AttributeAuthorization::build(&bx(
            "authz",
            serde_json::json!({
                "attribute_allow": { "default": { "default": { "a": ["("] } } }
            }),
        ))
        .is_err());
    }
}
