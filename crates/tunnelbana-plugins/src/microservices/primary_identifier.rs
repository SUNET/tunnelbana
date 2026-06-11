//! `primary_identifier` — construct a primary identifier from an ordered
//! candidate list (SATOSA: `PrimaryIdentifier`).

use std::collections::BTreeMap;

use async_trait::async_trait;
use serde::Deserialize;
use tunnelbana_core::context::{Context, KEY_ERROR_REDIRECT};
use tunnelbana_core::error::{Error, Result};
use tunnelbana_core::internal::{InternalData, SubjectType};
use tunnelbana_core::plugin::{BuildContext, MicroService};

#[derive(Debug, Clone, Deserialize)]
struct Candidate {
    /// Attribute names whose first values are concatenated; the special name
    /// `name_id` pulls in the subject id when `name_id_format` matches the
    /// response's subject type.
    attribute_names: Vec<String>,
    /// Required subject NameID format for the `name_id` pseudo-attribute;
    /// either a SAML format URN or a short name (`persistent`, `transient`,
    /// `public`, `pairwise`).
    #[serde(default)]
    name_id_format: Option<String>,
    /// Extra component appended last: the literal value, or
    /// `issuer_entityid` for the asserting IdP's entity id.
    #[serde(default)]
    add_scope: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
struct Overrides {
    #[serde(default)]
    ordered_identifier_candidates: Option<Vec<Candidate>>,
    #[serde(default)]
    primary_identifier: Option<String>,
    #[serde(default)]
    clear_input_attributes: Option<bool>,
    #[serde(default)]
    replace_subject_id: Option<bool>,
    #[serde(default)]
    on_error: Option<String>,
    /// Skip this micro-service entirely for the matching entity.
    #[serde(default)]
    ignore: bool,
}

#[derive(Debug, Deserialize)]
struct PrimaryIdentifierConfig {
    ordered_identifier_candidates: Vec<Candidate>,
    /// Attribute receiving the constructed identifier (default `uid`).
    #[serde(default)]
    primary_identifier: Option<String>,
    #[serde(default)]
    clear_input_attributes: bool,
    #[serde(default)]
    replace_subject_id: bool,
    /// Redirect target when no identifier can be constructed; called with
    /// `?sp=…&idp=…` appended. Without it the response passes through
    /// unchanged.
    #[serde(default)]
    on_error: Option<String>,
    /// Per-entity overrides keyed by SP (requester) or IdP (issuer) entity
    /// id; an SP override wins over an IdP override.
    #[serde(default, rename = "override")]
    overrides: BTreeMap<String, Overrides>,
}

/// Constructs a primary identifier from the first candidate whose attributes
/// are all present, concatenating their first values (plus the subject id for
/// `name_id`, plus an optional scope).
pub struct PrimaryIdentifier {
    name: String,
    config: PrimaryIdentifierConfig,
}

/// Effective settings after applying IdP- then SP-level overrides.
struct Effective<'a> {
    candidates: &'a [Candidate],
    primary_identifier: &'a str,
    clear_input_attributes: bool,
    replace_subject_id: bool,
    on_error: Option<&'a str>,
    ignore: bool,
}

fn subject_type_matches(format: &str, subject_type: SubjectType) -> bool {
    let short = match subject_type {
        SubjectType::Persistent => "persistent",
        SubjectType::Transient => "transient",
        SubjectType::Public => "public",
        SubjectType::Pairwise => "pairwise",
    };
    format == short
        || format
            .rsplit(':')
            .next()
            .is_some_and(|suffix| suffix == short)
}

impl PrimaryIdentifier {
    pub fn build(bx: &BuildContext) -> Result<Box<dyn MicroService>> {
        let config: PrimaryIdentifierConfig = bx.parse_config()?;
        if config.ordered_identifier_candidates.is_empty() {
            return Err(Error::Config(format!(
                "primary_identifier {}: ordered_identifier_candidates must not be empty",
                bx.name
            )));
        }
        Ok(Box::new(PrimaryIdentifier {
            name: bx.name.clone(),
            config,
        }))
    }

    fn effective(&self, requester: &str, issuer: &str) -> Effective<'_> {
        let cfg = &self.config;
        let mut eff = Effective {
            candidates: &cfg.ordered_identifier_candidates,
            primary_identifier: cfg.primary_identifier.as_deref().unwrap_or("uid"),
            clear_input_attributes: cfg.clear_input_attributes,
            replace_subject_id: cfg.replace_subject_id,
            on_error: cfg.on_error.as_deref(),
            ignore: false,
        };
        // IdP override first, SP override wins on conflict.
        for key in [issuer, requester] {
            if key.is_empty() {
                continue;
            }
            if let Some(o) = cfg.overrides.get(key) {
                if let Some(c) = &o.ordered_identifier_candidates {
                    eff.candidates = c;
                }
                if let Some(p) = &o.primary_identifier {
                    eff.primary_identifier = p;
                }
                if let Some(v) = o.clear_input_attributes {
                    eff.clear_input_attributes = v;
                }
                if let Some(v) = o.replace_subject_id {
                    eff.replace_subject_id = v;
                }
                if let Some(u) = &o.on_error {
                    eff.on_error = Some(u);
                }
                eff.ignore = eff.ignore || o.ignore;
            }
        }
        eff
    }

    fn construct(candidates: &[Candidate], data: &InternalData) -> Option<String> {
        'candidates: for candidate in candidates {
            let mut values: Vec<String> = Vec::new();
            for name in &candidate.attribute_names {
                if name == "name_id" {
                    let format_matches = candidate
                        .name_id_format
                        .as_deref()
                        .is_some_and(|f| subject_type_matches(f, data.subject_type));
                    match (&data.subject_id, format_matches) {
                        (Some(subject), true) => {
                            // Skip the NameID when an attribute already
                            // asserted the same value (SATOSA: known
                            // non-compliant IdPs duplicate eppn there).
                            if !values.iter().any(|v| v == subject) {
                                values.push(subject.clone());
                            }
                        }
                        _ => continue 'candidates,
                    }
                } else {
                    match data.attr_first(name) {
                        Some(v) => values.push(v.to_string()),
                        None => continue 'candidates,
                    }
                }
            }
            if let Some(scope) = &candidate.add_scope {
                if scope == "issuer_entityid" {
                    match &data.auth_info.issuer {
                        Some(issuer) => values.push(issuer.clone()),
                        None => continue 'candidates,
                    }
                } else {
                    values.push(scope.clone());
                }
            }
            if !values.is_empty() {
                return Some(values.concat());
            }
        }
        None
    }
}

#[async_trait]
impl MicroService for PrimaryIdentifier {
    fn name(&self) -> &str {
        &self.name
    }

    async fn process_response(
        &self,
        ctx: &mut Context,
        mut data: InternalData,
    ) -> Result<InternalData> {
        let requester = data.requester.clone().unwrap_or_default();
        let issuer = data.auth_info.issuer.clone().unwrap_or_default();
        let eff = self.effective(&requester, &issuer);
        if eff.ignore {
            return Ok(data);
        }

        let Some(identifier) = Self::construct(eff.candidates, &data) else {
            if let Some(on_error) = eff.on_error {
                let qs = url::form_urlencoded::Serializer::new(String::new())
                    .append_pair("sp", &requester)
                    .append_pair("idp", &issuer)
                    .finish();
                ctx.decorate(
                    KEY_ERROR_REDIRECT,
                    serde_json::Value::String(format!("{on_error}?{qs}")),
                );
                return Err(Error::Authn(format!(
                    "primary_identifier {}: no identifier could be constructed",
                    self.name
                )));
            }
            tracing::warn!(
                microservice = %self.name,
                requester = %requester,
                "no primary identifier found; passing response through"
            );
            return Ok(data);
        };

        if eff.clear_input_attributes {
            data.attributes.clear();
        }
        data.attributes
            .insert(eff.primary_identifier.to_string(), vec![identifier.clone()]);
        if eff.replace_subject_id {
            data.subject_id = Some(identifier);
        }
        Ok(data)
    }
}

#[cfg(test)]
mod tests {
    use super::super::testutil::{bx, ctx, response_from};
    use super::*;

    fn build(config: serde_json::Value) -> Box<dyn MicroService> {
        PrimaryIdentifier::build(&bx("pid", config)).unwrap()
    }

    #[tokio::test]
    async fn falls_through_candidates_in_order() {
        let pid = build(serde_json::json!({
            "ordered_identifier_candidates": [
                { "attribute_names": ["edupersonuniqueid"] },
                { "attribute_names": ["edupersonprincipalname"] },
                { "attribute_names": ["givenname", "sn"], "add_scope": "issuer_entityid" }
            ],
            "primary_identifier": "uid",
            "replace_subject_id": true
        }));

        // First candidate missing, second present.
        let mut data = response_from("https://sp.example");
        data.set_attr("edupersonprincipalname", "anna@example.org");
        let data = pid.process_response(&mut ctx(), data).await.unwrap();
        assert_eq!(data.attr_first("uid"), Some("anna@example.org"));
        assert_eq!(data.subject_id.as_deref(), Some("anna@example.org"));

        // Only the composite candidate is satisfiable; the issuer scope lands last.
        let mut data = response_from("https://sp.example");
        data.auth_info.issuer = Some("https://idp.example".into());
        data.set_attr("givenname", "Anna");
        data.set_attr("sn", "Andersson");
        let data = pid.process_response(&mut ctx(), data).await.unwrap();
        assert_eq!(
            data.attr_first("uid"),
            Some("AnnaAnderssonhttps://idp.example")
        );
    }

    #[tokio::test]
    async fn name_id_candidate_requires_matching_subject_type() {
        let pid = build(serde_json::json!({
            "ordered_identifier_candidates": [
                {
                    "attribute_names": ["name_id"],
                    "name_id_format": "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"
                }
            ]
        }));

        let mut data = response_from("https://sp.example");
        data.subject_id = Some("stable-id".into());
        data.subject_type = SubjectType::Persistent;
        let out = pid
            .process_response(&mut ctx(), data.clone())
            .await
            .unwrap();
        assert_eq!(out.attr_first("uid"), Some("stable-id"));

        // A transient subject doesn't satisfy a persistent candidate; with no
        // on_error the data passes through unchanged.
        data.subject_type = SubjectType::Transient;
        let out = pid.process_response(&mut ctx(), data).await.unwrap();
        assert!(!out.attributes.contains_key("uid"));
    }

    #[tokio::test]
    async fn on_error_sets_redirect_decoration_and_fails() {
        let pid = build(serde_json::json!({
            "ordered_identifier_candidates": [
                { "attribute_names": ["edupersonprincipalname"] }
            ],
            "on_error": "https://errors.example/no-id"
        }));

        let mut data = response_from("https://sp.example");
        data.auth_info.issuer = Some("https://idp.example".into());
        let mut c = ctx();
        let err = pid.process_response(&mut c, data).await.unwrap_err();
        assert!(matches!(err, Error::Authn(_)));
        assert_eq!(
            c.decoration(KEY_ERROR_REDIRECT).and_then(|v| v.as_str()),
            Some(
                "https://errors.example/no-id?sp=https%3A%2F%2Fsp.example&idp=https%3A%2F%2Fidp.example"
            )
        );
    }

    #[tokio::test]
    async fn per_entity_overrides_and_ignore() {
        let pid = build(serde_json::json!({
            "ordered_identifier_candidates": [
                { "attribute_names": ["edupersonprincipalname"] }
            ],
            "clear_input_attributes": true,
            "override": {
                "https://special.example": { "primary_identifier": "employeeid" },
                "https://skipped.example": { "ignore": true }
            }
        }));

        let mut data = response_from("https://special.example");
        data.set_attr("edupersonprincipalname", "anna@example.org");
        data.set_attr("mail", "anna@example.org");
        let data = pid.process_response(&mut ctx(), data).await.unwrap();
        assert_eq!(data.attr_first("employeeid"), Some("anna@example.org"));
        // clear_input_attributes from the defaults still applies.
        assert!(!data.attributes.contains_key("mail"));

        let mut data = response_from("https://skipped.example");
        data.set_attr("mail", "anna@example.org");
        let data = pid.process_response(&mut ctx(), data).await.unwrap();
        assert!(data.attributes.contains_key("mail"));
        assert!(!data.attributes.contains_key("uid"));
    }

    #[test]
    fn requires_candidates() {
        assert!(PrimaryIdentifier::build(&bx(
            "pid",
            serde_json::json!({ "ordered_identifier_candidates": [] })
        ))
        .is_err());
    }
}
