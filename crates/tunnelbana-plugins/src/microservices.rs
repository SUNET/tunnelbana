//! Built-in micro-services.
//!
//! - `static_attributes` — inject fixed attributes on the response path.
//! - `filter_attributes` — keep only allow-listed attributes on the response path.
//! - `custom_routing` — pick the backend by requester on the request path.
//! - `attribute_processor` — per-attribute value transforms on the response
//!   path (SATOSA: `AttributeProcessor` + `processors/*`).
//! - `attribute_authorization` — regex-based allow/deny authorization on
//!   response attributes (SATOSA: `AttributeAuthorization`).

use std::collections::BTreeMap;

use async_trait::async_trait;
use regex::Regex;
use serde::Deserialize;
use tunnelbana_core::context::Context;
use tunnelbana_core::error::{Error, Result};
use tunnelbana_core::internal::InternalData;
use tunnelbana_core::plugin::{BuildContext, MicroService};

// ── static_attributes ───────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct StaticAttributesConfig {
    #[serde(default)]
    attributes: BTreeMap<String, Vec<String>>,
}

/// Adds fixed attributes to every authentication response.
pub struct StaticAttributes {
    name: String,
    attributes: BTreeMap<String, Vec<String>>,
}

impl StaticAttributes {
    pub fn build(bx: &BuildContext) -> Result<Box<dyn MicroService>> {
        let cfg: StaticAttributesConfig = bx.parse_config()?;
        Ok(Box::new(StaticAttributes {
            name: bx.name.clone(),
            attributes: cfg.attributes,
        }))
    }
}

#[async_trait]
impl MicroService for StaticAttributes {
    fn name(&self) -> &str {
        &self.name
    }

    async fn process_response(
        &self,
        _ctx: &mut Context,
        mut data: InternalData,
    ) -> Result<InternalData> {
        for (k, v) in &self.attributes {
            data.attributes
                .entry(k.clone())
                .or_insert_with(|| v.clone());
        }
        Ok(data)
    }
}

// ── filter_attributes ───────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct FilterAttributesConfig {
    /// Internal attribute names to keep; everything else is dropped.
    #[serde(default)]
    allowed: Vec<String>,
}

/// Keeps only allow-listed internal attributes on the response path.
pub struct FilterAttributes {
    name: String,
    allowed: Vec<String>,
}

impl FilterAttributes {
    pub fn build(bx: &BuildContext) -> Result<Box<dyn MicroService>> {
        let cfg: FilterAttributesConfig = bx.parse_config()?;
        Ok(Box::new(FilterAttributes {
            name: bx.name.clone(),
            allowed: cfg.allowed,
        }))
    }
}

#[async_trait]
impl MicroService for FilterAttributes {
    fn name(&self) -> &str {
        &self.name
    }

    async fn process_response(
        &self,
        _ctx: &mut Context,
        mut data: InternalData,
    ) -> Result<InternalData> {
        data.attributes.retain(|k, _| self.allowed.contains(k));
        Ok(data)
    }
}

// ── custom_routing ──────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct RoutingRule {
    requester: String,
    backend: String,
}

#[derive(Debug, Deserialize)]
struct CustomRoutingConfig {
    #[serde(default)]
    rule: Vec<RoutingRule>,
    #[serde(default)]
    default_backend: Option<String>,
}

/// Selects the backend on the request path based on the requester (SP/RP id).
pub struct CustomRouting {
    name: String,
    rules: BTreeMap<String, String>,
    default_backend: Option<String>,
}

impl CustomRouting {
    pub fn build(bx: &BuildContext) -> Result<Box<dyn MicroService>> {
        let cfg: CustomRoutingConfig = bx.parse_config()?;
        let rules = cfg
            .rule
            .into_iter()
            .map(|r| (r.requester, r.backend))
            .collect();
        Ok(Box::new(CustomRouting {
            name: bx.name.clone(),
            rules,
            default_backend: cfg.default_backend,
        }))
    }
}

#[async_trait]
impl MicroService for CustomRouting {
    fn name(&self) -> &str {
        &self.name
    }

    async fn process_request(&self, ctx: &mut Context, data: InternalData) -> Result<InternalData> {
        if let Some(requester) = &data.requester {
            if let Some(backend) = self.rules.get(requester) {
                ctx.target_backend = Some(backend.clone());
            } else if let Some(default) = &self.default_backend {
                ctx.target_backend = Some(default.clone());
            }
        }
        Ok(data)
    }
}

// ── attribute_processor ─────────────────────────────────────────────────────

/// One `[[microservice.config.process.processors]]` entry.
#[derive(Debug, Deserialize)]
struct ProcessorSpec {
    /// Processor kind; currently only `"regex_sub"` (SATOSA:
    /// `RegexSubProcessor`).
    name: String,
    /// Regex applied to each value (SATOSA: `regex_sub_match_pattern`).
    #[serde(default)]
    match_pattern: Option<String>,
    /// Replacement for every match (SATOSA: `regex_sub_replace_pattern`).
    /// Group references use `$1`/`${1}`; Python-style `\1` is accepted and
    /// converted for SATOSA config portability.
    #[serde(default)]
    replace_pattern: Option<String>,
}

/// One `[[microservice.config.process]]` entry.
#[derive(Debug, Deserialize)]
struct ProcessRule {
    /// Internal attribute name whose values are transformed.
    attribute: String,
    processors: Vec<ProcessorSpec>,
}

#[derive(Debug, Deserialize)]
struct AttributeProcessorConfig {
    #[serde(default)]
    process: Vec<ProcessRule>,
}

enum Processor {
    RegexSub { regex: Regex, replace: String },
}

impl Processor {
    fn apply(&self, value: &str) -> String {
        match self {
            Processor::RegexSub { regex, replace } => {
                regex.replace_all(value, replace.as_str()).into_owned()
            }
        }
    }
}

struct CompiledRule {
    attribute: String,
    processors: Vec<Processor>,
}

/// Transforms attribute values on the response path; each configured
/// attribute's values run through its processor chain in order.
pub struct AttributeProcessor {
    name: String,
    rules: Vec<CompiledRule>,
}

/// Convert Python-style `\1` backreferences (as used in SATOSA configs) to the
/// regex crate's `${1}` form, leaving `$`-style references untouched.
fn convert_backrefs(replace: &str) -> String {
    let mut out = String::with_capacity(replace.len());
    let mut chars = replace.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\\' && chars.peek().is_some_and(|n| n.is_ascii_digit()) {
            let mut num = String::new();
            while let Some(d) = chars.peek().filter(|d| d.is_ascii_digit()) {
                num.push(*d);
                chars.next();
            }
            out.push_str(&format!("${{{num}}}"));
        } else {
            out.push(c);
        }
    }
    out
}

fn required_regex_sub_field<'a>(
    field: Option<&'a str>,
    plugin_name: &str,
    field_name: &str,
) -> Result<&'a str> {
    field.filter(|value| !value.is_empty()).ok_or_else(|| {
        Error::Config(format!(
            "attribute_processor {plugin_name}: regex_sub needs {field_name}"
        ))
    })
}

impl AttributeProcessor {
    pub fn build(bx: &BuildContext) -> Result<Box<dyn MicroService>> {
        let cfg: AttributeProcessorConfig = bx.parse_config()?;
        let mut rules = Vec::new();
        for rule in cfg.process {
            let mut processors = Vec::new();
            for spec in rule.processors {
                match spec.name.as_str() {
                    "regex_sub" => {
                        let pattern = required_regex_sub_field(
                            spec.match_pattern.as_deref(),
                            &bx.name,
                            "match_pattern",
                        )?;
                        let regex = Regex::new(pattern).map_err(|e| {
                            Error::Config(format!(
                                "attribute_processor {}: bad match_pattern: {e}",
                                bx.name
                            ))
                        })?;
                        let replace = convert_backrefs(required_regex_sub_field(
                            spec.replace_pattern.as_deref(),
                            &bx.name,
                            "replace_pattern",
                        )?);
                        processors.push(Processor::RegexSub { regex, replace });
                    }
                    other => {
                        return Err(Error::Config(format!(
                            "attribute_processor {}: unknown processor: {other}",
                            bx.name
                        )));
                    }
                }
            }
            rules.push(CompiledRule {
                attribute: rule.attribute,
                processors,
            });
        }
        Ok(Box::new(AttributeProcessor {
            name: bx.name.clone(),
            rules,
        }))
    }
}

#[async_trait]
impl MicroService for AttributeProcessor {
    fn name(&self) -> &str {
        &self.name
    }

    async fn process_response(
        &self,
        _ctx: &mut Context,
        mut data: InternalData,
    ) -> Result<InternalData> {
        for rule in &self.rules {
            if let Some(values) = data.attributes.get_mut(&rule.attribute) {
                for value in values.iter_mut() {
                    for processor in &rule.processors {
                        *value = processor.apply(value);
                    }
                }
            }
        }
        Ok(data)
    }
}

// ── attribute_authorization ─────────────────────────────────────────────────

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

/// SATOSA's `get_dict_defaults`: exact key, else `""`, else `"default"`.
fn level<'a, T>(map: &'a BTreeMap<String, T>, key: &str) -> Option<&'a T> {
    map.get(key)
        .or_else(|| map.get(""))
        .or_else(|| map.get("default"))
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
    use super::*;
    use std::sync::Arc;
    use tunnelbana_core::attributes::AttributeMapper;
    use tunnelbana_core::http::HttpRequestData;
    use tunnelbana_core::plugin::NullHttpClient;
    use tunnelbana_core::state::State;

    fn bx(name: &str, config: serde_json::Value) -> BuildContext {
        BuildContext {
            name: name.to_string(),
            base_url: "https://x".into(),
            config,
            attribute_mapper: Arc::new(AttributeMapper::default()),
            http_client: Arc::new(NullHttpClient),
            secret: "s".into(),
            previous_secrets: Vec::new(),
        }
    }

    fn ctx() -> Context {
        Context::new(HttpRequestData::default(), State::new())
    }

    #[tokio::test]
    async fn static_and_filter() {
        let mut data = InternalData::default();
        data.set_attr("mail", "a@x");

        let stat = StaticAttributes::build(&bx(
            "static",
            serde_json::json!({ "attributes": { "affiliation": ["member"] } }),
        ))
        .unwrap();
        let data = stat.process_response(&mut ctx(), data).await.unwrap();
        assert_eq!(data.attr_first("affiliation"), Some("member"));

        let filter =
            FilterAttributes::build(&bx("filter", serde_json::json!({ "allowed": ["mail"] })))
                .unwrap();
        let data = filter.process_response(&mut ctx(), data).await.unwrap();
        assert_eq!(data.attr_first("mail"), Some("a@x"));
        assert!(!data.attributes.contains_key("affiliation"));
    }

    #[tokio::test]
    async fn attribute_processor_regex_sub_satosa_subject_id() {
        // The production SATOSA config: subject-id "user@scope.tld" -> "user_scope".
        let proc = AttributeProcessor::build(&bx(
            "proc",
            serde_json::json!({
                "process": [{
                    "attribute": "subjectid",
                    "processors": [{
                        "name": "regex_sub",
                        "match_pattern": "@([^.]+)\\.(.+)",
                        "replace_pattern": "_\\1"
                    }]
                }]
            }),
        ))
        .unwrap();

        let mut data = InternalData::default();
        data.set_attr("subjectid", "kushal@sunet.se");
        data.set_attr("mail", "kushal@sunet.se");
        let data = proc.process_response(&mut ctx(), data).await.unwrap();
        assert_eq!(data.attr_first("subjectid"), Some("kushal_sunet"));
        // Untargeted attributes are untouched.
        assert_eq!(data.attr_first("mail"), Some("kushal@sunet.se"));
    }

    #[tokio::test]
    async fn attribute_processor_dollar_backrefs_and_chaining() {
        let proc = AttributeProcessor::build(&bx(
            "proc",
            serde_json::json!({
                "process": [{
                    "attribute": "affiliation",
                    "processors": [
                        { "name": "regex_sub", "match_pattern": "staff", "replace_pattern": "employee" },
                        { "name": "regex_sub", "match_pattern": "^(\\w+)$", "replace_pattern": "$1@example.org" }
                    ]
                }]
            }),
        ))
        .unwrap();

        let mut data = InternalData::default();
        data.set_attr("affiliation", "staff");
        let data = proc.process_response(&mut ctx(), data).await.unwrap();
        assert_eq!(
            data.attr_first("affiliation"),
            Some("employee@example.org")
        );
    }

    #[test]
    fn attribute_processor_rejects_unknown_processor_and_bad_regex() {
        assert!(AttributeProcessor::build(&bx(
            "proc",
            serde_json::json!({
                "process": [{ "attribute": "a", "processors": [{ "name": "hash" }] }]
            }),
        ))
        .is_err());
        assert!(AttributeProcessor::build(&bx(
            "proc",
            serde_json::json!({
                "process": [{ "attribute": "a", "processors": [{ "name": "regex_sub", "match_pattern": "(" }] }]
            }),
        ))
        .is_err());
    }

    #[test]
    fn attribute_processor_requires_non_empty_regex_sub_patterns() {
        assert!(AttributeProcessor::build(&bx(
            "proc",
            serde_json::json!({
                "process": [{
                    "attribute": "a",
                    "processors": [{ "name": "regex_sub", "replace_pattern": "x" }]
                }]
            }),
        ))
        .is_err());
        assert!(AttributeProcessor::build(&bx(
            "proc",
            serde_json::json!({
                "process": [{
                    "attribute": "a",
                    "processors": [{
                        "name": "regex_sub",
                        "match_pattern": "",
                        "replace_pattern": "x"
                    }]
                }]
            }),
        ))
        .is_err());
        assert!(AttributeProcessor::build(&bx(
            "proc",
            serde_json::json!({
                "process": [{
                    "attribute": "a",
                    "processors": [{ "name": "regex_sub", "match_pattern": "a" }]
                }]
            }),
        ))
        .is_err());
        assert!(AttributeProcessor::build(&bx(
            "proc",
            serde_json::json!({
                "process": [{
                    "attribute": "a",
                    "processors": [{
                        "name": "regex_sub",
                        "match_pattern": "a",
                        "replace_pattern": ""
                    }]
                }]
            }),
        ))
        .is_err());
    }

    #[test]
    fn convert_backrefs_forms() {
        assert_eq!(convert_backrefs("_\\1"), "_${1}");
        assert_eq!(convert_backrefs("\\10x"), "${10}x");
        assert_eq!(convert_backrefs("$1 stays"), "$1 stays");
        assert_eq!(convert_backrefs("no refs"), "no refs");
    }

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

    fn response_from(requester: &str) -> InternalData {
        InternalData {
            requester: Some(requester.into()),
            ..InternalData::default()
        }
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

    #[tokio::test]
    async fn routing_by_requester() {
        let routing = CustomRouting::build(&bx(
            "route",
            serde_json::json!({
                "rule": [{ "requester": "sp-a", "backend": "Saml2" }],
                "default_backend": "Oidc"
            }),
        ))
        .unwrap();

        let mut c = ctx();
        let _ = routing
            .process_request(&mut c, InternalData::request("sp-a"))
            .await
            .unwrap();
        assert_eq!(c.target_backend.as_deref(), Some("Saml2"));

        let mut c = ctx();
        let _ = routing
            .process_request(&mut c, InternalData::request("unknown"))
            .await
            .unwrap();
        assert_eq!(c.target_backend.as_deref(), Some("Oidc"));
    }
}
