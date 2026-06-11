//! `attribute_processor` — per-attribute value transform chains.

use std::collections::BTreeMap;

use async_trait::async_trait;
use regex::Regex;
use serde::Deserialize;
use sha2::{Digest, Sha256, Sha512};
use tunnelbana_core::context::Context;
use tunnelbana_core::error::{Error, Result};
use tunnelbana_core::internal::InternalData;
use tunnelbana_core::plugin::{BuildContext, MicroService};

/// One `[[microservice.config.process.processors]]` entry.
#[derive(Debug, Deserialize)]
struct ProcessorSpec {
    /// Processor kind: `regex_sub`, `hash`, `scope`, `scope_extractor`,
    /// `scope_remover` or `gender` (SATOSA: `processors/*`).
    name: String,
    /// Regex applied to each value (SATOSA: `regex_sub_match_pattern`).
    #[serde(default)]
    match_pattern: Option<String>,
    /// Replacement for every match (SATOSA: `regex_sub_replace_pattern`).
    /// Group references use `$1`/`${1}`; Python-style `\1` is accepted and
    /// converted for SATOSA config portability.
    #[serde(default)]
    replace_pattern: Option<String>,
    /// `hash`: digest algorithm, `sha256` (default) or `sha512`.
    #[serde(default)]
    hash_algo: Option<String>,
    /// `hash`: salt appended to the value before hashing.
    #[serde(default)]
    salt: Option<String>,
    /// `scope`: the scope appended as `@scope` to each value.
    #[serde(default)]
    scope: Option<String>,
    /// `scope_extractor`: attribute receiving the extracted scope.
    #[serde(default)]
    mapped_attribute: Option<String>,
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

#[derive(Clone, Copy)]
enum HashAlgo {
    Sha256,
    Sha512,
}

impl HashAlgo {
    fn parse(s: &str, plugin_name: &str) -> Result<Self> {
        match s {
            "sha256" => Ok(HashAlgo::Sha256),
            "sha512" => Ok(HashAlgo::Sha512),
            other => Err(Error::Config(format!(
                "attribute_processor {plugin_name}: unsupported hash_algo: {other}"
            ))),
        }
    }

    fn digest(&self, value: &str, salt: &str) -> String {
        match self {
            HashAlgo::Sha256 => {
                let mut h = Sha256::new();
                h.update(value.as_bytes());
                h.update(salt.as_bytes());
                format!("{:x}", h.finalize())
            }
            HashAlgo::Sha512 => {
                let mut h = Sha512::new();
                h.update(value.as_bytes());
                h.update(salt.as_bytes());
                format!("{:x}", h.finalize())
            }
        }
    }
}

enum Processor {
    RegexSub { regex: Regex, replace: String },
    Hash { algo: HashAlgo, salt: String },
    Scope { scope: String },
    ScopeExtractor { mapped_attribute: String },
    ScopeRemover,
    Gender,
}

impl Processor {
    /// Apply this processor to `attribute` within the attribute map. A missing
    /// or unsuitable attribute is skipped, matching SATOSA where processor
    /// *warnings* are logged and the flow continues.
    fn apply(&self, attributes: &mut BTreeMap<String, Vec<String>>, attribute: &str) {
        match self {
            Processor::RegexSub { regex, replace } => {
                if let Some(values) = attributes.get_mut(attribute) {
                    for value in values.iter_mut() {
                        *value = regex.replace_all(value, replace.as_str()).into_owned();
                    }
                }
            }
            Processor::Hash { algo, salt } => {
                if let Some(values) = attributes.get_mut(attribute) {
                    for value in values.iter_mut() {
                        *value = algo.digest(value, salt);
                    }
                }
            }
            Processor::Scope { scope } => {
                if let Some(values) = attributes.get_mut(attribute) {
                    for value in values.iter_mut() {
                        *value = format!("{value}@{scope}");
                    }
                }
            }
            Processor::ScopeExtractor { mapped_attribute } => {
                let scope = attributes
                    .get(attribute)
                    .into_iter()
                    .flatten()
                    .find_map(|v| v.split_once('@').map(|(_, s)| s.to_string()));
                if let Some(scope) = scope {
                    attributes.insert(mapped_attribute.clone(), vec![scope]);
                }
            }
            Processor::ScopeRemover => {
                if let Some(values) = attributes.get_mut(attribute) {
                    for value in values.iter_mut() {
                        if let Some((local, _)) = value.split_once('@') {
                            *value = local.to_string();
                        }
                    }
                }
            }
            Processor::Gender => {
                if let Some(values) = attributes.get_mut(attribute) {
                    for value in values.iter_mut() {
                        *value = gender_to_schac(value).to_string();
                    }
                }
            }
        }
    }
}

/// Map a textual gender to its schacGender / ISO 5218 code.
fn gender_to_schac(value: &str) -> u8 {
    if value.is_empty() {
        return 9; // NOT_SPECIFIED
    }
    match value.to_ascii_uppercase().replace(' ', "_").as_str() {
        "MALE" => 1,
        "FEMALE" => 2,
        "NOT_SPECIFIED" => 9,
        _ => 0, // NOT_KNOWN
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

fn required_field<'a>(
    field: Option<&'a str>,
    plugin_name: &str,
    processor: &str,
    field_name: &str,
) -> Result<&'a str> {
    field.filter(|value| !value.is_empty()).ok_or_else(|| {
        Error::Config(format!(
            "attribute_processor {plugin_name}: {processor} needs {field_name}"
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
                        let pattern = required_field(
                            spec.match_pattern.as_deref(),
                            &bx.name,
                            "regex_sub",
                            "match_pattern",
                        )?;
                        let regex = Regex::new(pattern).map_err(|e| {
                            Error::Config(format!(
                                "attribute_processor {}: bad match_pattern: {e}",
                                bx.name
                            ))
                        })?;
                        let replace = convert_backrefs(required_field(
                            spec.replace_pattern.as_deref(),
                            &bx.name,
                            "regex_sub",
                            "replace_pattern",
                        )?);
                        processors.push(Processor::RegexSub { regex, replace });
                    }
                    "hash" => {
                        let algo = HashAlgo::parse(
                            spec.hash_algo.as_deref().unwrap_or("sha256"),
                            &bx.name,
                        )?;
                        processors.push(Processor::Hash {
                            algo,
                            salt: spec.salt.clone().unwrap_or_default(),
                        });
                    }
                    "scope" => {
                        let scope =
                            required_field(spec.scope.as_deref(), &bx.name, "scope", "scope")?;
                        processors.push(Processor::Scope {
                            scope: scope.to_string(),
                        });
                    }
                    "scope_extractor" => {
                        let mapped = required_field(
                            spec.mapped_attribute.as_deref(),
                            &bx.name,
                            "scope_extractor",
                            "mapped_attribute",
                        )?;
                        processors.push(Processor::ScopeExtractor {
                            mapped_attribute: mapped.to_string(),
                        });
                    }
                    "scope_remover" => processors.push(Processor::ScopeRemover),
                    "gender" => processors.push(Processor::Gender),
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
            for processor in &rule.processors {
                processor.apply(&mut data.attributes, &rule.attribute);
            }
        }
        Ok(data)
    }
}

#[cfg(test)]
mod tests {
    use super::super::testutil::{bx, ctx};
    use super::*;

    fn build(config: serde_json::Value) -> Box<dyn MicroService> {
        AttributeProcessor::build(&bx("proc", config)).unwrap()
    }

    #[tokio::test]
    async fn attribute_processor_regex_sub_satosa_subject_id() {
        // The production SATOSA config: subject-id "user@scope.tld" -> "user_scope".
        let proc = build(serde_json::json!({
            "process": [{
                "attribute": "subjectid",
                "processors": [{
                    "name": "regex_sub",
                    "match_pattern": "@([^.]+)\\.(.+)",
                    "replace_pattern": "_\\1"
                }]
            }]
        }));

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
        let proc = build(serde_json::json!({
            "process": [{
                "attribute": "affiliation",
                "processors": [
                    { "name": "regex_sub", "match_pattern": "staff", "replace_pattern": "employee" },
                    { "name": "regex_sub", "match_pattern": "^(\\w+)$", "replace_pattern": "$1@example.org" }
                ]
            }]
        }));

        let mut data = InternalData::default();
        data.set_attr("affiliation", "staff");
        let data = proc.process_response(&mut ctx(), data).await.unwrap();
        assert_eq!(data.attr_first("affiliation"), Some("employee@example.org"));
    }

    #[tokio::test]
    async fn hash_processor_salted_sha256() {
        let proc = build(serde_json::json!({
            "process": [{
                "attribute": "uid",
                "processors": [{ "name": "hash", "salt": "pepper" }]
            }]
        }));

        let mut data = InternalData::default();
        data.set_attr("uid", "anna");
        let data = proc.process_response(&mut ctx(), data).await.unwrap();
        // sha256("anna" || "pepper")
        let mut h = Sha256::new();
        h.update(b"annapepper");
        assert_eq!(
            data.attr_first("uid"),
            Some(format!("{:x}", h.finalize()).as_str())
        );
    }

    #[tokio::test]
    async fn scope_processors_roundtrip() {
        let proc = build(serde_json::json!({
            "process": [
                {
                    "attribute": "eppn",
                    "processors": [{ "name": "scope_extractor", "mapped_attribute": "domain" }]
                },
                {
                    "attribute": "eppn",
                    "processors": [{ "name": "scope_remover" }]
                },
                {
                    "attribute": "uid",
                    "processors": [{ "name": "scope", "scope": "example.org" }]
                }
            ]
        }));

        let mut data = InternalData::default();
        data.set_attr("eppn", "anna@example.org");
        data.set_attr("uid", "anna");
        let data = proc.process_response(&mut ctx(), data).await.unwrap();
        assert_eq!(data.attr_first("domain"), Some("example.org"));
        assert_eq!(data.attr_first("eppn"), Some("anna"));
        assert_eq!(data.attr_first("uid"), Some("anna@example.org"));
    }

    #[tokio::test]
    async fn gender_processor_maps_to_schac_codes() {
        let proc = build(serde_json::json!({
            "process": [{
                "attribute": "gender",
                "processors": [{ "name": "gender" }]
            }]
        }));

        for (input, expected) in [
            ("male", "1"),
            ("Female", "2"),
            ("not specified", "9"),
            ("mystery", "0"),
        ] {
            let mut data = InternalData::default();
            data.set_attr("gender", input);
            let data = proc.process_response(&mut ctx(), data).await.unwrap();
            assert_eq!(data.attr_first("gender"), Some(expected), "input {input}");
        }
    }

    #[test]
    fn attribute_processor_rejects_unknown_processor_and_bad_regex() {
        assert!(AttributeProcessor::build(&bx(
            "proc",
            serde_json::json!({
                "process": [{ "attribute": "a", "processors": [{ "name": "bogus" }] }]
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
        assert!(AttributeProcessor::build(&bx(
            "proc",
            serde_json::json!({
                "process": [{ "attribute": "a", "processors": [{ "name": "hash", "hash_algo": "md5" }] }]
            }),
        ))
        .is_err());
        assert!(AttributeProcessor::build(&bx(
            "proc",
            serde_json::json!({
                "process": [{ "attribute": "a", "processors": [{ "name": "scope_extractor" }] }]
            }),
        ))
        .is_err());
    }

    #[test]
    fn attribute_processor_requires_non_empty_regex_sub_patterns() {
        for cfg in [
            serde_json::json!({
                "process": [{
                    "attribute": "a",
                    "processors": [{ "name": "regex_sub", "replace_pattern": "x" }]
                }]
            }),
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
            serde_json::json!({
                "process": [{
                    "attribute": "a",
                    "processors": [{ "name": "regex_sub", "match_pattern": "a" }]
                }]
            }),
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
        ] {
            assert!(AttributeProcessor::build(&bx("proc", cfg)).is_err());
        }
    }

    #[test]
    fn convert_backrefs_forms() {
        assert_eq!(convert_backrefs("_\\1"), "_${1}");
        assert_eq!(convert_backrefs("\\10x"), "${10}x");
        assert_eq!(convert_backrefs("$1 stays"), "$1 stays");
        assert_eq!(convert_backrefs("no refs"), "no refs");
    }
}
