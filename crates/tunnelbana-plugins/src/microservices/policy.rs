//! `static_attributes` and `filter_attributes`.

use std::collections::BTreeMap;

use async_trait::async_trait;
use serde::Deserialize;
use tunnelbana_core::context::Context;
use tunnelbana_core::error::{Error, Result};
use tunnelbana_core::internal::InternalData;
use tunnelbana_core::plugin::{BuildContext, MicroService};

use super::level;

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
struct PolicyEntry {
    /// Internal attribute names to keep for this requester. Required when a
    /// policy entry exists; an explicit empty list means "release nothing".
    #[serde(default)]
    allowed: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
struct FilterAttributesConfig {
    /// Global allowlist applied when no per-requester policy matches.
    #[serde(default)]
    allowed: Option<Vec<String>>,
    /// Per-requester allowlists (SATOSA: `AttributePolicy`); `""` and
    /// `"default"` act as wildcard keys.
    #[serde(default)]
    policy: BTreeMap<String, PolicyEntry>,
}

/// Keeps only allow-listed internal attributes on the response path. A
/// per-requester `policy` entry overrides the global `allowed` list; with
/// neither, attributes pass through untouched.
pub struct FilterAttributes {
    name: String,
    allowed: Option<Vec<String>>,
    policy: BTreeMap<String, PolicyEntry>,
}

impl FilterAttributes {
    pub fn build(bx: &BuildContext) -> Result<Box<dyn MicroService>> {
        let cfg: FilterAttributesConfig = bx.parse_config()?;
        for (requester, entry) in &cfg.policy {
            if entry.allowed.is_none() {
                return Err(Error::Config(format!(
                    "filter_attributes {}: policy entry {requester:?} must set allowed (use [] to drop everything)",
                    bx.name,
                )));
            }
        }
        Ok(Box::new(FilterAttributes {
            name: bx.name.clone(),
            allowed: cfg.allowed,
            policy: cfg.policy,
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
        let requester = data.requester.as_deref().unwrap_or("");
        let allowed = match level(&self.policy, requester) {
            Some(policy) => policy.allowed.as_ref(),
            None => self.allowed.as_ref(),
        };
        if let Some(allowed) = allowed {
            data.attributes.retain(|k, _| allowed.contains(k));
        }
        Ok(data)
    }
}

#[cfg(test)]
mod tests {
    use super::super::testutil::{bx, ctx, response_from};
    use super::*;

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
    async fn per_requester_policy_overrides_global() {
        let filter = FilterAttributes::build(&bx(
            "filter",
            serde_json::json!({
                "allowed": ["mail", "affiliation"],
                "policy": { "https://strict.example": { "allowed": ["mail"] } }
            }),
        ))
        .unwrap();

        let mut data = response_from("https://strict.example");
        data.set_attr("mail", "a@x");
        data.set_attr("affiliation", "member");
        let data = filter.process_response(&mut ctx(), data).await.unwrap();
        assert!(data.attributes.contains_key("mail"));
        assert!(!data.attributes.contains_key("affiliation"));

        // Other requesters fall back to the global list.
        let mut data = response_from("https://open.example");
        data.set_attr("mail", "a@x");
        data.set_attr("affiliation", "member");
        let data = filter.process_response(&mut ctx(), data).await.unwrap();
        assert!(data.attributes.contains_key("affiliation"));
    }

    #[tokio::test]
    async fn no_config_passes_through() {
        let filter = FilterAttributes::build(&bx("filter", serde_json::json!({}))).unwrap();
        let mut data = InternalData::default();
        data.set_attr("mail", "a@x");
        let data = filter.process_response(&mut ctx(), data).await.unwrap();
        assert!(data.attributes.contains_key("mail"));
    }

    #[test]
    fn rejects_policy_entry_without_allowed() {
        assert!(FilterAttributes::build(&bx(
            "filter",
            serde_json::json!({
                "allowed": ["mail"],
                "policy": { "https://strict.example": {} }
            }),
        ))
        .is_err());
    }
}
