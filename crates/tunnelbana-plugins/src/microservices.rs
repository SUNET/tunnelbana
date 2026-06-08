//! Built-in micro-services.
//!
//! - `static_attributes` — inject fixed attributes on the response path.
//! - `filter_attributes` — keep only allow-listed attributes on the response path.
//! - `custom_routing` — pick the backend by requester on the request path.

use std::collections::BTreeMap;

use async_trait::async_trait;
use serde::Deserialize;
use tunnelbana_core::context::Context;
use tunnelbana_core::error::Result;
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
            data.attributes.entry(k.clone()).or_insert_with(|| v.clone());
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

    async fn process_request(
        &self,
        ctx: &mut Context,
        data: InternalData,
    ) -> Result<InternalData> {
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

        let filter = FilterAttributes::build(&bx(
            "filter",
            serde_json::json!({ "allowed": ["mail"] }),
        ))
        .unwrap();
        let data = filter.process_response(&mut ctx(), data).await.unwrap();
        assert_eq!(data.attr_first("mail"), Some("a@x"));
        assert!(data.attributes.get("affiliation").is_none());
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
