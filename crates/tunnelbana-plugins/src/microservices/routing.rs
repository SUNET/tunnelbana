//! `custom_routing` and `idp_hinting`.

use std::collections::BTreeMap;

use async_trait::async_trait;
use serde::Deserialize;
use tunnelbana_core::context::{Context, KEY_TARGET_ENTITYID};
use tunnelbana_core::error::{Error, Result};
use tunnelbana_core::internal::InternalData;
use tunnelbana_core::plugin::{BuildContext, MicroService};

// ── custom_routing ──────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct RoutingRule {
    requester: String,
    backend: String,
}

#[derive(Debug, Deserialize)]
struct IssuerRule {
    issuer: String,
    backend: String,
}

#[derive(Debug, Deserialize)]
struct CustomRoutingConfig {
    #[serde(default)]
    rule: Vec<RoutingRule>,
    /// Match against the target-entity decoration (set by a discovery service
    /// or `idp_hinting`); takes precedence over requester rules (SATOSA:
    /// `DecideBackendByTargetIssuer`).
    #[serde(default)]
    issuer_rule: Vec<IssuerRule>,
    #[serde(default)]
    default_backend: Option<String>,
}

/// Selects the backend on the request path based on the target issuer (when a
/// target-entity decoration is present) or the requester (SP/RP id).
pub struct CustomRouting {
    name: String,
    rules: BTreeMap<String, String>,
    issuer_rules: BTreeMap<String, String>,
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
        let issuer_rules = cfg
            .issuer_rule
            .into_iter()
            .map(|r| (r.issuer, r.backend))
            .collect();
        Ok(Box::new(CustomRouting {
            name: bx.name.clone(),
            rules,
            issuer_rules,
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
        let issuer = ctx
            .decoration(KEY_TARGET_ENTITYID)
            .and_then(|v| v.as_str())
            .map(str::to_string);
        let by_issuer = issuer.as_deref().and_then(|i| self.issuer_rules.get(i));
        let by_requester = data
            .requester
            .as_deref()
            .and_then(|r| self.rules.get(r));

        if let Some(backend) = by_issuer.or(by_requester) {
            ctx.target_backend = Some(backend.clone());
        } else if (data.requester.is_some() || issuer.is_some())
            && self.default_backend.is_some()
        {
            ctx.target_backend = self.default_backend.clone();
        }
        Ok(data)
    }
}

// ── idp_hinting ─────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct IdpHintingConfig {
    /// Query-parameter names that may carry an IdP entity id hint.
    allowed_params: Vec<String>,
}

/// Lifts an IdP hint query parameter (e.g. `?idphint=…`) into the
/// target-entity decoration so the backend (or issuer-based routing) can act
/// on it. A decoration already set by an earlier step wins.
pub struct IdpHinting {
    name: String,
    allowed_params: Vec<String>,
}

impl IdpHinting {
    pub fn build(bx: &BuildContext) -> Result<Box<dyn MicroService>> {
        let cfg: IdpHintingConfig = bx.parse_config()?;
        if cfg.allowed_params.is_empty() {
            return Err(Error::Config(format!(
                "idp_hinting {}: allowed_params must not be empty",
                bx.name
            )));
        }
        Ok(Box::new(IdpHinting {
            name: bx.name.clone(),
            allowed_params: cfg.allowed_params,
        }))
    }
}

#[async_trait]
impl MicroService for IdpHinting {
    fn name(&self) -> &str {
        &self.name
    }

    async fn process_request(&self, ctx: &mut Context, data: InternalData) -> Result<InternalData> {
        if ctx.decoration(KEY_TARGET_ENTITYID).is_some() {
            return Ok(data);
        }
        let hint = self
            .allowed_params
            .iter()
            .find_map(|p| ctx.request.query.get(p))
            .filter(|v| !v.is_empty())
            .cloned();
        if let Some(hint) = hint {
            ctx.decorate(KEY_TARGET_ENTITYID, serde_json::Value::String(hint));
        }
        Ok(data)
    }
}

#[cfg(test)]
mod tests {
    use super::super::testutil::{bx, ctx};
    use super::*;

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

    #[tokio::test]
    async fn routing_by_target_issuer_beats_requester() {
        let routing = CustomRouting::build(&bx(
            "route",
            serde_json::json!({
                "rule": [{ "requester": "sp-a", "backend": "Oidc" }],
                "issuer_rule": [{ "issuer": "https://idp.example", "backend": "Saml2" }]
            }),
        ))
        .unwrap();

        let mut c = ctx();
        c.decorate(
            KEY_TARGET_ENTITYID,
            serde_json::Value::String("https://idp.example".into()),
        );
        let _ = routing
            .process_request(&mut c, InternalData::request("sp-a"))
            .await
            .unwrap();
        assert_eq!(c.target_backend.as_deref(), Some("Saml2"));

        // Unmatched issuer falls back to requester rules.
        let mut c = ctx();
        c.decorate(
            KEY_TARGET_ENTITYID,
            serde_json::Value::String("https://other.example".into()),
        );
        let _ = routing
            .process_request(&mut c, InternalData::request("sp-a"))
            .await
            .unwrap();
        assert_eq!(c.target_backend.as_deref(), Some("Oidc"));
    }

    #[tokio::test]
    async fn idp_hinting_sets_decoration_once() {
        let hinting = IdpHinting::build(&bx(
            "hint",
            serde_json::json!({ "allowed_params": ["idphint", "idp_hint"] }),
        ))
        .unwrap();

        let mut c = ctx();
        c.request
            .query
            .insert("idp_hint".into(), "https://idp.example".into());
        let _ = hinting
            .process_request(&mut c, InternalData::request("sp-a"))
            .await
            .unwrap();
        assert_eq!(
            c.decoration(KEY_TARGET_ENTITYID).and_then(|v| v.as_str()),
            Some("https://idp.example")
        );

        // An existing decoration is not overwritten.
        c.request
            .query
            .insert("idp_hint".into(), "https://evil.example".into());
        let _ = hinting
            .process_request(&mut c, InternalData::request("sp-a"))
            .await
            .unwrap();
        assert_eq!(
            c.decoration(KEY_TARGET_ENTITYID).and_then(|v| v.as_str()),
            Some("https://idp.example")
        );
    }

    #[test]
    fn idp_hinting_requires_params() {
        assert!(IdpHinting::build(&bx("hint", serde_json::json!({ "allowed_params": [] }))).is_err());
    }
}
