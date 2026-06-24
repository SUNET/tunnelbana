//! `static_attributes_for_virtual_idp` — inject/append static attributes keyed
//! by `(requester, virtual_idp)`.
//!
//! Ports eduID's `AddStaticAttributesForVirtualIdp`. Unlike the simpler
//! `static_attributes` (which inserts a flat default set), this resolves a
//! recipe by two-level lookup — first the requester (SP), then the virtual IdP
//! (the originating frontend, SATOSA's `virtual_idp`) — using the same
//! exact→`""`→`"default"` fallback as the rest of the micro-services. It
//! supports two maps:
//!
//! - `static_attributes_for_virtual_idp` — **replace**: set the attribute to
//!   the configured values.
//! - `static_appended_attributes_for_virtual_idp` — **append**: union the
//!   configured values with whatever the IdP already released, de-duplicated
//!   and sorted for stability.

use std::collections::BTreeMap;

use async_trait::async_trait;
use serde::Deserialize;
use tunnelbana_core::context::{Context, KEY_TARGET_FRONTEND, STATE_KEY_BASE};
use tunnelbana_core::error::Result;
use tunnelbana_core::internal::InternalData;
use tunnelbana_core::plugin::{BuildContext, MicroService};

use super::level;

/// `requester → virtual_idp → attr_name → values`.
type VirtualIdpMap = BTreeMap<String, BTreeMap<String, BTreeMap<String, Vec<String>>>>;

#[derive(Debug, Default, Deserialize)]
struct StaticForVidpConfig {
    /// Attributes that replace whatever the IdP released.
    #[serde(default)]
    static_attributes_for_virtual_idp: VirtualIdpMap,
    /// Attributes whose configured values are merged with the released values.
    #[serde(default)]
    static_appended_attributes_for_virtual_idp: VirtualIdpMap,
}

/// Injects static attributes per `(requester, virtual_idp)` (SATOSA/eduID:
/// `AddStaticAttributesForVirtualIdp`).
pub struct StaticAttributesForVirtualIdp {
    name: String,
    replace: VirtualIdpMap,
    append: VirtualIdpMap,
}

impl StaticAttributesForVirtualIdp {
    pub fn build(bx: &BuildContext) -> Result<Box<dyn MicroService>> {
        let cfg: StaticForVidpConfig = bx.parse_config()?;
        Ok(Box::new(StaticAttributesForVirtualIdp {
            name: bx.name.clone(),
            replace: cfg.static_attributes_for_virtual_idp,
            append: cfg.static_appended_attributes_for_virtual_idp,
        }))
    }

    /// Two-level `(requester, virtual_idp)` recipe lookup.
    fn recipe<'a>(
        map: &'a VirtualIdpMap,
        requester: &str,
        vidp: &str,
    ) -> Option<&'a BTreeMap<String, Vec<String>>> {
        level(map, requester).and_then(|by_vidp| level(by_vidp, vidp))
    }
}

#[async_trait]
impl MicroService for StaticAttributesForVirtualIdp {
    fn name(&self) -> &str {
        &self.name
    }

    async fn process_response(
        &self,
        ctx: &mut Context,
        mut data: InternalData,
    ) -> Result<InternalData> {
        let requester = data.requester.clone().unwrap_or_default();
        let vidp = ctx
            .target_frontend
            .clone()
            .or_else(|| ctx.state.get_str(STATE_KEY_BASE, KEY_TARGET_FRONTEND))
            .unwrap_or_default();

        // Replace: overwrite the attribute with the configured values.
        if let Some(recipe) = Self::recipe(&self.replace, &requester, &vidp) {
            for (attr, values) in recipe {
                data.attributes.insert(attr.clone(), values.clone());
            }
        }

        // Append: union configured + already-released values, dedup and sort.
        if let Some(recipe) = Self::recipe(&self.append, &requester, &vidp) {
            for (attr, values) in recipe {
                let mut merged = values.clone();
                if let Some(existing) = data.attributes.get(attr) {
                    for v in existing {
                        if !merged.contains(v) {
                            merged.push(v.clone());
                        }
                    }
                }
                merged.sort();
                data.attributes.insert(attr.clone(), merged);
            }
        }

        Ok(data)
    }
}

#[cfg(test)]
mod tests {
    use super::super::testutil::{bx, ctx, response_from};
    use super::*;

    fn with_frontend(name: &str) -> Context {
        let mut c = ctx();
        c.target_frontend = Some(name.to_string());
        c
    }

    #[tokio::test]
    async fn replace_sets_attribute_for_matching_requester_and_vidp() {
        let ms = StaticAttributesForVirtualIdp::build(&bx(
            "static_vidp",
            serde_json::json!({
                "static_attributes_for_virtual_idp": {
                    "https://sp.example": { "SunetIDP": { "schachomeorganization": ["foo"] } },
                    "default": { "SunetIDP": { "schachomeorganization": ["bar"] } }
                }
            }),
        ))
        .unwrap();

        let mut data = response_from("https://sp.example");
        data.set_attr("schachomeorganization", "preexisting");
        let data = ms
            .process_response(&mut with_frontend("SunetIDP"), data)
            .await
            .unwrap();
        assert_eq!(data.attr_first("schachomeorganization"), Some("foo"));
    }

    #[tokio::test]
    async fn replace_falls_back_to_default_requester() {
        let ms = StaticAttributesForVirtualIdp::build(&bx(
            "static_vidp",
            serde_json::json!({
                "static_attributes_for_virtual_idp": {
                    "default": { "SunetIDP": { "schachomeorganization": ["bar"] } }
                }
            }),
        ))
        .unwrap();

        let data = response_from("https://unknown.example");
        let data = ms
            .process_response(&mut with_frontend("SunetIDP"), data)
            .await
            .unwrap();
        assert_eq!(data.attr_first("schachomeorganization"), Some("bar"));
    }

    #[tokio::test]
    async fn append_unions_dedups_and_sorts() {
        let ms = StaticAttributesForVirtualIdp::build(&bx(
            "static_vidp",
            serde_json::json!({
                "static_appended_attributes_for_virtual_idp": {
                    "default": { "SunetIDP": { "edupersonassurance": ["b", "a"] } }
                }
            }),
        ))
        .unwrap();

        let mut data = response_from("https://sp.example");
        data.attributes
            .insert("edupersonassurance".into(), vec!["c".into(), "a".into()]);
        let data = ms
            .process_response(&mut with_frontend("SunetIDP"), data)
            .await
            .unwrap();
        assert_eq!(
            data.attributes.get("edupersonassurance"),
            Some(&vec!["a".to_string(), "b".to_string(), "c".to_string()])
        );
    }

    #[tokio::test]
    async fn no_matching_recipe_passes_through() {
        let ms = StaticAttributesForVirtualIdp::build(&bx(
            "static_vidp",
            serde_json::json!({
                "static_attributes_for_virtual_idp": {
                    "https://only.example": { "OtherIDP": { "x": ["y"] } }
                }
            }),
        ))
        .unwrap();

        let mut data = response_from("https://sp.example");
        data.set_attr("mail", "a@x");
        let data = ms
            .process_response(&mut with_frontend("SunetIDP"), data)
            .await
            .unwrap();
        assert_eq!(data.attr_first("mail"), Some("a@x"));
        assert!(!data.attributes.contains_key("x"));
    }

    #[tokio::test]
    async fn reads_vidp_from_state_when_context_field_unset() {
        let ms = StaticAttributesForVirtualIdp::build(&bx(
            "static_vidp",
            serde_json::json!({
                "static_attributes_for_virtual_idp": {
                    "default": { "SunetIDP": { "schachomeorganization": ["bar"] } }
                }
            }),
        ))
        .unwrap();

        let mut c = ctx();
        c.state
            .set_str(STATE_KEY_BASE, KEY_TARGET_FRONTEND, "SunetIDP");
        let data = ms
            .process_response(&mut c, response_from("https://sp.example"))
            .await
            .unwrap();
        assert_eq!(data.attr_first("schachomeorganization"), Some("bar"));
    }

    #[test]
    fn empty_config_builds() {
        assert!(
            StaticAttributesForVirtualIdp::build(&bx("static_vidp", serde_json::json!({}))).is_ok()
        );
    }
}
