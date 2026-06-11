//! `attribute_generation` — synthesize attributes from templates.

use std::collections::BTreeMap;

use async_trait::async_trait;
use serde::Deserialize;
use tunnelbana_core::context::Context;
use tunnelbana_core::error::{Error, Result};
use tunnelbana_core::internal::InternalData;
use tunnelbana_core::plugin::{BuildContext, MicroService};

use super::level;

/// `requester -> provider (issuer) -> attribute -> template`, with `""` and
/// `"default"` as synonymous wildcards (SATOSA: `AddSyntheticAttributes`).
type RawRecipes = BTreeMap<String, BTreeMap<String, BTreeMap<String, String>>>;

#[derive(Debug, Deserialize)]
struct AttributeGenerationConfig {
    #[serde(default)]
    synthetic_attributes: RawRecipes,
}

/// Synthesizes attributes from [Tera](https://keats.github.io/tera/) templates
/// evaluated over the current attribute set (SATOSA uses Mustache; the recipe
/// structure is the same, the template syntax is Tera's).
///
/// Each existing attribute is exposed to the template as an object with
/// `value` (values joined with `;`), `first`, `scope` (the part after `@` of
/// the first scoped value) and `values` (the full list, e.g. for `{% for %}`
/// loops). The rendered output is split on `;`/newlines into the synthetic
/// attribute's values; synthetic attributes override existing ones.
pub struct AttributeGeneration {
    name: String,
    tera: tera::Tera,
    /// `requester -> provider -> attribute -> template name in `tera``.
    recipes: BTreeMap<String, BTreeMap<String, BTreeMap<String, String>>>,
}

impl AttributeGeneration {
    pub fn build(bx: &BuildContext) -> Result<Box<dyn MicroService>> {
        let cfg: AttributeGenerationConfig = bx.parse_config()?;
        let mut tera = tera::Tera::default();
        let mut recipes = BTreeMap::new();
        let mut counter = 0usize;
        for (requester, by_provider) in cfg.synthetic_attributes {
            let mut providers = BTreeMap::new();
            for (provider, attrs) in by_provider {
                let mut by_attr = BTreeMap::new();
                for (attr, template) in attrs {
                    let id = format!("syn_{counter}");
                    counter += 1;
                    tera.add_raw_template(&id, &template).map_err(|e| {
                        Error::Config(format!(
                            "attribute_generation {}: bad template for {attr}: {e}",
                            bx.name
                        ))
                    })?;
                    by_attr.insert(attr, id);
                }
                providers.insert(provider, by_attr);
            }
            recipes.insert(requester, providers);
        }
        Ok(Box::new(AttributeGeneration {
            name: bx.name.clone(),
            tera,
            recipes,
        }))
    }

    fn template_context(attributes: &BTreeMap<String, Vec<String>>) -> tera::Context {
        let mut ctx = tera::Context::new();
        for (name, values) in attributes {
            let scope = values
                .iter()
                .find_map(|v| v.split_once('@').map(|(_, s)| s.to_string()))
                .unwrap_or_default();
            ctx.insert(
                name,
                &serde_json::json!({
                    "value": values.join(";"),
                    "first": values.first().cloned().unwrap_or_default(),
                    "scope": scope,
                    "values": values,
                }),
            );
        }
        ctx
    }
}

#[async_trait]
impl MicroService for AttributeGeneration {
    fn name(&self) -> &str {
        &self.name
    }

    async fn process_response(
        &self,
        _ctx: &mut Context,
        mut data: InternalData,
    ) -> Result<InternalData> {
        let requester = data.requester.as_deref().unwrap_or("");
        let provider = data.auth_info.issuer.as_deref().unwrap_or("");
        let Some(recipes) =
            level(&self.recipes, requester).and_then(|by_provider| level(by_provider, provider))
        else {
            return Ok(data);
        };

        let tctx = Self::template_context(&data.attributes);
        for (attr, template_id) in recipes {
            let rendered = self.tera.render(template_id, &tctx).map_err(|e| {
                Error::Internal(format!(
                    "attribute_generation {}: rendering {attr} failed: {e}",
                    self.name
                ))
            })?;
            let values: Vec<String> = rendered
                .split(['\n', ';'])
                .map(|t| t.trim())
                .filter(|t| !t.is_empty())
                .map(str::to_string)
                .collect();
            data.attributes.insert(attr.clone(), values);
        }
        Ok(data)
    }
}

#[cfg(test)]
mod tests {
    use super::super::testutil::{bx, ctx, response_from};
    use super::*;

    #[tokio::test]
    async fn synthesizes_static_and_scope_derived_attributes() {
        // The SATOSA doc example: schacHomeOrganization from the eppn scope.
        let svc = AttributeGeneration::build(&bx(
            "gen",
            serde_json::json!({
                "synthetic_attributes": {
                    "default": {
                        "default": {
                            "schachomeorganization": "{{ edupersonprincipalname.scope }}",
                            "edupersonaffiliation": "member;employee"
                        }
                    }
                }
            }),
        ))
        .unwrap();

        let mut data = InternalData::default();
        data.set_attr("edupersonprincipalname", "anna@example.org");
        let data = svc.process_response(&mut ctx(), data).await.unwrap();
        assert_eq!(
            data.attr_first("schachomeorganization"),
            Some("example.org")
        );
        assert_eq!(
            data.attributes["edupersonaffiliation"],
            vec!["member", "employee"]
        );
    }

    #[tokio::test]
    async fn iterates_values_and_scopes_rules_per_requester() {
        let svc = AttributeGeneration::build(&bx(
            "gen",
            serde_json::json!({
                "synthetic_attributes": {
                    "https://sp.example": {
                        "default": {
                            "labels": "{% for v in affiliation.values %}{{ v }}-x;{% endfor %}"
                        }
                    }
                }
            }),
        ))
        .unwrap();

        let mut data = response_from("https://sp.example");
        data.attributes
            .insert("affiliation".into(), vec!["staff".into(), "member".into()]);
        let data = svc.process_response(&mut ctx(), data).await.unwrap();
        assert_eq!(data.attributes["labels"], vec!["staff-x", "member-x"]);

        // No recipe for other requesters.
        let mut other = response_from("https://other.example");
        other.set_attr("affiliation", "staff");
        let other = svc.process_response(&mut ctx(), other).await.unwrap();
        assert!(!other.attributes.contains_key("labels"));
    }

    #[test]
    fn rejects_bad_template_at_build_time() {
        assert!(AttributeGeneration::build(&bx(
            "gen",
            serde_json::json!({
                "synthetic_attributes": {
                    "default": { "default": { "x": "{% broken" } }
                }
            }),
        ))
        .is_err());
    }
}
