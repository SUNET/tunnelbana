//! `filter_attribute_values` and `rename_attributes`.

use std::collections::BTreeMap;

use async_trait::async_trait;
use regex::Regex;
use serde::Deserialize;
use tunnelbana_core::context::Context;
use tunnelbana_core::error::{Error, Result};
use tunnelbana_core::internal::InternalData;
use tunnelbana_core::plugin::{BuildContext, MicroService};

// ── filter_attribute_values ─────────────────────────────────────────────────

/// A filter is either a bare regex string or a `{ regexp = "…" }` table
/// (SATOSA's two notations). SATOSA's `shibmdscope_match_*` filter types need
/// a SAML metadata store decoration and are not supported.
#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum FilterSpec {
    Pattern(String),
    Typed(BTreeMap<String, String>),
}

/// `provider (issuer) -> requester -> attribute -> filter`, where `""` keys
/// are defaults applied *in addition to* (before) the specific entries, and an
/// attribute key of `""` applies the filter to every attribute (SATOSA:
/// `FilterAttributeValues`).
type RawFilters = BTreeMap<String, BTreeMap<String, BTreeMap<String, FilterSpec>>>;
type Filters = BTreeMap<String, BTreeMap<String, BTreeMap<String, Regex>>>;

#[derive(Debug, Deserialize)]
struct FilterAttributeValuesConfig {
    #[serde(default)]
    attribute_filters: RawFilters,
}

/// Drops attribute *values* not matching the configured regex (unanchored
/// search), keyed per target provider and requester. Unlike
/// `filter_attributes` (which drops whole attributes) this filters within the
/// value lists.
pub struct FilterAttributeValues {
    name: String,
    filters: Filters,
}

fn compile_filters(raw: RawFilters, name: &str) -> Result<Filters> {
    let mut compiled = Filters::new();
    for (provider, by_requester) in raw {
        let mut requesters = BTreeMap::new();
        for (requester, by_attr) in by_requester {
            let mut attrs = BTreeMap::new();
            for (attr, spec) in by_attr {
                let pattern = match spec {
                    FilterSpec::Pattern(p) => p,
                    FilterSpec::Typed(map) => {
                        let mut it = map.into_iter();
                        let entry = it.next();
                        match (entry, it.next()) {
                            (Some((kind, value)), None) if kind == "regexp" => value,
                            (Some((kind, _)), _) if kind != "regexp" => {
                                return Err(Error::Config(format!(
                                    "filter_attribute_values {name}: unsupported filter type {kind:?}"
                                )));
                            }
                            _ => {
                                return Err(Error::Config(format!(
                                    "filter_attribute_values {name}: a filter needs exactly one regexp"
                                )));
                            }
                        }
                    }
                };
                let regex = Regex::new(&pattern).map_err(|e| {
                    Error::Config(format!(
                        "filter_attribute_values {name}: bad pattern {pattern:?}: {e}"
                    ))
                })?;
                attrs.insert(attr, regex);
            }
            requesters.insert(requester, attrs);
        }
        compiled.insert(provider, requesters);
    }
    Ok(compiled)
}

impl FilterAttributeValues {
    pub fn build(bx: &BuildContext) -> Result<Box<dyn MicroService>> {
        let cfg: FilterAttributeValuesConfig = bx.parse_config()?;
        Ok(Box::new(FilterAttributeValues {
            name: bx.name.clone(),
            filters: compile_filters(cfg.attribute_filters, &bx.name)?,
        }))
    }

    fn apply(attributes: &mut BTreeMap<String, Vec<String>>, filters: &BTreeMap<String, Regex>) {
        for (attr, regex) in filters {
            if attr.is_empty() {
                for values in attributes.values_mut() {
                    values.retain(|v| regex.is_match(v));
                }
            } else if let Some(values) = attributes.get_mut(attr) {
                values.retain(|v| regex.is_match(v));
            }
        }
    }
}

#[async_trait]
impl MicroService for FilterAttributeValues {
    fn name(&self) -> &str {
        &self.name
    }

    async fn process_response(
        &self,
        _ctx: &mut Context,
        mut data: InternalData,
    ) -> Result<InternalData> {
        let requester = data.requester.clone().unwrap_or_default();
        let provider = data.auth_info.issuer.clone().unwrap_or_default();

        // SATOSA application order: default provider then specific provider;
        // within each, default requester then specific requester.
        let mut provider_keys = vec![String::new()];
        if !provider.is_empty() {
            provider_keys.push(provider);
        }
        let mut requester_keys = vec![String::new()];
        if !requester.is_empty() {
            requester_keys.push(requester);
        }
        for pk in &provider_keys {
            let Some(by_requester) = self.filters.get(pk) else {
                continue;
            };
            for rk in &requester_keys {
                if let Some(filters) = by_requester.get(rk) {
                    Self::apply(&mut data.attributes, filters);
                }
            }
        }
        Ok(data)
    }
}

// ── rename_attributes ───────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct RenameAttributesConfig {
    /// `old internal name -> new internal name`.
    #[serde(default)]
    rename: BTreeMap<String, String>,
}

/// Renames internal attributes on the response path; values merge into the
/// target attribute when it already exists.
pub struct RenameAttributes {
    name: String,
    rename: BTreeMap<String, String>,
}

impl RenameAttributes {
    pub fn build(bx: &BuildContext) -> Result<Box<dyn MicroService>> {
        let cfg: RenameAttributesConfig = bx.parse_config()?;
        Ok(Box::new(RenameAttributes {
            name: bx.name.clone(),
            rename: cfg.rename,
        }))
    }
}

#[async_trait]
impl MicroService for RenameAttributes {
    fn name(&self) -> &str {
        &self.name
    }

    async fn process_response(
        &self,
        _ctx: &mut Context,
        mut data: InternalData,
    ) -> Result<InternalData> {
        for (old, new) in &self.rename {
            if let Some(values) = data.attributes.remove(old) {
                data.attributes
                    .entry(new.clone())
                    .or_default()
                    .extend(values);
            }
        }
        Ok(data)
    }
}

#[cfg(test)]
mod tests {
    use super::super::testutil::{bx, ctx, response_from};
    use super::*;

    #[tokio::test]
    async fn filters_values_by_regex_string_and_typed_form() {
        let filter = FilterAttributeValues::build(&bx(
            "fav",
            serde_json::json!({
                "attribute_filters": {
                    "": {
                        "": {
                            // Bare string form: keep only example.org eppns.
                            "edupersonprincipalname": "@example\\.org$",
                            // Typed form.
                            "mail": { "regexp": "@example\\.org$" }
                        }
                    }
                }
            }),
        ))
        .unwrap();

        let mut data = InternalData::default();
        data.attributes.insert(
            "edupersonprincipalname".into(),
            vec!["a@example.org".into(), "b@evil.example".into()],
        );
        data.attributes.insert(
            "mail".into(),
            vec!["a@example.org".into(), "b@other.example".into()],
        );
        data.set_attr("displayname", "Anna");
        let data = filter.process_response(&mut ctx(), data).await.unwrap();
        assert_eq!(
            data.attributes["edupersonprincipalname"],
            vec!["a@example.org"]
        );
        assert_eq!(data.attributes["mail"], vec!["a@example.org"]);
        // Unfiltered attributes are untouched.
        assert_eq!(data.attr_first("displayname"), Some("Anna"));
    }

    #[tokio::test]
    async fn requester_and_provider_specific_filters_stack_on_defaults() {
        let filter = FilterAttributeValues::build(&bx(
            "fav",
            serde_json::json!({
                "attribute_filters": {
                    "": {
                        "https://sp.example": { "affiliation": "^(staff|member)$" }
                    },
                    "https://idp.example": {
                        "": { "affiliation": "^staff$" }
                    }
                }
            }),
        ))
        .unwrap();

        let mut data = response_from("https://sp.example");
        data.auth_info.issuer = Some("https://idp.example".into());
        data.attributes.insert(
            "affiliation".into(),
            vec!["staff".into(), "member".into(), "student".into()],
        );
        let data = filter.process_response(&mut ctx(), data).await.unwrap();
        // Both layers applied: requester filter keeps staff|member, then the
        // provider filter narrows to staff.
        assert_eq!(data.attributes["affiliation"], vec!["staff"]);
    }

    #[tokio::test]
    async fn empty_attribute_key_filters_all_attributes() {
        let filter = FilterAttributeValues::build(&bx(
            "fav",
            serde_json::json!({
                "attribute_filters": { "": { "": { "": "^[^<]*$" } } }
            }),
        ))
        .unwrap();

        let mut data = InternalData::default();
        data.attributes
            .insert("displayname".into(), vec!["Anna".into(), "<script>".into()]);
        let data = filter.process_response(&mut ctx(), data).await.unwrap();
        assert_eq!(data.attributes["displayname"], vec!["Anna"]);
    }

    #[test]
    fn rejects_unknown_filter_type_and_bad_regex() {
        assert!(FilterAttributeValues::build(&bx(
            "fav",
            serde_json::json!({
                "attribute_filters": { "": { "": { "mail": { "shibmdscope_match_scope": "x" } } } }
            }),
        ))
        .is_err());
        assert!(FilterAttributeValues::build(&bx(
            "fav",
            serde_json::json!({
                "attribute_filters": { "": { "": { "mail": "(" } } }
            }),
        ))
        .is_err());
    }

    #[tokio::test]
    async fn renames_and_merges_attributes() {
        let rename = RenameAttributes::build(&bx(
            "rename",
            serde_json::json!({ "rename": { "surname": "sn", "missing": "other" } }),
        ))
        .unwrap();

        let mut data = InternalData::default();
        data.set_attr("surname", "Andersson");
        data.set_attr("sn", "Existing");
        let data = rename.process_response(&mut ctx(), data).await.unwrap();
        assert!(!data.attributes.contains_key("surname"));
        assert_eq!(data.attributes["sn"], vec!["Existing", "Andersson"]);
        assert!(!data.attributes.contains_key("other"));
    }
}
