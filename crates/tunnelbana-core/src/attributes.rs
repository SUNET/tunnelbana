//! Attribute mapping between protocol-specific names and the internal model.
//!
//! Driven by `attributes.toml`. Each internal attribute name maps, per profile
//! (`saml`, `openid`, `oauth`, ...), to one or more external names. Conversion
//! is bidirectional and priority-ordered: when several external names map to one
//! internal name, the first non-empty source wins on the way in.

use crate::error::Result;
use serde::Deserialize;
use std::collections::BTreeMap;

/// The parsed attribute map.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct AttributeMap {
    /// internal-name -> (profile -> [external names]).
    #[serde(default)]
    pub attributes: BTreeMap<String, BTreeMap<String, Vec<String>>>,
    /// Internal attribute names whose joined values compose the subject id.
    #[serde(default)]
    pub user_id_from_attrs: Vec<String>,
    /// If set, the subject id is also copied into this internal attribute.
    #[serde(default)]
    pub user_id_to_attr: Option<String>,
}

/// Maps attributes in both directions for a given profile.
#[derive(Debug, Clone, Default)]
pub struct AttributeMapper {
    map: AttributeMap,
}

impl AttributeMapper {
    pub fn new(map: AttributeMap) -> Self {
        Self { map }
    }

    /// Parse an attribute map from a TOML string.
    pub fn from_toml(toml_str: &str) -> Result<Self> {
        let map: AttributeMap = toml::from_str(toml_str)
            .map_err(|e| crate::error::Error::Config(format!("attribute map: {e}")))?;
        Ok(Self::new(map))
    }

    pub fn raw(&self) -> &AttributeMap {
        &self.map
    }

    /// Convert external (protocol) attributes into internal attributes.
    ///
    /// For each internal attribute, the external names listed for `profile` are
    /// tried in order; values from every matching external name are collected
    /// (deduplicated, order-preserving).
    pub fn to_internal(
        &self,
        profile: &str,
        external: &BTreeMap<String, Vec<String>>,
    ) -> BTreeMap<String, Vec<String>> {
        let mut internal: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for (internal_name, profiles) in &self.map.attributes {
            let Some(ext_names) = profiles.get(profile) else {
                continue;
            };
            let mut values: Vec<String> = Vec::new();
            for ext in ext_names {
                if let Some(vals) = external.get(ext) {
                    for v in vals {
                        if !values.contains(v) {
                            values.push(v.clone());
                        }
                    }
                }
            }
            if !values.is_empty() {
                internal.insert(internal_name.clone(), values);
            }
        }
        internal
    }

    /// Convert internal attributes into external (protocol) attributes.
    ///
    /// Each internal attribute is emitted under the first external name listed
    /// for `profile` (the canonical name for that protocol).
    pub fn from_internal(
        &self,
        profile: &str,
        internal: &BTreeMap<String, Vec<String>>,
    ) -> BTreeMap<String, Vec<String>> {
        let mut external: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for (internal_name, values) in internal {
            let Some(profiles) = self.map.attributes.get(internal_name) else {
                continue;
            };
            let Some(ext_names) = profiles.get(profile) else {
                continue;
            };
            if let Some(canonical) = ext_names.first() {
                external.insert(canonical.clone(), values.clone());
            }
        }
        external
    }

    /// Compose a subject id from the configured `user_id_from_attrs` (joined
    /// with ':'), reading from internal attributes.
    pub fn compose_subject_id(&self, internal: &BTreeMap<String, Vec<String>>) -> Option<String> {
        if self.map.user_id_from_attrs.is_empty() {
            return None;
        }
        let mut parts = Vec::new();
        for name in &self.map.user_id_from_attrs {
            let v = internal.get(name).and_then(|v| v.first())?;
            parts.push(v.clone());
        }
        Some(parts.join(":"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mapper() -> AttributeMapper {
        let toml_str = r#"
            user_id_from_attrs = ["edupersonprincipalname"]

            [attributes.mail]
            openid = ["email"]
            saml = ["email", "emailAddress", "mail"]

            [attributes.givenname]
            openid = ["given_name"]
            saml = ["givenName"]

            [attributes.edupersonprincipalname]
            openid = ["sub"]
            saml = ["eduPersonPrincipalName"]
        "#;
        AttributeMapper::from_toml(toml_str).unwrap()
    }

    #[test]
    fn saml_to_internal_to_openid() {
        let m = mapper();
        let mut saml = BTreeMap::new();
        saml.insert("mail".to_string(), vec!["a@x.se".to_string()]);
        saml.insert("givenName".to_string(), vec!["Anna".to_string()]);
        saml.insert(
            "eduPersonPrincipalName".to_string(),
            vec!["anna@x.se".to_string()],
        );

        let internal = m.to_internal("saml", &saml);
        assert_eq!(internal.get("mail").unwrap(), &vec!["a@x.se".to_string()]);
        assert_eq!(
            m.compose_subject_id(&internal).as_deref(),
            Some("anna@x.se")
        );

        let openid = m.from_internal("openid", &internal);
        assert_eq!(openid.get("email").unwrap(), &vec!["a@x.se".to_string()]);
        assert_eq!(openid.get("given_name").unwrap(), &vec!["Anna".to_string()]);
        assert_eq!(openid.get("sub").unwrap(), &vec!["anna@x.se".to_string()]);
    }
}
