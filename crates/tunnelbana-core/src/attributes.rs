//! Attribute mapping between protocol-specific names and the internal model.
//!
//! Driven by `attributes.toml`. Each internal attribute name maps, per profile
//! (`saml`, `openid`, `oauth`, ...), to one or more external names. Conversion
//! is bidirectional and priority-ordered: when several external names map to one
//! internal name, the first non-empty source wins on the way in.
//!
//! A profile mapping is either the legacy plain list of names or a detailed
//! table carrying an OID and a SAML FriendlyName:
//!
//! ```toml
//! [attributes.givenname]
//! saml = ["givenName"]                  # legacy form
//!
//! [attributes.mail]
//! saml = { names = ["mail", "email"], oid = "urn:oid:0.9.2342.19200300.100.1.3", friendly_name = "mail" }
//! ```

use crate::error::Result;
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};

/// One internal attribute's mapping for a single profile, normalized.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct ProfileAttribute {
    /// External names, priority-ordered; the first is the canonical outbound
    /// name for the profile.
    #[serde(default)]
    pub names: Vec<String>,
    /// Attribute OID urn (e.g. `urn:oid:0.9.2342.19200300.100.1.3`), used by
    /// the SAML `uri` attribute name format. Also matched on the way in.
    #[serde(default)]
    pub oid: Option<String>,
    /// SAML FriendlyName. Also matched on the way in.
    #[serde(default)]
    pub friendly_name: Option<String>,
}

/// The serde shape of a profile mapping: a plain name list (legacy) or the
/// detailed form.
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum ProfileMapping {
    /// `saml = ["mail", "email"]`
    Names(Vec<String>),
    /// `saml = { names = [...], oid = "...", friendly_name = "..." }`
    Detailed(ProfileAttribute),
}

impl ProfileMapping {
    fn normalize(self) -> ProfileAttribute {
        match self {
            ProfileMapping::Names(names) => ProfileAttribute {
                names,
                ..Default::default()
            },
            ProfileMapping::Detailed(detailed) => detailed,
        }
    }
}

/// The parsed attribute map (serde input shape).
#[derive(Debug, Clone, Default, Deserialize)]
pub struct AttributeMap {
    /// internal-name -> (profile -> mapping).
    #[serde(default)]
    pub attributes: BTreeMap<String, BTreeMap<String, ProfileMapping>>,
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
    /// internal-name -> (profile -> normalized mapping).
    attributes: BTreeMap<String, BTreeMap<String, ProfileAttribute>>,
    user_id_from_attrs: Vec<String>,
    user_id_to_attr: Option<String>,
}

impl AttributeMapper {
    pub fn new(map: AttributeMap) -> Self {
        let attributes = map
            .attributes
            .into_iter()
            .map(|(internal, profiles)| {
                let normalized = profiles
                    .into_iter()
                    .map(|(profile, mapping)| (profile, mapping.normalize()))
                    .collect();
                (internal, normalized)
            })
            .collect();
        Self {
            attributes,
            user_id_from_attrs: map.user_id_from_attrs,
            user_id_to_attr: map.user_id_to_attr,
        }
    }

    /// Parse an attribute map from a TOML string.
    pub fn from_toml(toml_str: &str) -> Result<Self> {
        let map: AttributeMap = toml::from_str(toml_str)
            .map_err(|e| crate::error::Error::Config(format!("attribute map: {e}")))?;
        Ok(Self::new(map))
    }

    /// Iterate over the normalized mappings: internal name -> (profile -> mapping).
    pub fn attributes(
        &self,
    ) -> impl Iterator<Item = (&String, &BTreeMap<String, ProfileAttribute>)> {
        self.attributes.iter()
    }

    /// The normalized mapping of one internal attribute for `profile`.
    pub fn profile_attribute(
        &self,
        profile: &str,
        internal_name: &str,
    ) -> Option<&ProfileAttribute> {
        self.attributes.get(internal_name)?.get(profile)
    }

    /// If set, the internal attribute the subject id is copied into.
    pub fn user_id_to_attr(&self) -> Option<&str> {
        self.user_id_to_attr.as_deref()
    }

    /// Every external key (names, OIDs, friendly names) mapped for `profile`.
    /// Useful to decide whether an inbound attribute is "known".
    pub fn external_names(&self, profile: &str) -> BTreeSet<&str> {
        let mut set = BTreeSet::new();
        for profiles in self.attributes.values() {
            let Some(mapping) = profiles.get(profile) else {
                continue;
            };
            set.extend(mapping.names.iter().map(String::as_str));
            if let Some(oid) = &mapping.oid {
                set.insert(oid.as_str());
            }
            if let Some(friendly) = &mapping.friendly_name {
                set.insert(friendly.as_str());
            }
        }
        set
    }

    /// Convert external (protocol) attributes into internal attributes.
    ///
    /// For each internal attribute, the external names listed for `profile`
    /// (plus its OID and FriendlyName, when set) are tried in order; values
    /// from every matching external name are collected (deduplicated,
    /// order-preserving).
    pub fn to_internal(
        &self,
        profile: &str,
        external: &BTreeMap<String, Vec<String>>,
    ) -> BTreeMap<String, Vec<String>> {
        let mut internal: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for (internal_name, profiles) in &self.attributes {
            let Some(mapping) = profiles.get(profile) else {
                continue;
            };
            let keys = mapping
                .names
                .iter()
                .map(String::as_str)
                .chain(mapping.oid.as_deref())
                .chain(mapping.friendly_name.as_deref());
            let mut values: Vec<String> = Vec::new();
            for ext in keys {
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
            let Some(profiles) = self.attributes.get(internal_name) else {
                continue;
            };
            let Some(mapping) = profiles.get(profile) else {
                continue;
            };
            if let Some(canonical) = mapping.names.first() {
                external.insert(canonical.clone(), values.clone());
            }
        }
        external
    }

    /// Compose a subject id from the configured `user_id_from_attrs` (joined
    /// with ':'), reading from internal attributes.
    pub fn compose_subject_id(&self, internal: &BTreeMap<String, Vec<String>>) -> Option<String> {
        if self.user_id_from_attrs.is_empty() {
            return None;
        }
        let mut parts = Vec::new();
        for name in &self.user_id_from_attrs {
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
            saml = { names = ["email", "emailAddress", "mail"], oid = "urn:oid:0.9.2342.19200300.100.1.3", friendly_name = "mail" }

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

    #[test]
    fn legacy_plain_list_still_parses() {
        let m = AttributeMapper::from_toml(
            r#"
            [attributes.givenname]
            saml = ["givenName"]
        "#,
        )
        .unwrap();
        let pa = m.profile_attribute("saml", "givenname").unwrap();
        assert_eq!(pa.names, vec!["givenName".to_string()]);
        assert!(pa.oid.is_none());
        assert!(pa.friendly_name.is_none());
    }

    #[test]
    fn oid_matches_inbound() {
        let m = mapper();
        let mut saml = BTreeMap::new();
        saml.insert(
            "urn:oid:0.9.2342.19200300.100.1.3".to_string(),
            vec!["a@x.se".to_string()],
        );
        let internal = m.to_internal("saml", &saml);
        assert_eq!(internal.get("mail").unwrap(), &vec!["a@x.se".to_string()]);
    }

    #[test]
    fn profile_attribute_exposes_oid_and_friendly_name() {
        let m = mapper();
        let pa = m.profile_attribute("saml", "mail").unwrap();
        assert_eq!(pa.names.first().map(String::as_str), Some("email"));
        assert_eq!(pa.oid.as_deref(), Some("urn:oid:0.9.2342.19200300.100.1.3"));
        assert_eq!(pa.friendly_name.as_deref(), Some("mail"));
    }

    #[test]
    fn external_names_cover_names_oid_and_friendly_name() {
        let m = mapper();
        let names = m.external_names("saml");
        assert!(names.contains("email"));
        assert!(names.contains("mail"));
        assert!(names.contains("urn:oid:0.9.2342.19200300.100.1.3"));
        assert!(names.contains("givenName"));
        assert!(!names.contains("given_name"), "openid names are separate");
    }
}
