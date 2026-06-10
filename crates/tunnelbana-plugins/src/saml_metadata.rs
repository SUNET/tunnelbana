//! Shared SAML metadata-publishing config: `[*.config.organization]` and
//! `[[*.config.contact_person]]` blocks used by both the SAML2 backend (SP
//! metadata) and frontend (IdP metadata). Mirrors SATOSA's
//! `organization`/`contact_person` config keys; required for SWAMID
//! registration of either role.

use std::str::FromStr;

use serde::Deserialize;

use gamlastan::metadata::types::contact::{ContactPerson, ContactType};
use gamlastan::metadata::types::organization::Organization;

use tunnelbana_core::error::{Error, Result};

/// `[*.config.organization]` — published as `<md:Organization>`.
#[derive(Debug, Clone, Deserialize)]
pub struct OrganizationConfig {
    pub name: String,
    pub display_name: String,
    pub url: String,
    /// xml:lang for the localized strings.
    #[serde(default = "default_lang")]
    pub lang: String,
}

fn default_lang() -> String {
    "en".to_string()
}

impl OrganizationConfig {
    pub fn to_organization(&self) -> Organization {
        Organization::simple(&self.lang, &self.name, &self.display_name, &self.url)
    }
}

/// `[[*.config.contact_person]]` — published as `<md:ContactPerson>`.
#[derive(Debug, Clone, Deserialize)]
pub struct ContactPersonConfig {
    /// `technical`, `support`, `administrative`, `billing` or `other`.
    pub contact_type: String,
    #[serde(default)]
    pub email_address: Option<String>,
    #[serde(default)]
    pub given_name: Option<String>,
    #[serde(default)]
    pub sur_name: Option<String>,
    #[serde(default)]
    pub company: Option<String>,
}

impl ContactPersonConfig {
    pub fn to_contact_person(&self) -> Result<ContactPerson> {
        let contact_type = ContactType::from_str(&self.contact_type).map_err(|_| {
            Error::Config(format!(
                "unknown contact_person.contact_type: {} (expected technical, support, \
                 administrative, billing or other)",
                self.contact_type
            ))
        })?;
        Ok(ContactPerson {
            contact_type,
            extensions: None,
            company: self.company.clone(),
            given_name: self.given_name.clone(),
            sur_name: self.sur_name.clone(),
            email_addresses: self.email_address.iter().cloned().collect(),
            telephone_numbers: vec![],
        })
    }
}

/// Convert the configured contact persons, surfacing the first config error.
pub fn contact_persons(configs: &[ContactPersonConfig]) -> Result<Vec<ContactPerson>> {
    configs.iter().map(|c| c.to_contact_person()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn organization_converts_with_default_lang() {
        let cfg: OrganizationConfig = serde_json::from_value(serde_json::json!({
            "name": "SUNET",
            "display_name": "Vetenskapsrådet / SUNET",
            "url": "https://sunet.se"
        }))
        .unwrap();
        assert_eq!(cfg.lang, "en");
        let org = cfg.to_organization();
        assert_eq!(org.organization_names[0].value, "SUNET");
        assert_eq!(
            org.organization_display_names[0].value,
            "Vetenskapsrådet / SUNET"
        );
        assert_eq!(org.organization_urls[0].value, "https://sunet.se");
    }

    #[test]
    fn contact_person_converts() {
        let cfg: ContactPersonConfig = serde_json::from_value(serde_json::json!({
            "contact_type": "technical",
            "email_address": "noc@sunet.se",
            "given_name": "Ops"
        }))
        .unwrap();
        let cp = cfg.to_contact_person().unwrap();
        assert_eq!(cp.contact_type, ContactType::Technical);
        assert_eq!(cp.email_addresses, vec!["noc@sunet.se".to_string()]);
        assert_eq!(cp.given_name.as_deref(), Some("Ops"));
    }

    #[test]
    fn unknown_contact_type_is_a_config_error() {
        let cfg: ContactPersonConfig = serde_json::from_value(serde_json::json!({
            "contact_type": "security"
        }))
        .unwrap();
        assert!(cfg.to_contact_person().is_err());
    }
}
