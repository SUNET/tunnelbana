//! Protocol-agnostic internal data model.
//!
//! Frontends translate inbound protocol requests into [`InternalData`] and
//! translate [`InternalData`] responses back out; backends do the inverse.
//! Neither side knows the other's protocol — they only exchange this type.
//! Mirrors SATOSA's `satosa.internal`.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Information about how/where the user authenticated.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AuthenticationInformation {
    /// Authentication context class reference (e.g. a SAML AuthnContextClassRef
    /// or an OIDC `acr`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_class_ref: Option<String>,
    /// When the authentication occurred (RFC 3339 timestamp).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<String>,
    /// The upstream IdP/OP issuer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
}

/// How the subject identifier should be treated downstream.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SubjectType {
    /// Stable across sessions.
    #[default]
    Persistent,
    /// New per session.
    Transient,
    /// OIDC public subject.
    Public,
    /// OIDC pairwise subject.
    Pairwise,
}

/// The protocol-agnostic carrier of an authentication request/response.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct InternalData {
    /// Authentication info (populated on the response path).
    #[serde(default)]
    pub auth_info: AuthenticationInformation,
    /// The entity that requested authentication (SP entityID or OIDC client_id).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requester: Option<String>,
    /// Optional localized display names for the requester.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub requester_name: Vec<String>,
    /// The stable subject identifier of the authenticated user.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject_id: Option<String>,
    /// How the subject id should be treated.
    #[serde(default)]
    pub subject_type: SubjectType,
    /// Internal attribute map: internal-name -> list of values.
    #[serde(default)]
    pub attributes: BTreeMap<String, Vec<String>>,
}

impl InternalData {
    /// Construct an empty request carrying just the requester.
    pub fn request(requester: impl Into<String>) -> Self {
        Self {
            requester: Some(requester.into()),
            ..Default::default()
        }
    }

    /// Get the first value of an attribute, if any.
    pub fn attr_first(&self, name: &str) -> Option<&str> {
        self.attributes
            .get(name)
            .and_then(|v| v.first())
            .map(|s| s.as_str())
    }

    /// Set an attribute to a single value.
    pub fn set_attr(&mut self, name: impl Into<String>, value: impl Into<String>) {
        self.attributes.insert(name.into(), vec![value.into()]);
    }
}
