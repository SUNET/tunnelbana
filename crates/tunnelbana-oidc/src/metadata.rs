//! OpenID Provider metadata (discovery document, RFC 8414 / OIDC Discovery).

use serde::{Deserialize, Serialize};

/// OpenID Provider metadata. Serializes to the `.well-known/openid-configuration`
/// document and is reused (under `metadata.openid_provider`) in federation
/// entity statements.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderMetadata {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub userinfo_endpoint: String,
    pub jwks_uri: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registration_endpoint: Option<String>,

    #[serde(default)]
    pub scopes_supported: Vec<String>,
    #[serde(default)]
    pub response_types_supported: Vec<String>,
    #[serde(default)]
    pub response_modes_supported: Vec<String>,
    #[serde(default)]
    pub grant_types_supported: Vec<String>,
    #[serde(default)]
    pub subject_types_supported: Vec<String>,
    #[serde(default)]
    pub id_token_signing_alg_values_supported: Vec<String>,
    #[serde(default)]
    pub token_endpoint_auth_methods_supported: Vec<String>,
    #[serde(default)]
    pub claims_supported: Vec<String>,
    #[serde(default)]
    pub code_challenge_methods_supported: Vec<String>,
    #[serde(default)]
    pub claims_parameter_supported: bool,
    #[serde(default)]
    pub request_parameter_supported: bool,

    /// Federation / vendor extensions (e.g. `client_registration_types_supported`).
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

impl ProviderMetadata {
    /// Build sensible defaults for a code-flow OP rooted at `issuer`, with the
    /// standard endpoints under `<issuer-or-module-base>`.
    pub fn new(issuer: impl Into<String>, base: &str) -> Self {
        let base = base.trim_end_matches('/').to_string();
        let issuer = issuer.into();
        Self {
            authorization_endpoint: format!("{base}/authorization"),
            token_endpoint: format!("{base}/token"),
            userinfo_endpoint: format!("{base}/userinfo"),
            jwks_uri: format!("{base}/jwks"),
            registration_endpoint: None,
            scopes_supported: vec![
                "openid".into(),
                "profile".into(),
                "email".into(),
            ],
            response_types_supported: vec!["code".into()],
            response_modes_supported: vec!["query".into(), "fragment".into()],
            grant_types_supported: vec!["authorization_code".into()],
            subject_types_supported: vec!["public".into(), "pairwise".into()],
            id_token_signing_alg_values_supported: vec!["RS256".into(), "ES256".into()],
            token_endpoint_auth_methods_supported: vec![
                "client_secret_basic".into(),
                "client_secret_post".into(),
                "private_key_jwt".into(),
            ],
            claims_supported: vec!["sub".into(), "iss".into(), "aud".into(), "exp".into()],
            code_challenge_methods_supported: vec!["S256".into()],
            claims_parameter_supported: true,
            request_parameter_supported: true,
            issuer,
            extra: serde_json::Map::new(),
        }
    }

    /// Serialize to the discovery JSON document.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::to_value(self).unwrap_or(serde_json::Value::Null)
    }
}
