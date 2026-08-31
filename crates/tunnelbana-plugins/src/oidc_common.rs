//! Shared OpenID Connect frontend claim, request, and error handling.

use std::collections::BTreeMap;

use tunnelbana_core::attributes::AttributeMapper;
use tunnelbana_core::error::{Error, Result};
use tunnelbana_core::internal::InternalData;
use tunnelbana_oidc::metadata::ProviderMetadata;
use tunnelbana_oidc::oauth_error::{OAuthError, OAuthErrorCode};
use tunnelbana_oidc::request::AuthorizationRequest;

/// Reserved internal attribute whose OpenID mapping controls release of the
/// OP-asserted upstream authentication authority.
const AUTHENTICATING_AUTHORITY_ATTRIBUTE: &str = "authenticating_authority";
/// Claims whose canonical values are owned by the ID-token implementation and
/// which grindvakt therefore refuses to accept through `extra_claims`.
pub(crate) const RESERVED_ID_TOKEN_CLAIMS: &[&str] = &[
    "iss",
    "sub",
    "aud",
    "exp",
    "iat",
    "nbf",
    "jti",
    "nonce",
    "auth_time",
    "acr",
];

/// Reject authority-claim names that the provider reserves for canonical
/// ID-token values. Accepting one would advertise the configured name while
/// grindvakt silently omits the extra claim at issuance time.
pub(crate) fn validate_authenticating_authority_mapping(
    mapper: &AttributeMapper,
    frontend_name: &str,
) -> Result<()> {
    let Some(claim_name) = mapper
        .profile_attribute("openid", AUTHENTICATING_AUTHORITY_ATTRIBUTE)
        .and_then(|mapping| mapping.names.first())
    else {
        return Ok(());
    };

    if RESERVED_ID_TOKEN_CLAIMS.contains(&claim_name.as_str()) {
        return Err(Error::Config(format!(
            "oidc frontend {frontend_name}: {AUTHENTICATING_AUTHORITY_ATTRIBUTE} cannot map to reserved ID-token claim {claim_name}"
        )));
    }
    Ok(())
}

/// Add every canonical OpenID output name to provider discovery, including
/// the configured name of the trusted authenticating-authority claim.
pub(crate) fn advertise_mapped_claims(metadata: &mut ProviderMetadata, mapper: &AttributeMapper) {
    let claim_names = mapper
        .attributes()
        .filter_map(|(_, profiles)| profiles.get("openid"))
        .filter_map(|mapping| mapping.names.first());
    for claim_name in claim_names {
        if !metadata.claims_supported.contains(claim_name) {
            metadata.claims_supported.push(claim_name.clone());
        }
    }
}

/// Build the trusted upstream-authority claim according to the tenant's
/// OpenID attribute map.
///
/// The reserved internal attribute is release configuration only: an ordinary
/// backend attribute with the same mapping can never provide the claim value.
/// Removing its mapped output before inserting the OP-asserted value also
/// makes an unknown issuer omit the claim rather than releasing spoofed data.
pub(crate) fn authenticating_authority_claims(
    mapper: &AttributeMapper,
    external: &mut BTreeMap<String, Vec<String>>,
    issuer: Option<&str>,
) -> BTreeMap<String, serde_json::Value> {
    let mut claims = BTreeMap::new();
    // The standard name is reserved even when release is disabled or renamed,
    // so another mapped internal attribute cannot fabricate the claim.
    external.remove(AUTHENTICATING_AUTHORITY_ATTRIBUTE);
    let Some(claim_name) = mapper
        .profile_attribute("openid", AUTHENTICATING_AUTHORITY_ATTRIBUTE)
        .and_then(|mapping| mapping.names.first())
    else {
        return claims;
    };

    external.remove(claim_name);
    if let Some(issuer) = issuer {
        claims.insert(
            claim_name.clone(),
            serde_json::Value::Array(vec![serde_json::Value::String(issuer.to_owned())]),
        );
    }
    claims
}

/// Translate OIDC prompt constraints into the protocol-neutral request sent
/// through Tunnelbana's backend pipeline.
pub(crate) fn apply_prompt_constraints(req: &AuthorizationRequest, request: &mut InternalData) {
    request.force_authn = req.has_prompt("login");
    request.is_passive = req.has_prompt("none");
}

/// Render a backend failure as an OIDC authorization error.
///
/// A passive request whose backend specifically marks that UI is required is
/// returned as `login_required`, as required by OIDC Core §3.1.2.6. Other
/// authentication failures retain the existing `access_denied` behavior.
pub(crate) fn backend_authorization_error(
    req: &AuthorizationRequest,
    error: &Error,
    interaction_required: bool,
) -> OAuthError {
    let (code, description) = match error {
        Error::Authn(_) if req.has_prompt("none") && interaction_required => (
            OAuthErrorCode::LoginRequired,
            "silent authentication could not be completed",
        ),
        Error::Authn(_) => (OAuthErrorCode::AccessDenied, "authentication was denied"),
        _ => (
            OAuthErrorCode::ServerError,
            "authentication could not be completed",
        ),
    };
    OAuthError::new(code, description).with_state(req.state.clone())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authenticating_authority_uses_configured_name_and_trusted_value() {
        let mapper = AttributeMapper::from_toml(
            r#"
            [attributes.authenticating_authority]
            openid = ["upstream_idp", "inbound_alias"]
            "#,
        )
        .unwrap();
        let mut external = BTreeMap::from([
            (
                "authenticating_authority".to_string(),
                vec!["https://spoofed-standard.example".to_string()],
            ),
            (
                "upstream_idp".to_string(),
                vec!["https://spoofed-renamed.example".to_string()],
            ),
        ]);

        let claims = authenticating_authority_claims(
            &mapper,
            &mut external,
            Some("https://trusted.example"),
        );

        assert!(!external.contains_key("authenticating_authority"));
        assert!(!external.contains_key("upstream_idp"));
        assert_eq!(
            claims.get("upstream_idp"),
            Some(&serde_json::json!(["https://trusted.example"]))
        );
        let mut metadata = ProviderMetadata::new("https://op.example", "https://op.example");
        advertise_mapped_claims(&mut metadata, &mapper);
        assert!(metadata.claims_supported.contains(&"upstream_idp".into()));
        assert!(!metadata.claims_supported.contains(&"inbound_alias".into()));
    }

    #[test]
    fn authenticating_authority_is_omitted_without_issuer_or_mapping() {
        let mapped = AttributeMapper::from_toml(
            r#"
            [attributes.authenticating_authority]
            openid = ["authenticating_authority"]
            "#,
        )
        .unwrap();
        let mut external = BTreeMap::from([(
            "authenticating_authority".to_string(),
            vec!["https://spoofed.example".to_string()],
        )]);
        assert!(authenticating_authority_claims(&mapped, &mut external, None).is_empty());
        assert!(external.is_empty());

        let unmapped = AttributeMapper::default();
        let mut external = BTreeMap::from([(
            "authenticating_authority".to_string(),
            vec!["https://spoofed.example".to_string()],
        )]);
        assert!(authenticating_authority_claims(
            &unmapped,
            &mut external,
            Some("https://trusted.example")
        )
        .is_empty());
        assert!(external.is_empty());
    }

    #[test]
    fn prompt_constraints_are_exact_and_case_sensitive() {
        let req = AuthorizationRequest {
            prompt: Some("login none".into()),
            ..Default::default()
        };
        let mut internal = InternalData::default();
        apply_prompt_constraints(&req, &mut internal);
        assert!(internal.force_authn);
        assert!(internal.is_passive);

        let req = AuthorizationRequest {
            prompt: Some("Login nonetheless".into()),
            ..Default::default()
        };
        let mut internal = InternalData::default();
        apply_prompt_constraints(&req, &mut internal);
        assert!(!internal.force_authn);
        assert!(!internal.is_passive);
    }

    #[test]
    fn only_marked_passive_authentication_failure_is_login_required() {
        let req = AuthorizationRequest {
            prompt: Some("none".into()),
            state: Some("state-1".into()),
            ..Default::default()
        };
        let error = backend_authorization_error(&req, &Error::Authn("no session".into()), true);
        assert_eq!(error.code, OAuthErrorCode::LoginRequired);
        assert_eq!(error.state.as_deref(), Some("state-1"));

        let ordinary = backend_authorization_error(&req, &Error::Authn("denied".into()), false);
        assert_eq!(ordinary.code, OAuthErrorCode::AccessDenied);
    }
}
