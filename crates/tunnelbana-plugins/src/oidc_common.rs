//! Shared OpenID Connect claim, request, validation, and error handling.

use std::collections::BTreeMap;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use jose_rs::JwsAlgorithm;
use sha2::{Digest, Sha256};
use tunnelbana_core::attributes::AttributeMapper;
use tunnelbana_core::context::Context;
use tunnelbana_core::error::{Error, Result};
use tunnelbana_core::http::Response;
use tunnelbana_core::internal::InternalData;
use tunnelbana_oidc::client::Client;
use tunnelbana_oidc::metadata::ProviderMetadata;
use tunnelbana_oidc::oauth_error::{OAuthError, OAuthErrorCode};
use tunnelbana_oidc::provider::Provider;
use tunnelbana_oidc::request::AuthorizationRequest;

/// Compact registration binding stored inside the authenticated flow cookie.
const AUTHORIZATION_CLIENT: &str = "authorization_client_v1";

/// Hash all registration fields without storing client secrets or JWKs in the
/// flow cookie. Separate flattened JWK extensions and canonicalize object order
/// so neither overlapping field names nor map iteration affect the binding.
fn client_fingerprint(client: &Client) -> Result<String> {
    let mut registration = client.clone();
    let extensions = registration.jwks.as_mut().map(|jwks| {
        jwks.keys
            .iter_mut()
            .map(|key| std::mem::take(&mut key.extra))
            .collect::<Vec<_>>()
    });
    let mut value = serde_json::to_value((registration, extensions))?;
    value.sort_all_objects();
    Ok(URL_SAFE_NO_PAD.encode(Sha256::digest(serde_json::to_vec(&value)?)))
}

/// Bind response-pipeline output to the registration validated before login.
pub(crate) fn bind_authorization_client(
    ctx: &mut Context,
    frontend: &str,
    client: &Client,
) -> Result<()> {
    ctx.state.set_value(
        frontend,
        AUTHORIZATION_CLIENT,
        serde_json::Value::String(client_fingerprint(client)?),
    );
    Ok(())
}

/// Resolve the established subject only after matching the issuance registration
/// to the login snapshot. Keep the historical subject_id/composition precedence;
/// the configured response pipeline owns pairwise derivation and sector policy.
/// Every login needs a binding: the current subject type cannot establish the
/// policy used by older code when it created an unbound login cookie.
pub(crate) fn resolve_authorization_subject(
    ctx: &Context,
    frontend: &str,
    client: &Client,
    response: &InternalData,
    mapper: &AttributeMapper,
) -> std::result::Result<String, OAuthError> {
    match ctx.state.get_value(frontend, AUTHORIZATION_CLIENT) {
        Some(saved) => {
            let current = client_fingerprint(client).map_err(|_| {
                OAuthError::new(
                    OAuthErrorCode::ServerError,
                    "cannot compare client registration",
                )
            })?;
            if saved.as_str() != Some(current.as_str()) {
                return Err(OAuthError::new(
                    OAuthErrorCode::UnauthorizedClient,
                    "client registration changed during login; restart authorization",
                ));
            }
        }
        None => {
            return Err(OAuthError::new(
                OAuthErrorCode::UnauthorizedClient,
                "login has no registration binding; restart authorization",
            ));
        }
    }
    response
        .subject_id
        .clone()
        .or_else(|| mapper.compose_subject_id(&response.attributes))
        .ok_or_else(|| {
            OAuthError::new(
                OAuthErrorCode::AccessDenied,
                "no subject identifier available",
            )
        })
}

/// Redirect an authorization error only while the stored request still passes
/// current registration validation. Login state alone does not authorize a
/// revoked redirect URI; return the error locally when revalidation fails.
/// Like issuance, this is a snapshot check rather than a lock on later writes.
pub(crate) async fn authorization_error_response(
    provider: &Provider,
    req: &AuthorizationRequest,
    error: OAuthError,
) -> Response {
    if provider.validate_authorization_request(req).await.is_ok() {
        error.to_redirect(&req.redirect_uri, req.use_fragment())
    } else {
        error.to_response()
    }
}

/// OIDC's default registered ID-token signing algorithm.
pub(crate) fn default_id_token_algorithm() -> JwsAlgorithm {
    JwsAlgorithm::RS256
}

/// Upstream JWKS contain public keys, so they cannot establish HMAC trust.
/// Also require a crypto implementation; a recognized JOSE name alone does not
/// guarantee verification support. This includes implemented PQC algorithms.
pub(crate) fn validate_id_token_algorithm(algorithm: JwsAlgorithm) -> Result<()> {
    if matches!(
        algorithm,
        JwsAlgorithm::HS256 | JwsAlgorithm::HS384 | JwsAlgorithm::HS512
    ) {
        return Err(Error::Config(
            "id_token_signed_response_alg must be an asymmetric signing algorithm".into(),
        ));
    }
    algorithm.to_crypto().map_err(|_| {
        Error::Config(format!(
            "id_token_signed_response_alg {algorithm} has no supported crypto implementation"
        ))
    })?;
    Ok(())
}

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

    /// Fingerprints cover registration policy and key fields while treating
    /// harmless JSON object ordering as equivalent across federation refreshes.
    #[test]
    fn registration_fingerprint_is_complete_and_canonical() {
        let mut client: Client = serde_json::from_value(serde_json::json!({
            "client_id": "rp", "subject_type": "pairwise",
            "jwks": {"keys": [{"kty": "EC", "kid": "original", "x-extra": {"a": 1, "b": 2}}]}
        }))
        .unwrap();
        let original = client_fingerprint(&client).unwrap();
        let key = &mut client.jwks.as_mut().unwrap().keys[0];
        // preserve_order is enabled in Tunnelbana: equivalent incoming objects
        // must hash identically even when their insertion order differs.
        key.extra.insert(
            "x-extra".into(),
            serde_json::from_str(r#"{"b":2,"a":1}"#).unwrap(),
        );
        assert_eq!(client_fingerprint(&client).unwrap(), original);
        client.client_name = Some("updated name".into());
        assert_ne!(client_fingerprint(&client).unwrap(), original);
        client.client_name = None;
        client.subject_type = "public".into();
        assert_ne!(client_fingerprint(&client).unwrap(), original);
    }

    /// Programmatic flattened JWK extensions must not hide a changed dedicated
    /// field when comparing the login registration with the issuance snapshot.
    #[test]
    fn registration_fingerprint_keeps_jwk_extensions_separate() {
        let mut client: Client = serde_json::from_value(serde_json::json!({
            "client_id": "rp", "jwks": {"keys": [{"kty": "EC", "kid": "original"}]}
        }))
        .unwrap();
        client.jwks.as_mut().unwrap().keys[0]
            .extra
            .insert("kid".into(), serde_json::json!("extension"));
        let original = client_fingerprint(&client).unwrap();
        // The extension is unchanged; the independently accessible field is not.
        client.jwks.as_mut().unwrap().keys[0].kid = Some("updated".into());
        assert_ne!(client_fingerprint(&client).unwrap(), original);
    }

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
