//! Shared OpenID Connect frontend request and error handling.

use tunnelbana_core::error::Error;
use tunnelbana_core::internal::InternalData;
use tunnelbana_oidc::oauth_error::{OAuthError, OAuthErrorCode};
use tunnelbana_oidc::request::AuthorizationRequest;

/// Translate OIDC prompt constraints into the protocol-neutral request sent
/// through Tunnelbana's backend pipeline.
pub(crate) fn apply_prompt_constraints(req: &AuthorizationRequest, request: &mut InternalData) {
    request.force_authn = req.has_prompt("login");
    request.is_passive = req.has_prompt("none");
}

/// Render a backend failure as an OIDC authorization error.
///
/// A passive request that reaches an authentication failure could not be
/// completed without authentication UI, so OIDC Core §3.1.2.6 calls for
/// `login_required`. Other authentication failures retain the existing
/// `access_denied` behavior.
pub(crate) fn backend_authorization_error(req: &AuthorizationRequest, error: &Error) -> OAuthError {
    let (code, description) = match error {
        Error::Authn(_) if req.has_prompt("none") => (
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
    fn passive_authentication_failure_is_login_required_with_state() {
        let req = AuthorizationRequest {
            prompt: Some("none".into()),
            state: Some("state-1".into()),
            ..Default::default()
        };
        let error = backend_authorization_error(&req, &Error::Authn("no session".into()));
        assert_eq!(error.code, OAuthErrorCode::LoginRequired);
        assert_eq!(error.state.as_deref(), Some("state-1"));

        let ordinary = backend_authorization_error(
            &AuthorizationRequest::default(),
            &Error::Authn("denied".into()),
        );
        assert_eq!(ordinary.code, OAuthErrorCode::AccessDenied);
    }
}
