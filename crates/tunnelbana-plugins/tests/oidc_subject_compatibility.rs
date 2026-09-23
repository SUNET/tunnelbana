//! Existing public and caller-managed pairwise subjects across the Grindvakt
//! upgrade, using both OP frontends and their real authorization/token paths.

use std::sync::Arc;
use tunnelbana_core::attributes::AttributeMapper;
use tunnelbana_core::context::Context;
use tunnelbana_core::http::{HttpRequestData, Response};
use tunnelbana_core::internal::InternalData;
use tunnelbana_core::plugin::{BuildContext, Frontend, FrontendAction, NullHttpClient};
use tunnelbana_core::state::{State, StateSealer};

const ISSUER: &str = "https://proxy.example.com/OP";
const REDIRECT: &str = "https://rp.example.com/cb";

/// Reuse one signing key across frontend rebuilds, as an existing deployment does.
fn signing_jwk() -> serde_json::Value {
    let mut key = jose_rs::jwk::generate_ec("P-256").unwrap();
    key.alg = Some("ES256".into());
    key.kid = Some("existing-key".into());
    serde_json::to_value(key).unwrap()
}

/// Build either OP using the same old-style configuration and subject pipeline.
fn frontend(federation: bool, key: &serde_json::Value, kind: &str) -> Box<dyn Frontend> {
    let mapper = AttributeMapper::from_toml(
        r#"
        user_id_from_attrs = ["existing-id"]
        [attributes.existing-id]
        openid = ["sub"]
        [attributes.pairwise-id]
        openid = ["pairwise_id"]
        "#,
    )
    .unwrap();
    let mut config = serde_json::json!({
        "signing_jwk": key,
        "signing_algorithm": "ES256",
        "clients": [{
            "client_id": "rp", "client_secret": "existing-secret",
            "redirect_uris": [REDIRECT],
            "response_types": ["code", "id_token", "code id_token token"],
            "grant_types": ["authorization_code", "refresh_token"],
            "token_endpoint_auth_method": "client_secret_post",
            "subject_type": kind
        }]
    });
    if federation {
        config["federation"] = serde_json::json!({
            "signing_jwk": key,
            "signing_algorithm": "ES256",
            "authority_hints": ["https://ta.example.com"],
            "trust_anchor": [{"entity_id": "https://ta.example.com", "keys": [key]}]
        });
    }
    let bx = BuildContext {
        name: "OP".into(),
        base_url: "https://proxy.example.com".into(),
        config,
        attribute_mapper: Arc::new(mapper),
        http_client: Arc::new(NullHttpClient),
        secret: "existing-secret".into(),
        previous_secrets: Vec::new(),
    };
    if federation {
        tunnelbana_plugins::federation_frontend::FederationFrontend::build(&bx).unwrap()
    } else {
        tunnelbana_plugins::oidc_frontend::OidcFrontend::build(&bx).unwrap()
    }
}

/// Drive initial validation and carry its registration binding across the same
/// encrypted-cookie boundary used by interactive logins.
async fn start(frontend: &dyn Frontend, response_type: &str) -> Context {
    let mut ctx = Context::new(HttpRequestData::default(), State::new());
    ctx.request.query_pairs = [
        ("client_id", "rp"),
        ("redirect_uri", REDIRECT),
        ("response_type", response_type),
        ("scope", "openid"),
        ("nonce", "existing-nonce"),
        ("state", "existing-state"),
    ]
    .into_iter()
    .map(|(k, v)| (k.into(), v.into()))
    .collect();
    // Code and hybrid responses seal otherwise identical payloads; distinct
    // nonces keep this fixture from deliberately replaying its own used code.
    ctx.request
        .query_pairs
        .iter_mut()
        .find(|(key, _)| key == "nonce")
        .unwrap()
        .1 = format!("existing-nonce-{response_type}");
    assert!(matches!(
        frontend
            .handle_endpoint(&mut ctx, "authorization")
            .await
            .unwrap(),
        FrontendAction::StartAuth { .. }
    ));
    let sealer = StateSealer::new("existing-cookie-secret", "state");
    let sealed = sealer.seal(&ctx.state).unwrap();
    let cookie = sealed.split(';').next().unwrap().split_once('=').unwrap().1;
    ctx.state = sealer.unseal(Some(cookie));
    ctx
}

/// Preserve the existing final subject and the attribute-composition fallback.
fn identity(explicit: bool) -> InternalData {
    let mut response = InternalData::default();
    if explicit {
        response.subject_id = Some("existing-final-subject".into());
    }
    response.attributes.insert(
        "existing-id".into(),
        vec!["existing-composed-subject".into()],
    );
    // A pairwise attribute must not silently override either historical source.
    response.attributes.insert(
        "pairwise-id".into(),
        vec!["different-pairwise-attribute".into()],
    );
    response
}

/// Extract an authorization parameter from either response mode.
fn parameter(response: &Response, name: &str) -> Option<String> {
    let location = &response
        .headers
        .iter()
        .find(|(k, _)| k == "location")
        .unwrap()
        .1;
    let (_, encoded) = location.split_once(['?', '#'])?;
    form_urlencoded::parse(encoded.as_bytes())
        .find(|(k, _)| k == name)
        .map(|(_, v)| v.into_owned())
}

/// Send a real client-authenticated code or refresh grant through the frontend.
async fn token(frontend: &dyn Frontend, grant: &str, token: &str) -> serde_json::Value {
    let mut ctx = Context::new(HttpRequestData::default(), State::new());
    let field = if grant == "authorization_code" {
        "code"
    } else {
        "refresh_token"
    };
    ctx.request.form_pairs = [
        ("client_id", "rp"),
        ("client_secret", "existing-secret"),
        ("grant_type", grant),
        (field, token),
        ("redirect_uri", REDIRECT),
    ]
    .into_iter()
    .map(|(k, v)| (k.into(), v.into()))
    .collect();
    let FrontendAction::Respond(response) =
        frontend.handle_endpoint(&mut ctx, "token").await.unwrap()
    else {
        panic!("token endpoint must respond")
    };
    assert_eq!(
        response.status,
        200,
        "{}",
        String::from_utf8_lossy(&response.body)
    );
    serde_json::from_slice(&response.body).unwrap()
}

/// Check subjects in signed ID tokens and the UserInfo response.
async fn assert_tokens(
    frontend: &dyn Frontend,
    key: &serde_json::Value,
    tokens: &serde_json::Value,
    expected: &str,
) {
    let key: jose_rs::jwk::Jwk = serde_json::from_value(key.clone()).unwrap();
    let keys = jose_rs::jwk::JwkSet {
        keys: vec![key.to_public_jwk()],
    };
    let validation = jose_rs::jwt::Validation::new()
        .with_issuer(ISSUER)
        .with_audience("rp");
    let claims =
        jose_rs::jwt::decode_with_jwkset(&keys, tokens["id_token"].as_str().unwrap(), &validation)
            .unwrap();
    assert_eq!(claims.sub.as_deref(), Some(expected));
    if let Some(access) = tokens["access_token"].as_str() {
        let mut ctx = Context::new(HttpRequestData::default(), State::new());
        ctx.request
            .headers
            .insert("authorization".into(), format!("Bearer {access}"));
        let FrontendAction::Respond(response) = frontend
            .handle_endpoint(&mut ctx, "userinfo")
            .await
            .unwrap()
        else {
            panic!("UserInfo must respond")
        };
        assert_eq!(response.status, 200);
        let userinfo: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
        assert_eq!(userinfo["sub"], expected);
    }
}

/// Both frontends retain public and pairwise account identifiers, including the
/// configured fallback, through every authorization flow and refresh rotation.
#[tokio::test]
async fn existing_subjects_survive_both_frontends_and_all_flows() {
    let key = signing_jwk();
    for federation in [false, true] {
        for kind in ["public", "pairwise"] {
            let frontend = frontend(federation, &key, kind);
            // Advertising pairwise is backed by the same resolver path used
            // below for both explicit and attribute-composed final subjects.
            let mut discovery_ctx = Context::new(HttpRequestData::default(), State::new());
            let FrontendAction::Respond(discovery) = frontend
                .handle_endpoint(&mut discovery_ctx, "discovery")
                .await
                .unwrap()
            else {
                panic!("discovery must respond")
            };
            let metadata: serde_json::Value = serde_json::from_slice(&discovery.body).unwrap();
            assert_eq!(
                metadata["subject_types_supported"],
                serde_json::json!(["public", "pairwise"])
            );
            for explicit in [false, true] {
                let expected = if explicit {
                    "existing-final-subject"
                } else {
                    "existing-composed-subject"
                };
                for response_type in ["code", "id_token", "code id_token token"] {
                    let mut ctx = start(frontend.as_ref(), response_type).await;
                    let response = frontend
                        .handle_authn_response(&mut ctx, identity(explicit))
                        .await
                        .unwrap();
                    assert_eq!(
                        parameter(&response, "state").as_deref(),
                        Some("existing-state")
                    );
                    if let Some(id_token) = parameter(&response, "id_token") {
                        let tokens = serde_json::json!({"id_token": id_token, "access_token": parameter(&response, "access_token")});
                        assert_tokens(frontend.as_ref(), &key, &tokens, expected).await;
                    }
                    if let Some(code) = parameter(&response, "code") {
                        let tokens = token(frontend.as_ref(), "authorization_code", &code).await;
                        assert_tokens(frontend.as_ref(), &key, &tokens, expected).await;
                        // Rebuild the frontend to represent a deploy/restart:
                        // existing sealing keys and refresh payloads must work.
                        let restarted = self::frontend(federation, &key, kind);
                        let refreshed = token(
                            restarted.as_ref(),
                            "refresh_token",
                            tokens["refresh_token"].as_str().unwrap(),
                        )
                        .await;
                        assert_tokens(restarted.as_ref(), &key, &refreshed, expected).await;
                    }
                }
            }
        }
    }
}

/// A registration change across login must never reinterpret pipeline output
/// under a different subject policy; errors preserve the original state.
#[tokio::test]
async fn registration_changes_across_login_are_rejected() {
    let key = signing_jwk();
    for federation in [false, true] {
        for initial in ["public", "pairwise"] {
            let old = frontend(federation, &key, initial);
            let mut ctx = start(old.as_ref(), "code id_token token").await;
            let changed = if initial == "public" {
                "pairwise"
            } else {
                "public"
            };
            let new = frontend(federation, &key, changed);
            // Same frontend name, keys and client ID, but a different policy.
            let response = new
                .handle_authn_response(&mut ctx, identity(true))
                .await
                .unwrap();
            assert_eq!(
                parameter(&response, "error").as_deref(),
                Some("unauthorized_client")
            );
            assert_eq!(
                parameter(&response, "state").as_deref(),
                Some("existing-state")
            );
            assert!(parameter(&response, "code").is_none());
            assert!(parameter(&response, "id_token").is_none());
        }
    }
}

/// Pre-upgrade public cookies remain usable; an unbound pairwise login must
/// restart because no validated registration snapshot exists for comparison.
#[tokio::test]
async fn pre_upgrade_cookies_have_an_explicit_compatibility_boundary() {
    let key = signing_jwk();
    for federation in [false, true] {
        for kind in ["public", "pairwise"] {
            let frontend = frontend(federation, &key, kind);
            let mut ctx = start(frontend.as_ref(), "code").await;
            let request = ctx.state.get_value("OP", "authz_request").unwrap().clone();
            // Old cookies contain the request but no registration fingerprint.
            ctx.state.clear_namespace("OP");
            ctx.state.set_value("OP", "authz_request", request);
            let response = frontend
                .handle_authn_response(&mut ctx, identity(true))
                .await
                .unwrap();
            if kind == "public" {
                assert!(parameter(&response, "code").is_some());
            } else {
                assert_eq!(
                    parameter(&response, "error").as_deref(),
                    Some("unauthorized_client")
                );
            }
        }
    }
}
