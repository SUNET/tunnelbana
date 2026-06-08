//! End-to-end OP engine tests: authorization code + PKCE flow, id_token
//! verification, userinfo, and `private_key_jwt` client authentication.

use std::collections::BTreeMap;
use std::sync::Arc;

use tunnelbana_core::keys::{signing_key_from_jwk_json, SigningKey};
use tunnelbana_oidc::client::{
    Client, InMemoryClientStore, AUTH_NONE, AUTH_PRIVATE_KEY_JWT,
};
use tunnelbana_oidc::metadata::ProviderMetadata;
use tunnelbana_oidc::pkce;
use tunnelbana_oidc::provider::{Provider, TokenLifetimes, CLIENT_ASSERTION_TYPE};
use tunnelbana_oidc::request::AuthorizationRequest;
use tunnelbana_oidc::tokens::TokenCodec;

fn ec_signing_key(kid: &str) -> SigningKey {
    let mut jwk = jose_rs::jwk::generate_ec("P-256").unwrap();
    jwk.alg = Some("ES256".into());
    signing_key_from_jwk_json(&jwk.to_json().unwrap(), Some("ES256"), Some(kid)).unwrap()
}

fn provider_with(clients: InMemoryClientStore) -> Provider {
    let metadata = ProviderMetadata::new("https://op.example.com", "https://op.example.com");
    Provider::new(
        metadata,
        ec_signing_key("op-key-1"),
        Arc::new(clients),
        TokenCodec::new("op-secret"),
        TokenLifetimes::default(),
    )
}

fn map(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
    pairs
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

fn extract_param(redirect: &str, key: &str) -> Option<String> {
    let (_, query) = redirect.split_once(['?', '#'])?;
    for pair in query.split('&') {
        if let Some((k, v)) = pair.split_once('=') {
            if k == key {
                return Some(
                    percent_encoding::percent_decode_str(v)
                        .decode_utf8_lossy()
                        .into_owned(),
                );
            }
        }
    }
    None
}

#[tokio::test]
async fn authorization_code_pkce_flow() {
    // Public client using PKCE (auth method "none").
    let client = Client {
        client_id: "rp-1".into(),
        client_secret: None,
        redirect_uris: vec!["https://rp.example.com/cb".into()],
        response_types: vec!["code".into()],
        grant_types: vec!["authorization_code".into()],
        token_endpoint_auth_method: AUTH_NONE.into(),
        jwks: None,
        scope: None,
        subject_type: "public".into(),
        client_name: None,
    };
    let store = InMemoryClientStore::with_clients(vec![client]);
    let op = provider_with(store);

    let verifier = "verifier-0123456789-0123456789-0123456789";
    let challenge = pkce::s256_challenge(verifier);

    let req = AuthorizationRequest::from_params(&map(&[
        ("client_id", "rp-1"),
        ("response_type", "code"),
        ("redirect_uri", "https://rp.example.com/cb"),
        ("scope", "openid email"),
        ("state", "state-xyz"),
        ("nonce", "nonce-abc"),
        ("code_challenge", &challenge),
        ("code_challenge_method", "S256"),
    ]))
    .unwrap();

    // Validate against the client.
    op.validate_authorization_request(&req).await.unwrap();

    // User authenticated; release claims.
    let mut claims: BTreeMap<String, Vec<String>> = BTreeMap::new();
    claims.insert("email".into(), vec!["anna@example.com".into()]);
    let redirect = op
        .authorization_redirect(&req, "subject-123", &claims, Some("urn:acr:pwd".into()))
        .unwrap();
    assert_eq!(redirect.status, 302);
    let location = redirect
        .headers
        .iter()
        .find(|(k, _)| k == "location")
        .map(|(_, v)| v.clone())
        .unwrap();
    assert!(location.starts_with("https://rp.example.com/cb?"));
    assert_eq!(extract_param(&location, "state").as_deref(), Some("state-xyz"));
    let code = extract_param(&location, "code").unwrap();

    // Token exchange with PKCE verifier.
    let token_resp = op
        .handle_token_request(
            &map(&[
                ("grant_type", "authorization_code"),
                ("code", &code),
                ("redirect_uri", "https://rp.example.com/cb"),
                ("client_id", "rp-1"),
                ("code_verifier", verifier),
            ]),
            None,
            "https://op.example.com/token",
        )
        .await
        .expect("token exchange");

    assert_eq!(token_resp.token_type, "Bearer");
    let id_token = token_resp.id_token.clone().unwrap();

    // Verify the id_token with the OP's published JWKS.
    let jwks = op.jwks_document();
    let validation = jose_rs::jwt::Validation::new()
        .with_issuer("https://op.example.com")
        .with_audience("rp-1");
    let id_claims = jose_rs::jwt::decode_with_jwkset(&jwks, &id_token, &validation).unwrap();
    assert_eq!(id_claims.sub.as_deref(), Some("subject-123"));
    assert_eq!(
        id_claims.extra.get("nonce").and_then(|v| v.as_str()),
        Some("nonce-abc")
    );
    assert_eq!(
        id_claims.extra.get("email").and_then(|v| v.as_str()),
        Some("anna@example.com")
    );
    assert_eq!(
        id_claims.extra.get("acr").and_then(|v| v.as_str()),
        Some("urn:acr:pwd")
    );

    // UserInfo with the access token.
    let userinfo = op.userinfo(&token_resp.access_token).await.unwrap();
    assert_eq!(userinfo["sub"], "subject-123");
    assert_eq!(userinfo["email"], "anna@example.com");
}

#[tokio::test]
async fn pkce_mismatch_rejected() {
    let client = Client {
        client_id: "rp-1".into(),
        client_secret: None,
        redirect_uris: vec!["https://rp.example.com/cb".into()],
        response_types: vec!["code".into()],
        grant_types: vec!["authorization_code".into()],
        token_endpoint_auth_method: AUTH_NONE.into(),
        jwks: None,
        scope: None,
        subject_type: "public".into(),
        client_name: None,
    };
    let op = provider_with(InMemoryClientStore::with_clients(vec![client]));

    let verifier = "verifier-0123456789-0123456789-0123456789";
    let challenge = pkce::s256_challenge(verifier);
    let req = AuthorizationRequest::from_params(&map(&[
        ("client_id", "rp-1"),
        ("response_type", "code"),
        ("redirect_uri", "https://rp.example.com/cb"),
        ("scope", "openid"),
        ("code_challenge", &challenge),
        ("code_challenge_method", "S256"),
    ]))
    .unwrap();
    let redirect = op
        .authorization_redirect(&req, "sub", &BTreeMap::new(), None)
        .unwrap();
    let location = &redirect.headers.iter().find(|(k, _)| k == "location").unwrap().1;
    let code = extract_param(location, "code").unwrap();

    let err = op
        .handle_token_request(
            &map(&[
                ("grant_type", "authorization_code"),
                ("code", &code),
                ("client_id", "rp-1"),
                ("code_verifier", "the-wrong-verifier-the-wrong-verifier"),
            ]),
            None,
            "https://op.example.com/token",
        )
        .await;
    assert!(err.is_err(), "wrong PKCE verifier must be rejected");
}

#[tokio::test]
async fn private_key_jwt_client_auth() {
    // The client authenticates with private_key_jwt; the OP holds its public JWKS.
    let client_key = ec_signing_key("rp-key-1");
    let jwks = client_key.to_public_jwks();

    let client = Client {
        client_id: "rp-fed".into(),
        client_secret: None,
        redirect_uris: vec!["https://rp.example.com/cb".into()],
        response_types: vec!["code".into()],
        grant_types: vec!["authorization_code".into()],
        token_endpoint_auth_method: AUTH_PRIVATE_KEY_JWT.into(),
        jwks: Some(jwks),
        scope: None,
        subject_type: "public".into(),
        client_name: None,
    };
    let op = provider_with(InMemoryClientStore::with_clients(vec![client]));

    // Issue a code (no PKCE).
    let req = AuthorizationRequest::from_params(&map(&[
        ("client_id", "rp-fed"),
        ("response_type", "code"),
        ("redirect_uri", "https://rp.example.com/cb"),
        ("scope", "openid"),
    ]))
    .unwrap();
    let redirect = op
        .authorization_redirect(&req, "sub-fed", &BTreeMap::new(), None)
        .unwrap();
    let location = &redirect.headers.iter().find(|(k, _)| k == "location").unwrap().1;
    let code = extract_param(location, "code").unwrap();

    // Build a client assertion (RFC 7523) addressed to the token endpoint.
    let token_url = "https://op.example.com/token";
    let assertion =
        tunnelbana_oidc::rp::build_client_assertion(&client_key, "rp-fed", token_url).unwrap();

    let token_resp = op
        .handle_token_request(
            &map(&[
                ("grant_type", "authorization_code"),
                ("code", &code),
                ("redirect_uri", "https://rp.example.com/cb"),
                ("client_assertion_type", CLIENT_ASSERTION_TYPE),
                ("client_assertion", &assertion),
            ]),
            None,
            token_url,
        )
        .await
        .expect("private_key_jwt token exchange");
    assert!(token_resp.id_token.is_some());

    // A wrong audience must be rejected.
    let bad_assertion = tunnelbana_oidc::rp::build_client_assertion(
        &client_key,
        "rp-fed",
        "https://evil.example.com/token",
    )
    .unwrap();
    let err = op
        .authenticate_client(
            &map(&[
                ("client_assertion_type", CLIENT_ASSERTION_TYPE),
                ("client_assertion", &bad_assertion),
            ]),
            None,
            token_url,
        )
        .await;
    assert!(err.is_err(), "wrong audience must be rejected");
}
