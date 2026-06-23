//! DPoP (RFC 9449) end-to-end through the OIDC OP frontend: a DPoP-bound
//! `client_credentials` token, the discovery advertisement, replay rejection,
//! and the `use_dpop_nonce` challenge.

use std::collections::BTreeMap;
use std::sync::Arc;

use tunnelbana_core::attributes::AttributeMapper;
use tunnelbana_core::http::{HttpRequestData, Response};
use tunnelbana_core::plugin::Backend;
use tunnelbana_core::plugin::{BuildContext, Frontend, NullHttpClient};
use tunnelbana_core::proxy::Proxy;
use tunnelbana_core::state::StateSealer;

const ISSUER: &str = "https://proxy.example.com/OIDC";
const TOKEN_URL: &str = "https://proxy.example.com/OIDC/token";

fn mapper() -> Arc<AttributeMapper> {
    Arc::new(AttributeMapper::from_toml("").unwrap())
}

fn build_frontend(require_nonce: bool) -> Box<dyn Frontend> {
    let mut jwk = jose_rs::jwk::generate_ec("P-256").unwrap();
    jwk.alg = Some("ES256".into());
    let signing_jwk: serde_json::Value = serde_json::from_str(&jwk.to_json().unwrap()).unwrap();

    let config = serde_json::json!({
        "signing_jwk": signing_jwk,
        "signing_algorithm": "ES256",
        "signing_key_id": "k1",
        "dpop": { "enabled": true, "require_nonce": require_nonce },
        "clients": [{
            "client_id": "svc-1",
            "client_secret": "svc-secret",
            "grant_types": ["client_credentials"],
            "token_endpoint_auth_method": "client_secret_post",
            "scope": "read write"
        }]
    });

    let bx = BuildContext {
        name: "OIDC".to_string(),
        base_url: "https://proxy.example.com".to_string(),
        config,
        attribute_mapper: mapper(),
        http_client: Arc::new(NullHttpClient),
        secret: "test-secret".to_string(),
        previous_secrets: Vec::new(),
    };
    tunnelbana_plugins::oidc_frontend::OidcFrontend::build(&bx).unwrap()
}

fn proxy(require_nonce: bool) -> Proxy {
    let sealer = StateSealer::new("test-secret", "TB_STATE").with_secure(false);
    Proxy::new(
        vec![build_frontend(require_nonce)],
        Vec::<Box<dyn Backend>>::new(),
        vec![],
        sealer,
    )
}

/// A signed ES256 DPoP proof for (htm, htu), plus the key's thumbprint.
fn make_proof(htm: &str, htu: &str, nonce: Option<&str>) -> (String, String) {
    use jose_rs::jwk::thumbprint::thumbprint_sha256;
    use jose_rs::JoseHeader;

    let mut jwk = jose_rs::jwk::generate_ec("P-256").unwrap();
    jwk.alg = Some("ES256".to_string());
    let public = jwk.to_public_jwk();
    let jkt = thumbprint_sha256(&public).unwrap();

    let mut header = JoseHeader::new("ES256");
    header.typ = Some("dpop+jwt".to_string());
    header.jwk = Some(serde_json::from_str(&public.to_json().unwrap()).unwrap());

    let mut claims = serde_json::json!({
        "jti": tunnelbana_core::util::random_token(16),
        "htm": htm,
        "htu": htu,
        "iat": tunnelbana_core::util::now_secs(),
    });
    if let Some(n) = nonce {
        claims["nonce"] = serde_json::Value::String(n.to_string());
    }
    let payload = serde_json::to_vec(&claims).unwrap();
    let proof = jose_rs::jws::compact::sign_with_jwk(&jwk, &payload, &header).unwrap();
    (proof, jkt)
}

fn token_req(proof: Option<&str>) -> HttpRequestData {
    let mut r = HttpRequestData {
        path: "OIDC/token".to_string(),
        method: "POST".to_string(),
        ..Default::default()
    };
    let mut form = BTreeMap::new();
    form.insert("grant_type".to_string(), "client_credentials".to_string());
    form.insert("client_id".to_string(), "svc-1".to_string());
    form.insert("client_secret".to_string(), "svc-secret".to_string());
    form.insert("scope".to_string(), "read".to_string());
    r.form = form;
    if let Some(p) = proof {
        r.headers.insert("dpop".to_string(), p.to_string());
    }
    r
}

fn header<'a>(resp: &'a Response, name: &str) -> Option<&'a str> {
    resp.headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}

#[tokio::test]
async fn discovery_advertises_dpop() {
    let p = proxy(false);
    let r = p
        .run(HttpRequestData {
            path: "OIDC/.well-known/openid-configuration".into(),
            method: "GET".into(),
            ..Default::default()
        })
        .await;
    assert_eq!(r.status, 200);
    let disco: serde_json::Value = serde_json::from_slice(&r.body).unwrap();
    assert_eq!(
        disco["dpop_signing_alg_values_supported"],
        serde_json::json!(["ES256"])
    );
    assert_eq!(
        disco["grant_types_supported"],
        serde_json::json!(["authorization_code", "client_credentials", "refresh_token"])
    );
    assert_eq!(disco["issuer"], ISSUER);
}

#[tokio::test]
async fn dpop_bound_token_and_replay_rejected() {
    let p = proxy(false);
    let (proof, _jkt) = make_proof("POST", TOKEN_URL, None);

    // First use → 200, token_type DPoP.
    let r1 = p.run(token_req(Some(&proof))).await;
    assert_eq!(r1.status, 200, "{}", String::from_utf8_lossy(&r1.body));
    let body: serde_json::Value = serde_json::from_slice(&r1.body).unwrap();
    assert_eq!(body["token_type"], "DPoP");
    assert_eq!(body["scope"], "read");

    // Replaying the same proof → invalid_dpop_proof.
    let r2 = p.run(token_req(Some(&proof))).await;
    assert_eq!(r2.status, 400);
    let err: serde_json::Value = serde_json::from_slice(&r2.body).unwrap();
    assert_eq!(err["error"], "invalid_dpop_proof");
}

#[tokio::test]
async fn plain_bearer_when_no_proof() {
    let p = proxy(false);
    let r = p.run(token_req(None)).await;
    assert_eq!(r.status, 200);
    let body: serde_json::Value = serde_json::from_slice(&r.body).unwrap();
    assert_eq!(body["token_type"], "Bearer");
}

#[tokio::test]
async fn htu_mismatch_rejected() {
    let p = proxy(false);
    // Proof bound to a different endpoint.
    let (proof, _) = make_proof("POST", "https://evil.example/token", None);
    let r = p.run(token_req(Some(&proof))).await;
    assert_eq!(r.status, 400);
    let err: serde_json::Value = serde_json::from_slice(&r.body).unwrap();
    assert_eq!(err["error"], "invalid_dpop_proof");
}

#[tokio::test]
async fn htu_trailing_slash_mismatch_rejected() {
    let p = proxy(false);
    let (proof, _) = make_proof("POST", &format!("{TOKEN_URL}/"), None);
    let r = p.run(token_req(Some(&proof))).await;
    assert_eq!(r.status, 400);
    let err: serde_json::Value = serde_json::from_slice(&r.body).unwrap();
    assert_eq!(err["error"], "invalid_dpop_proof");
}

#[tokio::test]
async fn nonce_challenge_then_accept() {
    let p = proxy(true);

    // No nonce → 400 use_dpop_nonce with a DPoP-Nonce header.
    let (proof, _) = make_proof("POST", TOKEN_URL, None);
    let r1 = p.run(token_req(Some(&proof))).await;
    assert_eq!(r1.status, 400);
    let err: serde_json::Value = serde_json::from_slice(&r1.body).unwrap();
    assert_eq!(err["error"], "use_dpop_nonce");
    let nonce = header(&r1, "DPoP-Nonce")
        .expect("DPoP-Nonce header")
        .to_string();
    assert!(!nonce.is_empty());

    // Retry with the issued nonce → 200 DPoP.
    let (proof2, _) = make_proof("POST", TOKEN_URL, Some(&nonce));
    let r2 = p.run(token_req(Some(&proof2))).await;
    assert_eq!(r2.status, 200, "{}", String::from_utf8_lossy(&r2.body));
    let body: serde_json::Value = serde_json::from_slice(&r2.body).unwrap();
    assert_eq!(body["token_type"], "DPoP");
}

// ── Resource-endpoint (userinfo) sender-constraint enforcement (RFC 9449 §7.1) ──

const USERINFO_URL: &str = "https://proxy.example.com/OIDC/userinfo";

fn gen_key() -> jose_rs::jwk::Jwk {
    let mut jwk = jose_rs::jwk::generate_ec("P-256").unwrap();
    jwk.alg = Some("ES256".to_string());
    jwk
}

/// A signed ES256 DPoP proof from a *given* key, so the same key can sign both
/// the token-request proof and the later resource proof. Returns the compact
/// proof and the key's thumbprint.
fn proof_with_key(
    jwk: &jose_rs::jwk::Jwk,
    htm: &str,
    htu: &str,
    nonce: Option<&str>,
    ath: Option<&str>,
) -> (String, String) {
    use jose_rs::jwk::thumbprint::thumbprint_sha256;
    use jose_rs::JoseHeader;

    let public = jwk.to_public_jwk();
    let jkt = thumbprint_sha256(&public).unwrap();

    let mut header = JoseHeader::new("ES256");
    header.typ = Some("dpop+jwt".to_string());
    header.jwk = Some(serde_json::from_str(&public.to_json().unwrap()).unwrap());

    let mut claims = serde_json::json!({
        "jti": tunnelbana_core::util::random_token(16),
        "htm": htm,
        "htu": htu,
        "iat": tunnelbana_core::util::now_secs(),
    });
    if let Some(n) = nonce {
        claims["nonce"] = serde_json::Value::String(n.to_string());
    }
    if let Some(a) = ath {
        claims["ath"] = serde_json::Value::String(a.to_string());
    }
    let payload = serde_json::to_vec(&claims).unwrap();
    let proof = jose_rs::jws::compact::sign_with_jwk(jwk, &payload, &header).unwrap();
    (proof, jkt)
}

fn ath_of(token: &str) -> String {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    URL_SAFE_NO_PAD.encode(tunnelbana_core::mac::sha256(token.as_bytes()))
}

fn userinfo_req(token: &str, scheme: &str, proof: Option<&str>) -> HttpRequestData {
    let mut r = HttpRequestData {
        path: "OIDC/userinfo".to_string(),
        method: "GET".to_string(),
        ..Default::default()
    };
    r.headers
        .insert("authorization".to_string(), format!("{scheme} {token}"));
    if let Some(p) = proof {
        r.headers.insert("dpop".to_string(), p.to_string());
    }
    r
}

/// Mint a DPoP-bound `client_credentials` token signed with `key`.
async fn mint_bound_token(p: &Proxy, key: &jose_rs::jwk::Jwk) -> String {
    let (proof, _) = proof_with_key(key, "POST", TOKEN_URL, None, None);
    let r = p.run(token_req(Some(&proof))).await;
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    let body: serde_json::Value = serde_json::from_slice(&r.body).unwrap();
    assert_eq!(body["token_type"], "DPoP");
    body["access_token"].as_str().unwrap().to_string()
}

/// A stolen DPoP-bound token replayed as a plain Bearer token (no proof) must be
/// rejected — this is the core sender-constraint guarantee.
#[tokio::test]
async fn userinfo_rejects_bound_token_as_plain_bearer() {
    let p = proxy(false);
    let key = gen_key();
    let token = mint_bound_token(&p, &key).await;

    let r = p.run(userinfo_req(&token, "Bearer", None)).await;
    assert_eq!(r.status, 400);
    let err: serde_json::Value = serde_json::from_slice(&r.body).unwrap();
    assert_eq!(err["error"], "invalid_dpop_proof");
}

/// The legitimate holder of the proof key gets in: a proof bound to this request
/// (htm/htu) and this token (ath), signed by the bound key, is accepted.
#[tokio::test]
async fn userinfo_accepts_matching_dpop_proof() {
    let p = proxy(false);
    let key = gen_key();
    let token = mint_bound_token(&p, &key).await;

    let ath = ath_of(&token);
    let (proof, _) = proof_with_key(&key, "GET", USERINFO_URL, None, Some(&ath));
    let r = p.run(userinfo_req(&token, "DPoP", Some(&proof))).await;
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    let claims: serde_json::Value = serde_json::from_slice(&r.body).unwrap();
    assert_eq!(claims["sub"], "svc-1");
}

#[tokio::test]
async fn userinfo_accepts_lowercase_auth_scheme() {
    let p = proxy(false);
    let key = gen_key();
    let token = mint_bound_token(&p, &key).await;

    let ath = ath_of(&token);
    let (proof, _) = proof_with_key(&key, "GET", USERINFO_URL, None, Some(&ath));
    let r = p.run(userinfo_req(&token, "dpop", Some(&proof))).await;
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    let claims: serde_json::Value = serde_json::from_slice(&r.body).unwrap();
    assert_eq!(claims["sub"], "svc-1");
}

/// A proof signed by a *different* key (an attacker who captured the token and
/// even computed the right ath) does not match the token's cnf.jkt → rejected.
#[tokio::test]
async fn userinfo_rejects_proof_from_wrong_key() {
    let p = proxy(false);
    let key = gen_key();
    let token = mint_bound_token(&p, &key).await;

    let other = gen_key();
    let ath = ath_of(&token);
    let (proof, _) = proof_with_key(&other, "GET", USERINFO_URL, None, Some(&ath));
    let r = p.run(userinfo_req(&token, "DPoP", Some(&proof))).await;
    assert_eq!(r.status, 400);
    let err: serde_json::Value = serde_json::from_slice(&r.body).unwrap();
    assert_eq!(err["error"], "invalid_dpop_proof");
}

/// A proof with the wrong access-token hash (`ath` bound to another token) is
/// rejected even though it is signed by the bound key.
#[tokio::test]
async fn userinfo_rejects_proof_with_wrong_ath() {
    let p = proxy(false);
    let key = gen_key();
    let token = mint_bound_token(&p, &key).await;

    let wrong_ath = ath_of("some-other-token");
    let (proof, _) = proof_with_key(&key, "GET", USERINFO_URL, None, Some(&wrong_ath));
    let r = p.run(userinfo_req(&token, "DPoP", Some(&proof))).await;
    assert_eq!(r.status, 400);
    let err: serde_json::Value = serde_json::from_slice(&r.body).unwrap();
    assert_eq!(err["error"], "invalid_dpop_proof");
}
