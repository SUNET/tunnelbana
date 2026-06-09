//! End-to-end test through the real `Proxy` orchestrator: an OIDC OP frontend
//! plus a mock backend that simulates a successful upstream login. Exercises
//! routing, the state cookie, request/response dispatch, and OP token issuance.

use std::collections::BTreeMap;
use std::sync::Arc;

use async_trait::async_trait;
use tunnelbana_core::attributes::AttributeMapper;
use tunnelbana_core::context::Context;
use tunnelbana_core::error::Result;
use tunnelbana_core::http::{HttpRequestData, Response};
use tunnelbana_core::internal::{AuthenticationInformation, InternalData, SubjectType};
use tunnelbana_core::plugin::{
    Backend, BackendAction, BuildContext, Frontend, NullHttpClient, Route,
};
use tunnelbana_core::proxy::Proxy;
use tunnelbana_core::state::StateSealer;
use tunnelbana_oidc::pkce;

/// A backend that immediately "logs in" a fixed user.
struct MockBackend {
    name: String,
}

#[async_trait]
impl Backend for MockBackend {
    fn name(&self) -> &str {
        &self.name
    }
    fn register_endpoints(&self) -> Vec<Route> {
        vec![Route::new(&format!("{}/callback", self.name), "callback")]
    }
    async fn start_auth(&self, _ctx: &mut Context, _req: InternalData) -> Result<Response> {
        // Simulate redirecting to an IdP that instantly bounces back to our ACS.
        Ok(Response::redirect(format!("/{}/callback", self.name)))
    }
    async fn handle_endpoint(&self, _ctx: &mut Context, _route_id: &str) -> Result<BackendAction> {
        let mut attributes = BTreeMap::new();
        attributes.insert("mail".to_string(), vec!["anna@example.com".to_string()]);
        attributes.insert("givenname".to_string(), vec!["Anna".to_string()]);
        let response = InternalData {
            auth_info: AuthenticationInformation {
                auth_class_ref: Some("urn:acr:mock".into()),
                timestamp: None,
                issuer: Some("https://idp.mock".into()),
            },
            requester: None,
            requester_name: Vec::new(),
            subject_id: Some("user-anna".into()),
            subject_type: SubjectType::Public,
            attributes,
        };
        Ok(BackendAction::AuthResponse(response))
    }
}

fn attribute_mapper() -> Arc<AttributeMapper> {
    let toml_str = r#"
        [attributes.mail]
        openid = ["email"]
        [attributes.givenname]
        openid = ["given_name"]
    "#;
    Arc::new(AttributeMapper::from_toml(toml_str).unwrap())
}

fn build_frontend(mapper: Arc<AttributeMapper>) -> Box<dyn Frontend> {
    let mut jwk = jose_rs::jwk::generate_ec("P-256").unwrap();
    jwk.alg = Some("ES256".into());
    let signing_jwk: serde_json::Value = serde_json::from_str(&jwk.to_json().unwrap()).unwrap();

    let config = serde_json::json!({
        "signing_jwk": signing_jwk,
        "signing_algorithm": "ES256",
        "signing_key_id": "k1",
        "clients": [{
            "client_id": "rp-1",
            "redirect_uris": ["https://rp.example.com/cb"],
            "response_types": ["code"],
            "token_endpoint_auth_method": "none"
        }]
    });

    let bx = BuildContext {
        name: "OIDC".to_string(),
        base_url: "https://proxy.example.com".to_string(),
        config,
        attribute_mapper: mapper,
        http_client: Arc::new(NullHttpClient),
        secret: "test-secret".to_string(),
        previous_secrets: Vec::new(),
    };
    tunnelbana_plugins::oidc_frontend::OidcFrontend::build(&bx).unwrap()
}

fn req(path: &str, method: &str, cookie: Option<&str>) -> HttpRequestData {
    let mut r = HttpRequestData {
        path: path.trim_start_matches('/').to_string(),
        method: method.to_string(),
        ..Default::default()
    };
    if let Some((p, q)) = path.split_once('?') {
        r.path = p.trim_start_matches('/').to_string();
        r.query = form_parse(q);
    }
    if let Some(c) = cookie {
        if let Some((k, v)) = c.split_once('=') {
            r.cookies.insert(k.to_string(), v.to_string());
        }
    }
    r
}

fn form_parse(s: &str) -> BTreeMap<String, String> {
    form_urlencoded::parse(s.as_bytes())
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect()
}

fn location(resp: &Response) -> String {
    resp.headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("location"))
        .map(|(_, v)| v.clone())
        .expect("location header")
}

fn set_cookie(resp: &Response) -> String {
    let raw = resp
        .headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("set-cookie"))
        .map(|(_, v)| v.clone())
        .expect("set-cookie header");
    raw.split(';').next().unwrap().to_string()
}

fn query_param(url: &str, key: &str) -> Option<String> {
    let (_, q) = url.split_once(['?', '#'])?;
    form_parse(q).get(key).cloned()
}

#[tokio::test]
async fn oidc_op_full_flow_through_proxy() {
    let mapper = attribute_mapper();
    let frontend = build_frontend(mapper.clone());
    let backend: Box<dyn Backend> = Box::new(MockBackend {
        name: "Mock".to_string(),
    });
    let sealer = StateSealer::new("test-secret", "TB_STATE").with_secure(false);
    let proxy = Proxy::new(vec![frontend], vec![backend], vec![], sealer);

    let verifier = "verifier-abcdefghijklmnop-abcdefghijklmnop";
    let challenge = pkce::s256_challenge(verifier);

    // 1) Authorization request → should redirect into the backend.
    let authz_url = format!(
        "OIDC/authorization?client_id=rp-1&response_type=code&redirect_uri={}&scope=openid%20email&state=st-1&nonce=no-1&code_challenge={}&code_challenge_method=S256",
        urlenc("https://rp.example.com/cb"),
        challenge
    );
    let r1 = proxy.run(req(&authz_url, "GET", None)).await;
    assert_eq!(r1.status, 302, "authorization should redirect");
    assert!(location(&r1).contains("Mock/callback"));
    let cookie1 = set_cookie(&r1);

    // 2) Backend callback → response path → OP issues code redirect to RP.
    let r2 = proxy.run(req("Mock/callback", "GET", Some(&cookie1))).await;
    assert_eq!(r2.status, 302, "callback should redirect to RP with code");
    let rp_redirect = location(&r2);
    assert!(rp_redirect.starts_with("https://rp.example.com/cb?"));
    assert_eq!(query_param(&rp_redirect, "state").as_deref(), Some("st-1"));
    let code = query_param(&rp_redirect, "code").expect("code");

    // 3) Token exchange (PKCE) → 200 with id_token + access_token.
    let mut token_req = req("OIDC/token", "POST", None);
    token_req.form = form_parse(&format!(
        "grant_type=authorization_code&code={}&redirect_uri={}&client_id=rp-1&code_verifier={}",
        urlenc(&code),
        urlenc("https://rp.example.com/cb"),
        verifier
    ));
    token_req.headers.insert(
        "content-type".into(),
        "application/x-www-form-urlencoded".into(),
    );
    let r3 = proxy.run(token_req).await;
    assert_eq!(
        r3.status,
        200,
        "token endpoint should succeed: {}",
        String::from_utf8_lossy(&r3.body)
    );
    let token_json: serde_json::Value = serde_json::from_slice(&r3.body).unwrap();
    let id_token = token_json["id_token"].as_str().expect("id_token");
    let access_token = token_json["access_token"].as_str().expect("access_token");

    // 4) Fetch the OP JWKS and verify the id_token signature + claims.
    let r4 = proxy.run(req("OIDC/jwks", "GET", None)).await;
    assert_eq!(r4.status, 200);
    let jwks: jose_rs::jwk::JwkSet = serde_json::from_slice(&r4.body).unwrap();
    let validation = jose_rs::jwt::Validation::new()
        .with_issuer("https://proxy.example.com/OIDC")
        .with_audience("rp-1");
    let claims = jose_rs::jwt::decode_with_jwkset(&jwks, id_token, &validation).unwrap();
    assert_eq!(claims.sub.as_deref(), Some("user-anna"));
    assert_eq!(
        claims.extra.get("nonce").and_then(|v| v.as_str()),
        Some("no-1")
    );
    assert_eq!(
        claims.extra.get("email").and_then(|v| v.as_str()),
        Some("anna@example.com")
    );
    assert_eq!(
        claims.extra.get("given_name").and_then(|v| v.as_str()),
        Some("Anna")
    );

    // 5) UserInfo with the access token.
    let mut ui_req = req("OIDC/userinfo", "GET", None);
    ui_req
        .headers
        .insert("authorization".into(), format!("Bearer {access_token}"));
    let r5 = proxy.run(ui_req).await;
    assert_eq!(r5.status, 200);
    let userinfo: serde_json::Value = serde_json::from_slice(&r5.body).unwrap();
    assert_eq!(userinfo["sub"], "user-anna");
    assert_eq!(userinfo["email"], "anna@example.com");

    // 6) Discovery document is served.
    let r6 = proxy
        .run(req("OIDC/.well-known/openid-configuration", "GET", None))
        .await;
    assert_eq!(r6.status, 200);
    let disco: serde_json::Value = serde_json::from_slice(&r6.body).unwrap();
    assert_eq!(disco["issuer"], "https://proxy.example.com/OIDC");
    assert_eq!(
        disco["token_endpoint"],
        "https://proxy.example.com/OIDC/token"
    );
}

fn urlenc(s: &str) -> String {
    form_urlencoded::byte_serialize(s.as_bytes()).collect()
}
