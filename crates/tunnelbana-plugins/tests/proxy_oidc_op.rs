//! End-to-end test through the real `Proxy` orchestrator: an OIDC OP frontend
//! plus a mock backend that simulates a successful upstream login. Exercises
//! routing, the state cookie, request/response dispatch, and OP token issuance.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use tunnelbana_core::attributes::AttributeMapper;
use tunnelbana_core::context::Context;
use tunnelbana_core::error::Result;
use tunnelbana_core::http::{HttpRequestData, Response};
use tunnelbana_core::internal::{AuthenticationInformation, InternalData, SubjectType};
use tunnelbana_core::plugin::{
    Backend, BackendAction, BuildContext, Frontend, MicroService, NullHttpClient, Route,
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
        attributes.insert("email_verified".to_string(), vec!["true".to_string()]);
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

struct RequesterProbe {
    seen: Arc<Mutex<Option<String>>>,
}

struct BackendPinProbe {
    backend: String,
}

#[async_trait]
impl MicroService for RequesterProbe {
    fn name(&self) -> &str {
        "requester_probe"
    }

    async fn process_response(
        &self,
        _ctx: &mut Context,
        data: InternalData,
    ) -> Result<InternalData> {
        *self.seen.lock().unwrap() = data.requester.clone();
        Ok(data)
    }
}

#[async_trait]
impl MicroService for BackendPinProbe {
    fn name(&self) -> &str {
        "backend_pin_probe"
    }

    async fn process_request(&self, ctx: &mut Context, data: InternalData) -> Result<InternalData> {
        ctx.target_backend = Some(self.backend.clone());
        Ok(data)
    }
}

fn attribute_mapper() -> Arc<AttributeMapper> {
    let toml_str = r#"
        [attributes.mail]
        openid = ["email"]
        [attributes.givenname]
        openid = ["given_name"]
        [attributes.email_verified]
        openid = ["email_verified"]
    "#;
    Arc::new(AttributeMapper::from_toml(toml_str).unwrap())
}

fn build_frontend(mapper: Arc<AttributeMapper>) -> Box<dyn Frontend> {
    build_frontend_with_grants(mapper, &["authorization_code"])
}

fn build_frontend_with_grants(mapper: Arc<AttributeMapper>, grants: &[&str]) -> Box<dyn Frontend> {
    build_frontend_full(mapper, grants, None)
}

fn build_frontend_pinned(mapper: Arc<AttributeMapper>, backend: &str) -> Box<dyn Frontend> {
    build_frontend_full(mapper, &["authorization_code"], Some(backend))
}

fn build_frontend_full(
    mapper: Arc<AttributeMapper>,
    grants: &[&str],
    backend: Option<&str>,
) -> Box<dyn Frontend> {
    let mut jwk = jose_rs::jwk::generate_ec("P-256").unwrap();
    jwk.alg = Some("ES256".into());
    let signing_jwk: serde_json::Value = serde_json::from_str(&jwk.to_json().unwrap()).unwrap();

    let mut config = serde_json::json!({
        "signing_jwk": signing_jwk,
        "signing_algorithm": "ES256",
        "signing_key_id": "k1",
        "clients": [{
            "client_id": "rp-1",
            "redirect_uris": ["https://rp.example.com/cb"],
            "response_types": ["code"],
            "grant_types": grants,
            "token_endpoint_auth_method": "none"
        }]
    });
    if let Some(b) = backend {
        config["backend"] = serde_json::Value::String(b.to_string());
    }

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
    // email_verified is emitted as a real JSON boolean (OIDC Core §5.1), not a
    // string — Vaultwarden and other strict RPs require the boolean type.
    assert_eq!(
        claims.extra.get("email_verified"),
        Some(&serde_json::Value::Bool(true))
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

#[tokio::test]
async fn oidc_op_refresh_token_flow_through_proxy() {
    let mapper = attribute_mapper();
    let frontend =
        build_frontend_with_grants(mapper.clone(), &["authorization_code", "refresh_token"]);
    let backend: Box<dyn Backend> = Box::new(MockBackend {
        name: "Mock".to_string(),
    });
    let sealer = StateSealer::new("test-secret", "TB_STATE").with_secure(false);
    let proxy = Proxy::new(vec![frontend], vec![backend], vec![], sealer);

    let verifier = "verifier-abcdefghijklmnop-abcdefghijklmnop";
    let challenge = pkce::s256_challenge(verifier);

    // Authorization → backend callback → code redirect to RP.
    let authz_url = format!(
        "OIDC/authorization?client_id=rp-1&response_type=code&redirect_uri={}&scope=openid%20email&state=st-1&nonce=no-1&code_challenge={}&code_challenge_method=S256",
        urlenc("https://rp.example.com/cb"),
        challenge
    );
    let r1 = proxy.run(req(&authz_url, "GET", None)).await;
    let cookie1 = set_cookie(&r1);
    let r2 = proxy.run(req("Mock/callback", "GET", Some(&cookie1))).await;
    let code = query_param(&location(&r2), "code").expect("code");

    // Code exchange returns a refresh token.
    let mut token_req = req("OIDC/token", "POST", None);
    token_req.form = form_parse(&format!(
        "grant_type=authorization_code&code={}&redirect_uri={}&client_id=rp-1&code_verifier={}",
        urlenc(&code),
        urlenc("https://rp.example.com/cb"),
        verifier
    ));
    let r3 = proxy.run(token_req).await;
    assert_eq!(r3.status, 200);
    let token_json: serde_json::Value = serde_json::from_slice(&r3.body).unwrap();
    let refresh = token_json["refresh_token"]
        .as_str()
        .expect("refresh_token issued")
        .to_string();

    // Refresh exchange returns fresh tokens and a rotated refresh token.
    let mut refresh_req = req("OIDC/token", "POST", None);
    refresh_req.form = form_parse(&format!(
        "grant_type=refresh_token&refresh_token={}&client_id=rp-1",
        urlenc(&refresh),
    ));
    let r4 = proxy.run(refresh_req).await;
    assert_eq!(
        r4.status,
        200,
        "refresh should succeed: {}",
        String::from_utf8_lossy(&r4.body)
    );
    let refreshed: serde_json::Value = serde_json::from_slice(&r4.body).unwrap();
    let new_access = refreshed["access_token"].as_str().expect("access_token");
    let rotated = refreshed["refresh_token"]
        .as_str()
        .expect("rotated refresh");
    assert_ne!(rotated, refresh, "refresh token should rotate");
    assert!(refreshed["id_token"].is_string(), "id_token on refresh");

    // The new access token works at userinfo.
    let mut ui_req = req("OIDC/userinfo", "GET", None);
    ui_req
        .headers
        .insert("authorization".into(), format!("Bearer {new_access}"));
    let r5 = proxy.run(ui_req).await;
    assert_eq!(r5.status, 200);
    let userinfo: serde_json::Value = serde_json::from_slice(&r5.body).unwrap();
    assert_eq!(userinfo["sub"], "user-anna");

    // Discovery advertises the refresh_token grant.
    let r6 = proxy
        .run(req("OIDC/.well-known/openid-configuration", "GET", None))
        .await;
    let disco: serde_json::Value = serde_json::from_slice(&r6.body).unwrap();
    let grants = disco["grant_types_supported"].as_array().unwrap();
    assert!(grants.iter().any(|g| g == "refresh_token"));
}

#[tokio::test]
async fn response_microservice_sees_restored_requester() {
    let mapper = attribute_mapper();
    let frontend = build_frontend(mapper.clone());
    let backend: Box<dyn Backend> = Box::new(MockBackend {
        name: "Mock".to_string(),
    });
    let seen = Arc::new(Mutex::new(None));
    let probe: Box<dyn MicroService> = Box::new(RequesterProbe { seen: seen.clone() });
    let sealer = StateSealer::new("test-secret", "TB_STATE").with_secure(false);
    let proxy = Proxy::new(vec![frontend], vec![backend], vec![probe], sealer);

    let verifier = "verifier-abcdefghijklmnop-abcdefghijklmnop";
    let challenge = pkce::s256_challenge(verifier);
    let authz_url = format!(
        "OIDC/authorization?client_id=rp-1&response_type=code&redirect_uri={}&scope=openid%20email&state=st-1&nonce=no-1&code_challenge={}&code_challenge_method=S256",
        urlenc("https://rp.example.com/cb"),
        challenge
    );

    let r1 = proxy.run(req(&authz_url, "GET", None)).await;
    assert_eq!(r1.status, 302, "authorization should redirect");
    let cookie1 = set_cookie(&r1);

    let r2 = proxy.run(req("Mock/callback", "GET", Some(&cookie1))).await;
    assert_eq!(r2.status, 302, "callback should redirect to RP with code");
    assert_eq!(seen.lock().unwrap().as_deref(), Some("rp-1"));
}

/// A frontend's `backend = "..."` config pin overrides request-path backend
/// routing and the default backend (which is the first one registered).
#[tokio::test]
async fn frontend_backend_pin_overrides_request_routing_and_default() {
    let mapper = attribute_mapper();
    let frontend = build_frontend_pinned(mapper.clone(), "Pinned");
    // "Default" is registered first, so it is the proxy default backend; the
    // micro-service also tries to steer the flow to "Default". The frontend
    // pin must still steer the flow to "Pinned" instead.
    let default_backend: Box<dyn Backend> = Box::new(MockBackend {
        name: "Default".to_string(),
    });
    let pinned_backend: Box<dyn Backend> = Box::new(MockBackend {
        name: "Pinned".to_string(),
    });
    let sealer = StateSealer::new("test-secret", "TB_STATE").with_secure(false);
    let proxy = Proxy::new(
        vec![frontend],
        vec![default_backend, pinned_backend],
        vec![Box::new(BackendPinProbe {
            backend: "Default".to_string(),
        })],
        sealer,
    );

    let verifier = "verifier-abcdefghijklmnop-abcdefghijklmnop";
    let challenge = pkce::s256_challenge(verifier);
    let authz_url = format!(
        "OIDC/authorization?client_id=rp-1&response_type=code&redirect_uri={}&scope=openid%20email&state=st-1&nonce=no-1&code_challenge={}&code_challenge_method=S256",
        urlenc("https://rp.example.com/cb"),
        challenge
    );
    let r1 = proxy.run(req(&authz_url, "GET", None)).await;
    assert_eq!(r1.status, 302, "authorization should redirect");
    assert!(
        location(&r1).contains("Pinned/callback"),
        "flow must be pinned to the configured backend, got {}",
        location(&r1)
    );
}

/// A client loaded from an external `clients_file` (JSON) completes the
/// authorization flow exactly like an inline client.
#[tokio::test]
async fn client_loaded_from_clients_file_can_authorize() {
    // A roster file holding one client distinct from any inline client.
    let clients_path = std::env::temp_dir().join("tb_proxy_oidc_clients_file.json");
    std::fs::write(
        &clients_path,
        r#"[{"client_id":"rp-file","redirect_uris":["https://file-rp.example.com/cb"],
            "response_types":["code"],"grant_types":["authorization_code"],
            "token_endpoint_auth_method":"none"}]"#,
    )
    .unwrap();

    let mut jwk = jose_rs::jwk::generate_ec("P-256").unwrap();
    jwk.alg = Some("ES256".into());
    let signing_jwk: serde_json::Value = serde_json::from_str(&jwk.to_json().unwrap()).unwrap();
    let config = serde_json::json!({
        "signing_jwk": signing_jwk,
        "signing_algorithm": "ES256",
        "signing_key_id": "k1",
        "clients_file": clients_path.to_str().unwrap(),
        // No inline clients: the roster comes entirely from the file.
    });
    let bx = BuildContext {
        name: "OIDC".to_string(),
        base_url: "https://proxy.example.com".to_string(),
        config,
        attribute_mapper: attribute_mapper(),
        http_client: Arc::new(NullHttpClient),
        secret: "test-secret".to_string(),
        previous_secrets: Vec::new(),
    };
    let frontend = tunnelbana_plugins::oidc_frontend::OidcFrontend::build(&bx).unwrap();

    let backend: Box<dyn Backend> = Box::new(MockBackend {
        name: "Mock".to_string(),
    });
    let sealer = StateSealer::new("test-secret", "TB_STATE").with_secure(false);
    let proxy = Proxy::new(vec![frontend], vec![backend], vec![], sealer);

    let verifier = "verifier-abcdefghijklmnop-abcdefghijklmnop";
    let challenge = pkce::s256_challenge(verifier);
    let authz_url = format!(
        "OIDC/authorization?client_id=rp-file&response_type=code&redirect_uri={}&scope=openid&state=st-1&nonce=no-1&code_challenge={}&code_challenge_method=S256",
        urlenc("https://file-rp.example.com/cb"),
        challenge
    );
    let r1 = proxy.run(req(&authz_url, "GET", None)).await;
    assert_eq!(
        r1.status, 302,
        "file-loaded client should be accepted and redirect into the backend"
    );
    assert!(location(&r1).contains("Mock/callback"));
}

fn urlenc(s: &str) -> String {
    form_urlencoded::byte_serialize(s.as_bytes()).collect()
}
