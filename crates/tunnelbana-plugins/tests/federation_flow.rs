//! Federation frontend: entity configuration + automatic RP registration via a
//! mocked trust-anchor resolve endpoint, then a full code flow with
//! `private_key_jwt` token authentication.

use std::collections::BTreeMap;
use std::sync::Arc;

use async_trait::async_trait;
use tunnelbana_core::attributes::AttributeMapper;
use tunnelbana_core::context::Context;
use tunnelbana_core::error::Result as CoreResult;
use tunnelbana_core::http::{HttpClient, HttpFetchResponse, HttpRequestData, Response};
use tunnelbana_core::internal::{AuthenticationInformation, InternalData, SubjectType};
use tunnelbana_core::keys::{signing_key_from_jwk_json, SigningKey};
use tunnelbana_core::plugin::{
    Backend, BackendAction, BuildContext, Frontend, NullHttpClient, Route,
};
use tunnelbana_core::proxy::Proxy;
use tunnelbana_core::state::StateSealer;

const TA_ID: &str = "https://ta.example.com";
const RP_ID: &str = "https://rp.fed.example.com";
const RP_REDIRECT: &str = "https://rp.fed.example.com/callback";

fn ec_key(kid: &str) -> SigningKey {
    let mut jwk = jose_rs::jwk::generate_ec("P-256").unwrap();
    jwk.alg = Some("ES256".into());
    signing_key_from_jwk_json(&jwk.to_json().unwrap(), Some("ES256"), Some(kid)).unwrap()
}

/// Mock the federation network: the trust anchor's entity config and resolve
/// endpoint, both signed by the TA key.
struct MockFederation {
    ta_key: SigningKey,
    rp_key: SigningKey,
}

#[async_trait]
impl HttpClient for MockFederation {
    async fn get(&self, url: &str) -> CoreResult<HttpFetchResponse> {
        let body = if url == format!("{TA_ID}/.well-known/openid-federation") {
            // TA entity configuration advertising its resolve endpoint.
            let metadata = serde_json::json!({
                "federation_entity": {
                    "federation_resolve_endpoint": format!("{TA_ID}/resolve")
                }
            });
            tunnelbana_oidc::federation::build_entity_configuration(
                &self.ta_key,
                TA_ID,
                &self.ta_key.to_public_jwks(),
                &[],
                metadata,
                &[],
                3600,
            )
            .unwrap()
        } else if url.starts_with(&format!("{TA_ID}/resolve")) {
            // Resolve response for the RP, signed by the TA, carrying the RP's
            // relying-party metadata (redirect_uris + public jwks) and a trust
            // chain rooted at the TA (required since grindvakt 0.2.0).
            let rp_metadata = serde_json::json!({
                "openid_relying_party": {
                    "redirect_uris": [RP_REDIRECT],
                    "client_name": "Federation RP",
                    "jwks": self.rp_key.to_public_jwks(),
                    "subject_type": "pairwise"
                }
            });
            let mut claims = jose_rs::jwt::Claims {
                iss: Some(TA_ID.to_string()),
                sub: Some(RP_ID.to_string()),
                iat: Some(tunnelbana_core::util::now_secs()),
                exp: Some(tunnelbana_core::util::now_secs() + 3600),
                ..Default::default()
            };
            claims.extra.insert("metadata".into(), rp_metadata.clone());
            claims.extra.insert(
                "trust_chain".into(),
                serde_json::json!([
                    // Chain head: the RP's self-signed entity configuration.
                    tunnelbana_oidc::federation::build_entity_configuration(
                        &self.rp_key,
                        RP_ID,
                        &self.rp_key.to_public_jwks(),
                        &[TA_ID.to_string()],
                        rp_metadata,
                        &[],
                        3600,
                    )
                    .unwrap(),
                    // Chain tail: the trust anchor's entity configuration.
                    tunnelbana_oidc::federation::build_entity_configuration(
                        &self.ta_key,
                        TA_ID,
                        &self.ta_key.to_public_jwks(),
                        &[],
                        serde_json::json!({
                            "federation_entity": {
                                "federation_resolve_endpoint": format!("{TA_ID}/resolve")
                            }
                        }),
                        &[],
                        3600,
                    )
                    .unwrap(),
                ]),
            );
            tunnelbana_oidc::jwt::sign(
                &self.ta_key,
                &claims,
                Some(tunnelbana_oidc::federation::RESOLVE_RESPONSE_TYP),
            )
            .unwrap()
        } else {
            return Ok(HttpFetchResponse {
                status: 404,
                body: Vec::new(),
                content_type: None,
            });
        };
        Ok(HttpFetchResponse {
            status: 200,
            body: body.into_bytes(),
            content_type: Some("application/entity-statement+jwt".into()),
        })
    }

    async fn post_form(
        &self,
        _url: &str,
        _form: &[(String, String)],
        _headers: &[(String, String)],
    ) -> CoreResult<HttpFetchResponse> {
        Ok(HttpFetchResponse {
            status: 404,
            body: Vec::new(),
            content_type: None,
        })
    }
}

struct MockBackend;

#[async_trait]
impl Backend for MockBackend {
    fn name(&self) -> &str {
        "Mock"
    }
    fn register_endpoints(&self) -> Vec<Route> {
        vec![Route::exact("Mock/callback", "callback")]
    }
    async fn start_auth(&self, _ctx: &mut Context, _req: InternalData) -> CoreResult<Response> {
        Ok(Response::redirect("/Mock/callback"))
    }
    async fn handle_endpoint(&self, _ctx: &mut Context, _id: &str) -> CoreResult<BackendAction> {
        let mut attributes = BTreeMap::new();
        attributes.insert("mail".to_string(), vec!["fed@example.com".to_string()]);
        Ok(BackendAction::AuthResponse(InternalData {
            auth_info: AuthenticationInformation::default(),
            requester: None,
            requester_name: vec![],
            subject_id: Some("fed-user".into()),
            subject_type: SubjectType::Pairwise,
            attributes,
        }))
    }
}

fn mapper() -> Arc<AttributeMapper> {
    Arc::new(
        AttributeMapper::from_toml(
            r#"
            [attributes.mail]
            openid = ["email"]
        "#,
        )
        .unwrap(),
    )
}

fn req(path: &str, method: &str, cookie: Option<&str>) -> HttpRequestData {
    let mut r = HttpRequestData {
        method: method.to_string(),
        ..Default::default()
    };
    if let Some((p, q)) = path.split_once('?') {
        r.path = p.trim_start_matches('/').to_string();
        r.query = form_urlencoded::parse(q.as_bytes())
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect();
    } else {
        r.path = path.trim_start_matches('/').to_string();
    }
    if let Some(c) = cookie {
        if let Some((k, v)) = c.split_once('=') {
            r.cookies.insert(k.to_string(), v.to_string());
        }
    }
    r
}

fn set_cookie(resp: &Response) -> String {
    resp.headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("set-cookie"))
        .map(|(_, v)| v.split(';').next().unwrap().to_string())
        .expect("set-cookie")
}

fn location(resp: &Response) -> String {
    resp.headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("location"))
        .map(|(_, v)| v.clone())
        .expect("location")
}

fn qp(url: &str, key: &str) -> Option<String> {
    let (_, q) = url.split_once(['?', '#'])?;
    form_urlencoded::parse(q.as_bytes())
        .find(|(k, _)| k == key)
        .map(|(_, v)| v.into_owned())
}

fn build_proxy(
    http: Arc<dyn HttpClient>,
    op_key_jwk: serde_json::Value,
    ta_pub: serde_json::Value,
) -> Proxy {
    let config = serde_json::json!({
        "signing_jwk": op_key_jwk,
        "signing_algorithm": "ES256",
        "signing_key_id": "op-1",
        "federation": {
            "signing_jwk": op_key_jwk,
            "signing_algorithm": "ES256",
            "signing_key_id": "fed-1",
            "authority_hints": [TA_ID],
            "organization_name": "Tunnelbana Test OP",
            "trust_anchor": [ { "entity_id": TA_ID, "keys": [ ta_pub ] } ]
        }
    });
    let bx = BuildContext {
        name: "OIDFed".to_string(),
        base_url: "https://proxy.example.com".to_string(),
        config,
        attribute_mapper: mapper(),
        http_client: http,
        secret: "fed-secret".to_string(),
        previous_secrets: Vec::new(),
    };
    let frontend = tunnelbana_plugins::federation_frontend::FederationFrontend::build(&bx).unwrap();
    let sealer = StateSealer::new("fed-secret", "TB_STATE").with_secure(false);
    Proxy::new(vec![frontend], vec![Box::new(MockBackend)], vec![], sealer)
}

#[tokio::test]
async fn entity_configuration_is_served_and_self_signed() {
    let ta_key = ec_key("ta-1");
    let rp_key = ec_key("rp-1");
    let http: Arc<dyn HttpClient> = Arc::new(MockFederation {
        ta_key: ta_key.clone(),
        rp_key: rp_key.clone(),
    });
    let op_jwk: serde_json::Value =
        serde_json::from_str(&ec_key("op-1").jwk.to_json().unwrap()).unwrap();
    let ta_pub: serde_json::Value =
        serde_json::from_str(&ta_key.public_jwk().to_json().unwrap()).unwrap();
    let proxy = build_proxy(http, op_jwk, ta_pub);

    let r = proxy
        .run(req("OIDFed/.well-known/openid-federation", "GET", None))
        .await;
    assert_eq!(r.status, 200);
    let jwt = String::from_utf8(r.body).unwrap();
    let stmt = tunnelbana_oidc::federation::verify_self_signed(&jwt).unwrap();
    assert_eq!(stmt.iss(), Some("https://proxy.example.com/OIDFed"));
    assert!(stmt.metadata("openid_provider").is_some());
    assert_eq!(
        stmt.authority_hints(),
        vec!["https://ta.example.com".to_string()]
    );
}

#[tokio::test]
async fn auto_registration_and_private_key_jwt_flow() {
    let ta_key = ec_key("ta-1");
    let rp_key = ec_key("rp-1");
    let http: Arc<dyn HttpClient> = Arc::new(MockFederation {
        ta_key: ta_key.clone(),
        rp_key: rp_key.clone(),
    });
    let op_jwk: serde_json::Value =
        serde_json::from_str(&ec_key("op-1").jwk.to_json().unwrap()).unwrap();
    let ta_pub: serde_json::Value =
        serde_json::from_str(&ta_key.public_jwk().to_json().unwrap()).unwrap();
    let proxy = build_proxy(http, op_jwk, ta_pub);

    // Authorization for an UNKNOWN client → triggers federation auto-registration.
    let authz = format!(
        "OIDFed/authorization?client_id={}&response_type=code&redirect_uri={}&scope=openid&state=st&nonce=no",
        enc(RP_ID),
        enc(RP_REDIRECT)
    );
    let r1 = proxy.run(req(&authz, "GET", None)).await;
    assert_eq!(
        r1.status,
        302,
        "should redirect into backend after auto-register: {}",
        String::from_utf8_lossy(&r1.body)
    );
    let cookie = set_cookie(&r1);

    // Backend callback → OP issues a code to the RP's redirect URI.
    let r2 = proxy.run(req("Mock/callback", "GET", Some(&cookie))).await;
    assert_eq!(r2.status, 302);
    let loc = location(&r2);
    assert!(loc.starts_with(RP_REDIRECT), "got: {loc}");
    let code = qp(&loc, "code").expect("code");

    // Token exchange with private_key_jwt (RP signs the client assertion).
    let token_url = "https://proxy.example.com/OIDFed/token";
    let assertion = tunnelbana_oidc::rp::build_client_assertion(&rp_key, RP_ID, token_url).unwrap();
    let mut treq = req("OIDFed/token", "POST", None);
    treq.form = [
        ("grant_type", "authorization_code"),
        ("code", code.as_str()),
        ("redirect_uri", RP_REDIRECT),
        (
            "client_assertion_type",
            "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        ),
        ("client_assertion", assertion.as_str()),
    ]
    .iter()
    .map(|(k, v)| (k.to_string(), v.to_string()))
    .collect();
    treq.headers.insert(
        "content-type".into(),
        "application/x-www-form-urlencoded".into(),
    );

    let r3 = proxy.run(treq).await;
    assert_eq!(
        r3.status,
        200,
        "token exchange should succeed: {}",
        String::from_utf8_lossy(&r3.body)
    );
    let body: serde_json::Value = serde_json::from_slice(&r3.body).unwrap();
    assert!(body.get("id_token").is_some());
    assert!(body.get("access_token").is_some());
}

fn enc(s: &str) -> String {
    form_urlencoded::byte_serialize(s.as_bytes()).collect()
}

/// Build a federation OP frontend with the given inline `clients` and optional
/// `clients_file`. `build()` does no network, so a fresh trust anchor + null
/// HTTP client suffice. Returns the build `Result` to exercise error paths.
fn build_frontend_with_clients(
    clients: serde_json::Value,
    clients_file: Option<&str>,
) -> CoreResult<Box<dyn Frontend>> {
    let op_jwk: serde_json::Value =
        serde_json::from_str(&ec_key("op-1").jwk.to_json().unwrap()).unwrap();
    let ta_pub: serde_json::Value =
        serde_json::from_str(&ec_key("ta-1").public_jwk().to_json().unwrap()).unwrap();
    let mut config = serde_json::json!({
        "signing_jwk": op_jwk,
        "signing_algorithm": "ES256",
        "signing_key_id": "op-1",
        "clients": clients,
        "federation": {
            "signing_jwk": op_jwk,
            "signing_algorithm": "ES256",
            "signing_key_id": "fed-1",
            "authority_hints": [TA_ID],
            "trust_anchor": [ { "entity_id": TA_ID, "keys": [ ta_pub ] } ]
        }
    });
    if let Some(p) = clients_file {
        config["clients_file"] = serde_json::Value::String(p.to_string());
    }
    let bx = BuildContext {
        name: "OIDFed".to_string(),
        base_url: "https://proxy.example.com".to_string(),
        config,
        attribute_mapper: mapper(),
        http_client: Arc::new(NullHttpClient),
        secret: "fed-secret".to_string(),
        previous_secrets: Vec::new(),
    };
    tunnelbana_plugins::federation_frontend::FederationFrontend::build(&bx)
}

/// The federation frontend seeds statically pre-registered clients from
/// `clients_file`, merged with inline `clients` (F5: parity with the `oidc`
/// frontend's clients_file wiring).
#[test]
fn clients_file_loads_in_federation_frontend() {
    let path = std::env::temp_dir().join("tb_fed_clients_file.json");
    std::fs::write(
        &path,
        r#"[{"client_id":"file-rp","redirect_uris":["https://file-rp.example/cb"],
            "token_endpoint_auth_method":"private_key_jwt"}]"#,
    )
    .unwrap();
    let res = build_frontend_with_clients(
        serde_json::json!([{ "client_id": "inline-rp" }]),
        Some(path.to_str().unwrap()),
    );
    assert!(
        res.is_ok(),
        "federation frontend should load clients_file: {:?}",
        res.err()
    );
}

/// A `client_id` duplicated across inline `clients` and `clients_file` fails the
/// federation frontend build, just like the `oidc` frontend.
#[test]
fn clients_file_duplicate_fails_federation_build() {
    let path = std::env::temp_dir().join("tb_fed_clients_file_dup.json");
    std::fs::write(&path, r#"[{"client_id":"dup"}]"#).unwrap();
    let err = build_frontend_with_clients(
        serde_json::json!([{ "client_id": "dup" }]),
        Some(path.to_str().unwrap()),
    )
    .err()
    .expect("duplicate client_id must fail the build");
    assert!(
        err.to_string().contains("duplicate client_id"),
        "got: {err}"
    );
}
