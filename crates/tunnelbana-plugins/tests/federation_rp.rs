//! Federation backend (RP side): entity configuration, OP resolution through
//! a mocked trust-anchor resolve endpoint, and a full code flow with
//! private_key_jwt client authentication and id_token verification.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use tunnelbana_core::attributes::AttributeMapper;
use tunnelbana_core::context::Context;
use tunnelbana_core::error::Result as CoreResult;
use tunnelbana_core::http::{HttpClient, HttpFetchResponse, HttpRequestData, Response};
use tunnelbana_core::internal::{InternalData, SubjectType};
use tunnelbana_core::keys::{signing_key_from_jwk_json, SigningKey};
use tunnelbana_core::plugin::{Backend, BackendAction, BuildContext};
use tunnelbana_core::state::State;

const TA_ID: &str = "https://ta.example.com";
const OP_ID: &str = "https://op.example.org";
const RP_ENTITY: &str = "https://proxy.example.com/OIDFedRP";

#[derive(Clone, Copy)]
enum KeyDistribution {
    Inline,
    SignedJwksUri,
    BadInlineWithJwksUri,
}

#[derive(Clone, Copy)]
struct NetworkConfig {
    resolve_issuer: &'static str,
    ta_ec_subject: &'static str,
    key_distribution: KeyDistribution,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            resolve_issuer: TA_ID,
            ta_ec_subject: TA_ID,
            key_distribution: KeyDistribution::Inline,
        }
    }
}

fn ec_key(kid: &str) -> SigningKey {
    let mut jwk = jose_rs::jwk::generate_ec("P-256").unwrap();
    jwk.alg = Some("ES256".into());
    signing_key_from_jwk_json(&jwk.to_json().unwrap(), Some("ES256"), Some(kid)).unwrap()
}

/// Mocks the federation network: the trust anchor (entity configuration +
/// resolve endpoint) and the upstream OP's token endpoint.
struct MockNetwork {
    ta_key: SigningKey,
    op_key: SigningKey,
    rp_pub_jwks: jose_rs::jwk::JwkSet,
    config: NetworkConfig,
    /// The nonce the RP put in its authorization redirect; the mock echoes it
    /// into the id_token (set by the test between start_auth and callback).
    nonce: Mutex<Option<String>>,
    /// Captured token-request form for assertions.
    token_form: Mutex<Vec<(String, String)>>,
}

#[async_trait]
impl HttpClient for MockNetwork {
    async fn get(&self, url: &str) -> CoreResult<HttpFetchResponse> {
        let body = if url == format!("{TA_ID}/.well-known/openid-federation") {
            let metadata = serde_json::json!({
                "federation_entity": {
                    "federation_resolve_endpoint": format!("{TA_ID}/resolve")
                }
            });
            entity_configuration(
                &self.ta_key,
                TA_ID,
                self.config.ta_ec_subject,
                &self.ta_key.to_public_jwks(),
                &[],
                metadata,
            )
        } else if url.starts_with(&format!("{TA_ID}/resolve")) {
            // Resolve response for the OP, signed by the TA, carrying the
            // OP's provider metadata and a trust chain rooted at the TA.
            let mut claims = jose_rs::jwt::Claims {
                iss: Some(self.config.resolve_issuer.to_string()),
                sub: Some(OP_ID.to_string()),
                iat: Some(tunnelbana_core::util::now_secs()),
                exp: Some(tunnelbana_core::util::now_secs() + 3600),
                ..Default::default()
            };
            claims.extra.insert(
                "trust_chain".into(),
                serde_json::json!([
                    tunnelbana_oidc::federation::build_entity_configuration(
                        &self.op_key,
                        OP_ID,
                        &self.op_key.to_public_jwks(),
                        &[TA_ID.to_string()],
                        serde_json::json!({ "openid_provider": {} }),
                        &[],
                        3600,
                    )
                    .unwrap(),
                    subordinate_statement(&self.ta_key, TA_ID, OP_ID, &self.op_key.to_public_jwks()),
                    entity_configuration(
                        &self.ta_key,
                        TA_ID,
                        self.config.ta_ec_subject,
                        &self.ta_key.to_public_jwks(),
                        &[],
                        serde_json::json!({
                            "federation_entity": {
                                "federation_resolve_endpoint": format!("{TA_ID}/resolve")
                            }
                        }),
                    )
                ]),
            );
            claims.extra.insert(
                "metadata".into(),
                serde_json::json!({
                    "openid_provider": provider_metadata(&self.op_key, self.config.key_distribution)
                }),
            );
            tunnelbana_oidc::jwt::sign(
                &self.ta_key,
                &claims,
                Some(tunnelbana_oidc::federation::RESOLVE_RESPONSE_TYP),
            )
            .unwrap()
        } else if url == format!("{OP_ID}/signed-jwks") {
            signed_jwks(&self.op_key, OP_ID)
        } else if url == format!("{OP_ID}/jwks") {
            return Ok(HttpFetchResponse {
                status: 200,
                body: self.op_key.to_public_jwks().to_json().unwrap().into_bytes(),
                content_type: Some("application/json".into()),
            });
        } else if url.starts_with(&format!("{TA_ID}/collection")) {
            // The trust anchor's OP listing for discovery.
            serde_json::to_string(&serde_json::json!({
                "entities": [
                    {
                        "entity_id": OP_ID,
                        "entity_types": ["openid_provider", "federation_entity"],
                        "ui_infos": {
                            "openid_provider": { "display_name": "The Test OP", "logo_uri": null }
                        }
                    },
                    {
                        "entity_id": "https://other-op.example.org",
                        "entity_types": ["openid_provider"],
                        "ui_infos": {}
                    },
                    {
                        "entity_id": "https://untyped-op.example.org",
                        "ui_infos": {
                            "openid_provider": { "display_name": "Untyped OP", "logo_uri": null }
                        }
                    }
                ]
            }))
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
            content_type: Some(content_type_for(url).into()),
        })
    }

    async fn post_form(
        &self,
        url: &str,
        form: &[(String, String)],
        _headers: &[(String, String)],
    ) -> CoreResult<HttpFetchResponse> {
        if url != format!("{OP_ID}/token") {
            return Ok(HttpFetchResponse {
                status: 404,
                body: Vec::new(),
                content_type: None,
            });
        }
        *self.token_form.lock().unwrap() = form.to_vec();

        // The OP verifies the RP's private_key_jwt assertion against the RP
        // keys published in its entity configuration.
        let assertion = form
            .iter()
            .find(|(k, _)| k == "client_assertion")
            .map(|(_, v)| v.clone())
            .expect("client_assertion in token request");
        let validation = jose_rs::jwt::Validation::new()
            .with_issuer(RP_ENTITY)
            .with_audience(format!("{OP_ID}/token"));
        tunnelbana_oidc::jwt::verify_with_jwks(&self.rp_pub_jwks, &assertion, &validation)
            .expect("client assertion must verify against the RP jwks");

        // Issue an id_token for the RP, echoing the captured nonce.
        let now = tunnelbana_core::util::now_secs();
        let mut claims = jose_rs::jwt::Claims {
            iss: Some(OP_ID.to_string()),
            sub: Some("fed-user-1".to_string()),
            aud: Some(jose_rs::jwt::Audience::Single(RP_ENTITY.to_string())),
            iat: Some(now),
            exp: Some(now + 600),
            ..Default::default()
        };
        if let Some(nonce) = self.nonce.lock().unwrap().clone() {
            claims
                .extra
                .insert("nonce".into(), serde_json::json!(nonce));
        }
        claims
            .extra
            .insert("email".into(), serde_json::json!("fed@example.org"));
        let id_token = tunnelbana_oidc::jwt::sign(&self.op_key, &claims, None).unwrap();

        let body = serde_json::json!({
            "access_token": "at-123",
            "token_type": "Bearer",
            "id_token": id_token,
        });
        Ok(HttpFetchResponse {
            status: 200,
            body: serde_json::to_vec(&body).unwrap(),
            content_type: Some("application/json".into()),
        })
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

fn content_type_for(url: &str) -> &'static str {
    if url.starts_with(&format!("{TA_ID}/resolve")) {
        "application/resolve-response+jwt"
    } else if url == format!("{OP_ID}/signed-jwks") {
        "application/jwk-set+jwt"
    } else if url.starts_with(&format!("{TA_ID}/collection")) {
        "application/json"
    } else {
        "application/entity-statement+jwt"
    }
}

fn provider_metadata(op_key: &SigningKey, key_distribution: KeyDistribution) -> serde_json::Value {
    let mut metadata = serde_json::json!({
        "issuer": OP_ID,
        "authorization_endpoint": format!("{OP_ID}/authorize"),
        "token_endpoint": format!("{OP_ID}/token"),
        "client_registration_types_supported": ["automatic"]
    });
    let object = metadata.as_object_mut().unwrap();
    match key_distribution {
        KeyDistribution::Inline => {
            object.insert("jwks".into(), serde_json::to_value(op_key.to_public_jwks()).unwrap());
        }
        KeyDistribution::SignedJwksUri => {
            object.insert(
                "signed_jwks_uri".into(),
                serde_json::Value::String(format!("{OP_ID}/signed-jwks")),
            );
        }
        KeyDistribution::BadInlineWithJwksUri => {
            object.insert("jwks".into(), serde_json::Value::String("not-a-jwks".into()));
            object.insert(
                "jwks_uri".into(),
                serde_json::Value::String(format!("{OP_ID}/jwks")),
            );
        }
    }
    metadata
}

fn entity_configuration(
    key: &SigningKey,
    issuer: &str,
    subject: &str,
    jwks: &jose_rs::jwk::JwkSet,
    authority_hints: &[String],
    metadata: serde_json::Value,
) -> String {
    if issuer == subject {
        return tunnelbana_oidc::federation::build_entity_configuration(
            key,
            issuer,
            jwks,
            authority_hints,
            metadata,
            &[],
            3600,
        )
        .unwrap();
    }

    let mut claims = jose_rs::jwt::Claims {
        iss: Some(issuer.to_string()),
        sub: Some(subject.to_string()),
        iat: Some(tunnelbana_core::util::now_secs()),
        exp: Some(tunnelbana_core::util::now_secs() + 3600),
        ..Default::default()
    };
    claims.extra.insert("jwks".into(), serde_json::to_value(jwks).unwrap());
    if !authority_hints.is_empty() {
        claims.extra.insert(
            "authority_hints".into(),
            serde_json::to_value(authority_hints).unwrap(),
        );
    }
    claims.extra.insert("metadata".into(), metadata);
    tunnelbana_oidc::jwt::sign(
        key,
        &claims,
        Some(tunnelbana_oidc::federation::ENTITY_STATEMENT_TYP),
    )
    .unwrap()
}

fn subordinate_statement(
    key: &SigningKey,
    issuer: &str,
    subject: &str,
    subject_jwks: &jose_rs::jwk::JwkSet,
) -> String {
    let mut claims = jose_rs::jwt::Claims {
        iss: Some(issuer.to_string()),
        sub: Some(subject.to_string()),
        iat: Some(tunnelbana_core::util::now_secs()),
        exp: Some(tunnelbana_core::util::now_secs() + 3600),
        ..Default::default()
    };
    claims.extra.insert(
        "jwks".into(),
        serde_json::to_value(subject_jwks).unwrap(),
    );
    tunnelbana_oidc::jwt::sign(
        key,
        &claims,
        Some(tunnelbana_oidc::federation::ENTITY_STATEMENT_TYP),
    )
    .unwrap()
}

fn signed_jwks(key: &SigningKey, subject: &str) -> String {
    let mut claims = jose_rs::jwt::Claims {
        iss: Some(subject.to_string()),
        sub: Some(subject.to_string()),
        iat: Some(tunnelbana_core::util::now_secs()),
        exp: Some(tunnelbana_core::util::now_secs() + 3600),
        ..Default::default()
    };
    claims.extra.insert(
        "keys".into(),
        serde_json::to_value(key.to_public_jwks().keys).unwrap(),
    );
    tunnelbana_oidc::jwt::sign(
        key,
        &claims,
        Some(tunnelbana_oidc::federation::JWK_SET_TYP),
    )
    .unwrap()
}

fn build_backend(http: Arc<dyn HttpClient>, fed_jwk: serde_json::Value, ta_pub: serde_json::Value) -> Box<dyn Backend> {
    let config = serde_json::json!({
        "op_entity_id": OP_ID,
        "scope": "openid email",
        "federation": {
            "signing_jwk": fed_jwk,
            "signing_algorithm": "ES256",
            "signing_key_id": "rp-fed-1",
            "authority_hints": [TA_ID],
            "organization_name": "Tunnelbana Test RP",
            "trust_anchor": [ { "entity_id": TA_ID, "keys": [ ta_pub ] } ]
        }
    });
    let bx = BuildContext {
        name: "OIDFedRP".to_string(),
        base_url: "https://proxy.example.com".to_string(),
        config,
        attribute_mapper: mapper(),
        http_client: http,
        secret: "fed-rp-secret".to_string(),
        previous_secrets: Vec::new(),
    };
    tunnelbana_plugins::federation_backend::FederationBackend::build(&bx).unwrap()
}

fn build_discovery_backend(http: Arc<dyn HttpClient>, fed_jwk: serde_json::Value, ta_pub: serde_json::Value) -> Box<dyn Backend> {
    let config = serde_json::json!({
        "scope": "openid email",
        "discovery": {
            "enable": true,
            "collection_endpoint": format!("{TA_ID}/collection"),
            "page_title": "Pick your IdP"
        },
        "federation": {
            "signing_jwk": fed_jwk,
            "signing_algorithm": "ES256",
            "signing_key_id": "rp-fed-1",
            "authority_hints": [TA_ID],
            "organization_name": "Tunnelbana Test RP",
            "trust_anchor": [ { "entity_id": TA_ID, "keys": [ ta_pub ] } ]
        }
    });
    let bx = BuildContext {
        name: "OIDFedRP".to_string(),
        base_url: "https://proxy.example.com".to_string(),
        config,
        attribute_mapper: mapper(),
        http_client: http,
        secret: "fed-rp-secret".to_string(),
        previous_secrets: Vec::new(),
    };
    tunnelbana_plugins::federation_backend::FederationBackend::build(&bx).unwrap()
}

fn ctx() -> Context {
    Context::new(HttpRequestData::default(), State::new())
}

fn qp(url: &str, key: &str) -> Option<String> {
    let (_, q) = url.split_once('?')?;
    form_urlencoded::parse(q.as_bytes())
        .find(|(k, _)| k == key)
        .map(|(_, v)| v.into_owned())
}

fn location(resp: &Response) -> String {
    resp.headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("location"))
        .map(|(_, v)| v.clone())
        .expect("location")
}

fn network(rp_fed_key: &SigningKey) -> (Arc<MockNetwork>, serde_json::Value, serde_json::Value) {
    network_with(rp_fed_key, NetworkConfig::default())
}

fn network_with(
    rp_fed_key: &SigningKey,
    config: NetworkConfig,
) -> (Arc<MockNetwork>, serde_json::Value, serde_json::Value) {
    let ta_key = ec_key("ta-1");
    let op_key = ec_key("op-1");
    let ta_pub: serde_json::Value =
        serde_json::from_str(&ta_key.public_jwk().to_json().unwrap()).unwrap();
    let fed_jwk: serde_json::Value =
        serde_json::from_str(&rp_fed_key.jwk.to_json().unwrap()).unwrap();
    let net = Arc::new(MockNetwork {
        ta_key,
        op_key,
        rp_pub_jwks: rp_fed_key.to_public_jwks(),
        config,
        nonce: Mutex::new(None),
        token_form: Mutex::new(Vec::new()),
    });
    (net, fed_jwk, ta_pub)
}

#[tokio::test]
async fn rp_entity_configuration_is_served_and_self_signed() {
    let rp_fed_key = ec_key("rp-fed-1");
    let (net, fed_jwk, ta_pub) = network(&rp_fed_key);
    let backend = build_backend(net, fed_jwk, ta_pub);

    let action = backend
        .handle_endpoint(&mut ctx(), "entity_configuration")
        .await
        .unwrap();
    let BackendAction::Respond(resp) = action else {
        panic!("expected a direct response");
    };
    assert_eq!(resp.status, 200);

    let jwt = String::from_utf8(resp.body).unwrap();
    let stmt = tunnelbana_oidc::federation::verify_self_signed(&jwt).unwrap();
    assert_eq!(stmt.iss(), Some(RP_ENTITY));
    assert_eq!(stmt.sub(), Some(RP_ENTITY));
    assert_eq!(stmt.authority_hints(), vec![TA_ID.to_string()]);

    let rp_meta = stmt.metadata("openid_relying_party").expect("rp metadata");
    assert_eq!(
        rp_meta["redirect_uris"],
        serde_json::json!([format!("{RP_ENTITY}/callback")])
    );
    assert_eq!(
        rp_meta["client_registration_types"],
        serde_json::json!(["automatic"])
    );
    assert_eq!(rp_meta["token_endpoint_auth_method"], "private_key_jwt");
    assert!(rp_meta.get("jwks").is_some(), "client keys must be published");
}

#[tokio::test]
async fn full_code_flow_via_resolved_op() {
    let rp_fed_key = ec_key("rp-fed-1");
    let (net, fed_jwk, ta_pub) = network(&rp_fed_key);
    let http: Arc<dyn HttpClient> = net.clone();
    let backend = build_backend(http, fed_jwk, ta_pub);

    // start_auth: the backend resolves the OP via the TA and redirects to its
    // authorization endpoint with client_id = the RP entity id and PKCE.
    let mut c = ctx();
    let resp = backend
        .start_auth(&mut c, InternalData::request("https://sp.example"))
        .await
        .unwrap();
    assert_eq!(resp.status, 302);
    let url = location(&resp);
    assert!(url.starts_with(&format!("{OP_ID}/authorize?")), "got {url}");
    assert_eq!(qp(&url, "client_id").as_deref(), Some(RP_ENTITY));
    assert_eq!(qp(&url, "response_type").as_deref(), Some("code"));
    assert!(qp(&url, "code_challenge").is_some(), "PKCE expected");
    let state = qp(&url, "state").expect("state");
    let nonce = qp(&url, "nonce").expect("nonce");

    // The OP (mock) will echo the nonce into the id_token.
    *net.nonce.lock().unwrap() = Some(nonce);

    // Callback: code exchange with private_key_jwt, id_token verified against
    // the trust-chain-delivered OP jwks, claims mapped to internal attributes.
    c.request.query.insert("state".into(), state);
    c.request.query.insert("code".into(), "authcode-1".into());
    let action = backend.handle_endpoint(&mut c, "callback").await.unwrap();
    let BackendAction::AuthResponse(data) = action else {
        panic!("expected an auth response");
    };
    assert_eq!(data.subject_id.as_deref(), Some("fed-user-1"));
    assert_eq!(data.subject_type, SubjectType::Pairwise);
    assert_eq!(data.auth_info.issuer.as_deref(), Some(OP_ID));
    assert_eq!(data.attr_first("mail"), Some("fed@example.org"));

    // The token request used PKCE and automatic registration.
    let form = net.token_form.lock().unwrap().clone();
    let get = |k: &str| form.iter().find(|(fk, _)| fk == k).map(|(_, v)| v.clone());
    assert_eq!(get("client_id").as_deref(), Some(RP_ENTITY));
    assert!(get("code_verifier").is_some());
    assert_eq!(
        get("client_assertion_type").as_deref(),
        Some("urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
    );
}

#[tokio::test]
async fn callback_rejects_state_mismatch_and_wrong_nonce() {
    let rp_fed_key = ec_key("rp-fed-1");
    let (net, fed_jwk, ta_pub) = network(&rp_fed_key);
    let http: Arc<dyn HttpClient> = net.clone();
    let backend = build_backend(http, fed_jwk, ta_pub);

    let mut c = ctx();
    let resp = backend
        .start_auth(&mut c, InternalData::request("https://sp.example"))
        .await
        .unwrap();
    let url = location(&resp);
    let state = qp(&url, "state").unwrap();

    // Wrong state is rejected before any token exchange.
    c.request.query.insert("state".into(), "forged".into());
    c.request.query.insert("code".into(), "authcode-1".into());
    assert!(backend.handle_endpoint(&mut c, "callback").await.is_err());

    // Right state but an id_token carrying the wrong nonce is rejected.
    *net.nonce.lock().unwrap() = Some("not-the-real-nonce".into());
    c.request.query.insert("state".into(), state);
    let err = backend.handle_endpoint(&mut c, "callback").await;
    assert!(err.is_err(), "nonce mismatch must fail id_token verification");
}

#[tokio::test]
async fn build_requires_trust_anchor() {
    let rp_fed_key = ec_key("rp-fed-1");
    let fed_jwk: serde_json::Value =
        serde_json::from_str(&rp_fed_key.jwk.to_json().unwrap()).unwrap();
    let config = serde_json::json!({
        "op_entity_id": OP_ID,
        "federation": {
            "signing_jwk": fed_jwk,
            "signing_algorithm": "ES256",
            "trust_anchor": []
        }
    });
    let bx = BuildContext {
        name: "OIDFedRP".to_string(),
        base_url: "https://proxy.example.com".to_string(),
        config,
        attribute_mapper: mapper(),
        http_client: Arc::new(tunnelbana_core::plugin::NullHttpClient),
        secret: "s".to_string(),
        previous_secrets: Vec::new(),
    };
    assert!(tunnelbana_plugins::federation_backend::FederationBackend::build(&bx).is_err());
}

#[tokio::test]
async fn discovery_renders_selection_page_then_starts_auth_with_choice() {
    let rp_fed_key = ec_key("rp-fed-1");
    let (net, fed_jwk, ta_pub) = network(&rp_fed_key);
    let http: Arc<dyn HttpClient> = net.clone();
    let backend = build_discovery_backend(http, fed_jwk, ta_pub);

    // start_auth in discovery mode renders the OP-selection page (200 HTML),
    // not a redirect.
    let mut c = ctx();
    let page = backend
        .start_auth(&mut c, InternalData::request("https://sp.example"))
        .await
        .unwrap();
    assert_eq!(page.status, 200);
    let html = String::from_utf8(page.body.clone()).unwrap();
    assert!(html.contains("Pick your IdP"), "custom page title");
    assert!(html.contains("The Test OP"), "OP display name from collection");
    assert!(html.contains(OP_ID), "OP entity id present");
    assert!(
        html.contains(r#"action="/OIDFedRP/disco""#),
        "form posts back to the disco endpoint"
    );

    // The user selects the OP: POST entity_id to the disco endpoint -> 302 to
    // the resolved OP's authorization endpoint.
    let mut c = ctx();
    c.request.form.insert("entity_id".into(), OP_ID.into());
    let action = backend.handle_endpoint(&mut c, "disco").await.unwrap();
    let BackendAction::Respond(resp) = action else {
        panic!("expected a redirect response");
    };
    assert_eq!(resp.status, 302);
    let url = location(&resp);
    assert!(url.starts_with(&format!("{OP_ID}/authorize?")), "got {url}");
    assert_eq!(qp(&url, "client_id").as_deref(), Some(RP_ENTITY));
    assert!(qp(&url, "code_challenge").is_some(), "PKCE expected");

    // The chosen OP and PKCE/state were persisted for the callback.
    let nonce = qp(&url, "nonce").unwrap();
    *net.nonce.lock().unwrap() = Some(nonce);
    c.request.query.insert("state".into(), qp(&url, "state").unwrap());
    c.request.query.insert("code".into(), "authcode-1".into());
    let action = backend.handle_endpoint(&mut c, "callback").await.unwrap();
    let BackendAction::AuthResponse(data) = action else {
        panic!("expected auth response after discovery selection");
    };
    assert_eq!(data.subject_id.as_deref(), Some("fed-user-1"));
    assert_eq!(data.auth_info.issuer.as_deref(), Some(OP_ID));
}

#[tokio::test]
async fn discovery_rejects_unlisted_op_and_empty_selection() {
    let rp_fed_key = ec_key("rp-fed-1");
    let (net, fed_jwk, ta_pub) = network(&rp_fed_key);
    let http: Arc<dyn HttpClient> = net.clone();
    let backend = build_discovery_backend(http, fed_jwk, ta_pub);

    // Empty selection re-renders the page with a prompt.
    let mut c = ctx();
    let action = backend.handle_endpoint(&mut c, "disco").await.unwrap();
    let BackendAction::Respond(resp) = action else { panic!() };
    assert_eq!(resp.status, 200);
    assert!(String::from_utf8(resp.body).unwrap().contains("Please select"));

    // An entity id not in the collection is refused (no resolution attempted).
    let mut c = ctx();
    c.request
        .form
        .insert("entity_id".into(), "https://evil.example/op".into());
    let action = backend.handle_endpoint(&mut c, "disco").await.unwrap();
    let BackendAction::Respond(resp) = action else { panic!() };
    assert_eq!(resp.status, 200);
    assert!(String::from_utf8(resp.body).unwrap().contains("Unknown identity provider"));
}

#[tokio::test]
async fn build_rejects_op_entity_id_and_discovery_together() {
    let rp_fed_key = ec_key("rp-fed-1");
    let fed_jwk: serde_json::Value =
        serde_json::from_str(&rp_fed_key.jwk.to_json().unwrap()).unwrap();
    let ta_pub: serde_json::Value = fed_jwk.clone();
    let bx = |config| BuildContext {
        name: "OIDFedRP".to_string(),
        base_url: "https://proxy.example.com".to_string(),
        config,
        attribute_mapper: mapper(),
        http_client: Arc::new(tunnelbana_core::plugin::NullHttpClient),
        secret: "s".to_string(),
        previous_secrets: Vec::new(),
    };
    let fed = serde_json::json!({
        "signing_jwk": fed_jwk,
        "signing_algorithm": "ES256",
        "trust_anchor": [ { "entity_id": TA_ID, "keys": [ ta_pub ] } ]
    });

    // Both set -> error.
    let both = serde_json::json!({
        "op_entity_id": OP_ID,
        "discovery": { "enable": true, "collection_endpoint": format!("{TA_ID}/collection") },
        "federation": fed.clone()
    });
    assert!(tunnelbana_plugins::federation_backend::FederationBackend::build(&bx(both)).is_err());

    // Neither set -> error.
    let neither = serde_json::json!({ "federation": fed.clone() });
    assert!(tunnelbana_plugins::federation_backend::FederationBackend::build(&bx(neither)).is_err());

    // Discovery enabled without a collection endpoint -> error.
    let no_collection = serde_json::json!({
        "discovery": { "enable": true },
        "federation": fed
    });
    assert!(tunnelbana_plugins::federation_backend::FederationBackend::build(&bx(no_collection)).is_err());
}

#[tokio::test]
async fn start_auth_rejects_wrong_resolve_response_issuer() {
    let rp_fed_key = ec_key("rp-fed-1");
    let (net, fed_jwk, ta_pub) = network_with(
        &rp_fed_key,
        NetworkConfig {
            resolve_issuer: "https://resolver.example.org",
            ..Default::default()
        },
    );
    let http: Arc<dyn HttpClient> = net;
    let backend = build_backend(http, fed_jwk, ta_pub);

    let err = backend
        .start_auth(&mut ctx(), InternalData::request("https://sp.example"))
        .await;
    assert!(err.is_err(), "unexpected resolve response issuer must fail");
}

#[tokio::test]
async fn start_auth_rejects_non_self_issued_trust_anchor_configuration() {
    let rp_fed_key = ec_key("rp-fed-1");
    let (net, fed_jwk, ta_pub) = network_with(
        &rp_fed_key,
        NetworkConfig {
            ta_ec_subject: "https://wrong-ta.example.org",
            ..Default::default()
        },
    );
    let http: Arc<dyn HttpClient> = net;
    let backend = build_backend(http, fed_jwk, ta_pub);

    let err = backend
        .start_auth(&mut ctx(), InternalData::request("https://sp.example"))
        .await;
    assert!(err.is_err(), "trust anchor entity configuration must be self-issued");
}

#[tokio::test]
async fn full_code_flow_via_signed_jwks_uri() {
    let rp_fed_key = ec_key("rp-fed-1");
    let (net, fed_jwk, ta_pub) = network_with(
        &rp_fed_key,
        NetworkConfig {
            key_distribution: KeyDistribution::SignedJwksUri,
            ..Default::default()
        },
    );
    let http: Arc<dyn HttpClient> = net.clone();
    let backend = build_backend(http, fed_jwk, ta_pub);

    let mut c = ctx();
    let resp = backend
        .start_auth(&mut c, InternalData::request("https://sp.example"))
        .await
        .unwrap();
    let url = location(&resp);
    *net.nonce.lock().unwrap() = qp(&url, "nonce");
    c.request.query.insert("state".into(), qp(&url, "state").unwrap());
    c.request.query.insert("code".into(), "authcode-1".into());

    let action = backend.handle_endpoint(&mut c, "callback").await.unwrap();
    let BackendAction::AuthResponse(data) = action else { panic!() };
    assert_eq!(data.subject_id.as_deref(), Some("fed-user-1"));
}

#[tokio::test]
async fn malformed_inline_jwks_does_not_fall_back_to_jwks_uri() {
    let rp_fed_key = ec_key("rp-fed-1");
    let (net, fed_jwk, ta_pub) = network_with(
        &rp_fed_key,
        NetworkConfig {
            key_distribution: KeyDistribution::BadInlineWithJwksUri,
            ..Default::default()
        },
    );
    let http: Arc<dyn HttpClient> = net.clone();
    let backend = build_backend(http, fed_jwk, ta_pub);

    let mut c = ctx();
    let resp = backend
        .start_auth(&mut c, InternalData::request("https://sp.example"))
        .await
        .unwrap();
    let url = location(&resp);
    *net.nonce.lock().unwrap() = qp(&url, "nonce");
    c.request.query.insert("state".into(), qp(&url, "state").unwrap());
    c.request.query.insert("code".into(), "authcode-1".into());

    let err = backend.handle_endpoint(&mut c, "callback").await;
    assert!(err.is_err(), "invalid inline jwks must fail instead of downgrading");
}

#[tokio::test]
async fn discovery_ignores_entities_without_entity_types() {
    let rp_fed_key = ec_key("rp-fed-1");
    let (net, fed_jwk, ta_pub) = network(&rp_fed_key);
    let http: Arc<dyn HttpClient> = net;
    let backend = build_discovery_backend(http, fed_jwk, ta_pub);

    let mut c = ctx();
    c.request
        .form
        .insert("entity_id".into(), "https://untyped-op.example.org".into());
    let action = backend.handle_endpoint(&mut c, "disco").await.unwrap();
    let BackendAction::Respond(resp) = action else { panic!() };
    assert_eq!(resp.status, 200);
    assert!(String::from_utf8(resp.body).unwrap().contains("Unknown identity provider"));
}
