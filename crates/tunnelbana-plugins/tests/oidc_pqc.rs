//! PQC code flow through real OP and RP plugins, with HTTP dispatched locally.

mod pqc;

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use serde_json::{json, Value};
use tunnelbana_core::attributes::AttributeMapper;
use tunnelbana_core::context::Context;
use tunnelbana_core::error::Result;
use tunnelbana_core::http::{HttpClient, HttpFetchResponse, HttpRequestData, Response};
use tunnelbana_core::internal::InternalData;
use tunnelbana_core::plugin::{
    BackendAction, BuildContext, Frontend, FrontendAction, NullHttpClient,
};
use tunnelbana_core::state::State;

const ISSUER: &str = "https://op.example/OP";
const REDIRECT: &str = "https://rp.example/RP/callback";

/// Construct a plugin with isolated state and an empty attribute mapping.
fn build_context(
    name: &str,
    base_url: &str,
    config: Value,
    http: Arc<dyn HttpClient>,
) -> BuildContext {
    BuildContext {
        name: name.into(),
        base_url: base_url.into(),
        config,
        attribute_mapper: Arc::new(AttributeMapper::from_toml("").unwrap()),
        http_client: http,
        secret: "pqc-test-secret".into(),
        previous_secrets: Vec::new(),
    }
}

/// Build either OP with an AKP signing key and an explicitly registered RP.
fn frontend(federation: bool, key: &jose_rs::jwk::Jwk) -> Box<dyn Frontend> {
    let mut config = json!({
        "signing_jwk": key,
        "signing_algorithm": key.alg,
        "clients": [{
            "client_id": "rp", "redirect_uris": [REDIRECT],
            "response_types": ["code", "code id_token", "id_token token"],
            "grant_types": ["authorization_code"],
            "token_endpoint_auth_method": "none"
        }]
    });
    if federation {
        config["federation"] = json!({
            "signing_jwk": key,
            "signing_algorithm": key.alg,
            "authority_hints": ["https://ta.example"],
            "trust_anchor": [{"entity_id": "https://ta.example", "keys": [key.to_public_jwk()]}]
        });
    }
    let bx = build_context("OP", "https://op.example", config, Arc::new(NullHttpClient));
    if federation {
        tunnelbana_plugins::federation_frontend::FederationFrontend::build(&bx).unwrap()
    } else {
        tunnelbana_plugins::oidc_frontend::OidcFrontend::build(&bx).unwrap()
    }
}

/// Dispatch discovery, JWKS, token and UserInfo requests to the real OP plugin.
/// Capture issued tokens so assertions check both the wire format and RP result.
struct LocalOp {
    frontend: Box<dyn Frontend>,
    tokens: Mutex<Option<Value>>,
}

impl LocalOp {
    /// Run a noninteractive endpoint without creating a network listener.
    async fn endpoint(&self, route: &str, request: HttpRequestData) -> Response {
        let mut ctx = Context::new(request, State::new());
        let FrontendAction::Respond(response) = self
            .frontend
            .handle_endpoint(&mut ctx, route)
            .await
            .unwrap()
        else {
            panic!("{route} must respond directly");
        };
        assert_eq!(
            response.status,
            200,
            "{}",
            String::from_utf8_lossy(&response.body)
        );
        response
    }
}

#[async_trait]
impl HttpClient for LocalOp {
    async fn get(&self, url: &str) -> Result<HttpFetchResponse> {
        let route = if url == format!("{ISSUER}/.well-known/openid-configuration") {
            "discovery"
        } else if url == format!("{ISSUER}/jwks") {
            "jwks"
        } else {
            panic!("unexpected URL {url}");
        };
        let response = self.endpoint(route, HttpRequestData::default()).await;
        Ok(HttpFetchResponse {
            status: response.status,
            body: response.body,
            content_type: Some("application/json".into()),
        })
    }

    async fn post_form(
        &self,
        url: &str,
        form: &[(String, String)],
        headers: &[(String, String)],
    ) -> Result<HttpFetchResponse> {
        let route = if url == format!("{ISSUER}/token") {
            "token"
        } else if url == format!("{ISSUER}/userinfo") {
            "userinfo"
        } else {
            panic!("unexpected URL {url}");
        };
        let response = self
            .endpoint(
                route,
                HttpRequestData {
                    method: "POST".into(),
                    form_pairs: form.to_vec(),
                    headers: headers
                        .iter()
                        .map(|(k, v)| (k.to_lowercase(), v.clone()))
                        .collect(),
                    ..Default::default()
                },
            )
            .await;
        if route == "token" {
            *self.tokens.lock().unwrap() = Some(serde_json::from_slice(&response.body).unwrap());
        }
        Ok(HttpFetchResponse {
            status: response.status,
            body: response.body,
            content_type: Some("application/json".into()),
        })
    }
}

/// Parse the redirect URL without discarding ordered authorization parameters.
fn redirect(response: &Response) -> url::Url {
    url::Url::parse(
        &response
            .headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("location"))
            .unwrap()
            .1,
    )
    .unwrap()
}

/// Every jose-rs PQC variant signs an ID token on both OPs and verifies on the
/// ordinary OIDC RP, while the default RS256 policy still rejects PQC tokens.
#[tokio::test]
async fn pqc_code_flow_between_real_plugins() {
    for key in pqc::signing_keys() {
        let algorithm = key.alg.as_deref().unwrap();
        for federation in [false, true] {
            let op = Arc::new(LocalOp {
                frontend: frontend(federation, &key),
                tokens: Mutex::new(None),
            });
            let metadata: Value = serde_json::from_slice(
                &op.get(&format!("{ISSUER}/.well-known/openid-configuration"))
                    .await
                    .unwrap()
                    .body,
            )
            .unwrap();
            assert_eq!(
                metadata["id_token_signing_alg_values_supported"],
                json!([algorithm])
            );
            let jwks: jose_rs::jwk::JwkSet =
                serde_json::from_slice(&op.get(&format!("{ISSUER}/jwks")).await.unwrap().body)
                    .unwrap();
            assert_eq!(jwks.keys.len(), 1);
            assert_eq!(jwks.keys[0].kty, "AKP");
            assert!(
                jwks.keys[0].priv_.is_none(),
                "JWKS must not expose a private seed"
            );

            for explicit_policy in [true, false] {
                let mut config = json!({
                    "issuer": ISSUER, "client_id": "rp", "scope": "openid",
                    "token_endpoint_auth_method": "none"
                });
                if explicit_policy {
                    config["id_token_signed_response_alg"] = json!(algorithm);
                }
                let backend = tunnelbana_plugins::oidc_backend::OidcBackend::build(&build_context(
                    "RP",
                    "https://rp.example",
                    config,
                    op.clone(),
                ))
                .unwrap();
                let mut rp_ctx = Context::new(HttpRequestData::default(), State::new());
                let request = backend
                    .start_auth(
                        &mut rp_ctx,
                        InternalData::request("https://downstream.example"),
                    )
                    .await
                    .unwrap();
                let mut op_ctx = Context::new(
                    HttpRequestData {
                        query_pairs: redirect(&request).query_pairs().into_owned().collect(),
                        ..Default::default()
                    },
                    State::new(),
                );
                assert!(matches!(
                    op.frontend
                        .handle_endpoint(&mut op_ctx, "authorization")
                        .await
                        .unwrap(),
                    FrontendAction::StartAuth { .. }
                ));
                let identity = InternalData {
                    subject_id: Some("pqc-user".into()),
                    ..Default::default()
                };
                let response = op
                    .frontend
                    .handle_authn_response(&mut op_ctx, identity)
                    .await
                    .unwrap();
                // The callback exchanges the real authorization code with PKCE.
                rp_ctx.request.query_pairs =
                    redirect(&response).query_pairs().into_owned().collect();
                rp_ctx.request.query = rp_ctx.request.query_pairs.iter().cloned().collect();
                let result = backend.handle_endpoint(&mut rp_ctx, "callback").await;
                if explicit_policy {
                    let BackendAction::AuthResponse(data) = result.unwrap() else {
                        panic!("expected verified authentication");
                    };
                    assert_eq!(data.subject_id.as_deref(), Some("pqc-user"));
                    assert_eq!(data.auth_info.issuer.as_deref(), Some(ISSUER));
                } else {
                    // Enabling crypto must never expand a registration's policy.
                    let error = result.err().expect("default RS256 must reject PQC");
                    assert!(
                        error.to_string().to_lowercase().contains("algorithm"),
                        "{error}"
                    );
                }
                let tokens = op.tokens.lock().unwrap().clone().unwrap();
                let jwt = tokens["id_token"].as_str().unwrap();
                let validation = jose_rs::jwt::Validation::new()
                    .with_issuer(ISSUER)
                    .with_audience("rp");
                let claims = jose_rs::jwt::decode_with_jwkset(&jwks, jwt, &validation).unwrap();
                assert_eq!(claims.sub.as_deref(), Some("pqc-user"));
                assert!(!claims.extra.contains_key("c_hash"));
                assert!(!claims.extra.contains_key("at_hash"));
            }

            // Grindvakt has no PQC c_hash/at_hash mapping. Preserve rejection of
            // responses that would otherwise require inventing such a mapping.
            for response_type in ["code id_token", "id_token token"] {
                let request = HttpRequestData {
                    query_pairs: [
                        ("client_id", "rp"),
                        ("redirect_uri", REDIRECT),
                        ("response_type", response_type),
                        ("scope", "openid"),
                        ("nonce", "pqc-nonce"),
                    ]
                    .into_iter()
                    .map(|(k, v)| (k.into(), v.into()))
                    .collect(),
                    ..Default::default()
                };
                let mut ctx = Context::new(request, State::new());
                let FrontendAction::Respond(response) = op
                    .frontend
                    .handle_endpoint(&mut ctx, "authorization")
                    .await
                    .unwrap()
                else {
                    panic!("unsupported flow must fail before authentication");
                };
                assert_eq!(response.status, 400);
                assert!(!response
                    .headers
                    .iter()
                    .any(|(k, _)| k.eq_ignore_ascii_case("location")));
                let error: Value = serde_json::from_slice(&response.body).unwrap();
                assert_eq!(error["error"], "unsupported_response_type");
                assert!(error.get("id_token").is_none());
            }
        }
    }
}
