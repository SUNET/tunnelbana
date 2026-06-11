//! OpenID Federation frontend — an OP that auto-registers federation RPs via
//! trust chains, serves its entity configuration, unpacks request objects
//! (RFC 9101) and accepts `private_key_jwt` (RFC 7523).
//!
//! Reproduces the behavior of the `satosa-federation` OpenIDFederationFrontend.

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

use async_trait::async_trait;
use jose_rs::jwk::JwkSet;
use serde::Deserialize;
use serde_json::Value;
use tunnelbana_core::attributes::AttributeMapper;
use tunnelbana_core::context::Context;
use tunnelbana_core::error::{Error, Result};
use tunnelbana_core::http::{HttpClient, Response};
use tunnelbana_core::internal::InternalData;
use tunnelbana_core::plugin::{BuildContext, Frontend, FrontendAction, Route};
use tunnelbana_oidc::client::{Client, ClientStore, InMemoryClientStore, AUTH_PRIVATE_KEY_JWT};
use tunnelbana_oidc::federation::{self, TrustAnchors};
use tunnelbana_oidc::metadata::ProviderMetadata;
use tunnelbana_oidc::oauth_error::{OAuthError, OAuthErrorCode};
use tunnelbana_oidc::provider::{Provider, TokenLifetimes};
use tunnelbana_oidc::request::AuthorizationRequest;
use tunnelbana_oidc::tokens::TokenCodec;

use crate::keyload::load_signing_key;

const AUTHZ_KEY: &str = "authz_request";

#[derive(Debug, Deserialize)]
struct TrustAnchorConfig {
    entity_id: String,
    /// Pre-distributed verification keys (JWK objects).
    keys: Vec<Value>,
}

#[derive(Debug, Deserialize)]
struct FederationConfig {
    #[serde(default)]
    signing_key_path: Option<String>,
    #[serde(default)]
    signing_jwk: Option<Value>,
    #[serde(default)]
    signing_jwk_path: Option<String>,
    #[serde(default)]
    signing_algorithm: Option<String>,
    #[serde(default)]
    signing_key_id: Option<String>,
    #[serde(default)]
    authority_hints: Vec<String>,
    #[serde(default)]
    trust_anchor: Vec<TrustAnchorConfig>,
    #[serde(default = "default_ec_lifetime")]
    entity_configuration_lifetime: u64,
    #[serde(default = "default_rp_cache_ttl")]
    rp_cache_ttl: u64,
    #[serde(default)]
    organization_name: Option<String>,
    #[serde(default)]
    organization_uri: Option<String>,
    #[serde(default)]
    trust_marks: Vec<Value>,
}

fn default_ec_lifetime() -> u64 {
    86400
}
fn default_rp_cache_ttl() -> u64 {
    3600
}

#[derive(Debug, Deserialize)]
struct FederationFrontendConfig {
    /// Federation entity identifier (the `iss`/`sub` of the entity
    /// configuration and the OP `issuer`). Defaults to the module base
    /// (`<base_url>/<name>`). Set this to publish the OP at a stable identifier
    /// — e.g. the bare host `https://op.example.com` — while the protocol
    /// endpoints stay mounted under `<base_url>/<name>`. The entity
    /// configuration must then be reachable at `<entity_id>/.well-known/
    /// openid-federation` (typically via a reverse-proxy rewrite to
    /// `<base_url>/<name>/.well-known/openid-federation`).
    #[serde(default)]
    entity_id: Option<String>,
    // OP id_token signing key (reuses the OIDC frontend fields).
    #[serde(default)]
    signing_key_path: Option<String>,
    #[serde(default)]
    signing_jwk: Option<Value>,
    #[serde(default)]
    signing_jwk_path: Option<String>,
    #[serde(default)]
    signing_algorithm: Option<String>,
    #[serde(default)]
    signing_key_id: Option<String>,
    #[serde(default)]
    clients: Vec<Client>,
    #[serde(default)]
    code_ttl: Option<u64>,
    #[serde(default)]
    access_token_ttl: Option<u64>,
    #[serde(default)]
    id_token_ttl: Option<u64>,
    federation: FederationConfig,
}

pub struct FederationFrontend {
    name: String,
    issuer: String,
    /// Base URL the protocol endpoints are mounted under (`<base_url>/<name>`).
    /// Distinct from `issuer` when a custom `entity_id` is configured.
    endpoint_base: String,
    provider: Provider,
    clients: Arc<InMemoryClientStore>,
    mapper: Arc<AttributeMapper>,
    http: Arc<dyn HttpClient>,
    // Federation state.
    fed_key: tunnelbana_core::keys::SigningKey,
    authority_hints: Vec<String>,
    trust_anchors: TrustAnchors,
    ec_lifetime: u64,
    rp_cache_ttl: u64,
    organization_name: Option<String>,
    organization_uri: Option<String>,
    trust_marks: Vec<Value>,
}

impl FederationFrontend {
    pub fn build(bx: &BuildContext) -> Result<Box<dyn Frontend>> {
        let cfg: FederationFrontendConfig = bx.parse_config()?;
        let module_base = bx.module_base();
        // The entity identifier (iss/sub of the entity configuration, and the OP
        // issuer) defaults to the module base but may be overridden — e.g. to the
        // bare host — so the OP keeps a stable federation identity independent of
        // where its endpoints are mounted.
        let issuer = cfg.entity_id.clone().unwrap_or_else(|| module_base.clone());

        let op_key = load_signing_key(
            cfg.signing_jwk.as_ref(),
            cfg.signing_key_path.as_deref(),
            cfg.signing_jwk_path.as_deref(),
            cfg.signing_algorithm.as_deref(),
            cfg.signing_key_id.as_deref(),
        )?;
        let fed = &cfg.federation;
        let fed_key = load_signing_key(
            fed.signing_jwk.as_ref(),
            fed.signing_key_path.as_deref(),
            fed.signing_jwk_path.as_deref(),
            fed.signing_algorithm.as_deref(),
            fed.signing_key_id.as_deref(),
        )?;

        let mut metadata = ProviderMetadata::new(issuer.clone(), &module_base);
        metadata.id_token_signing_alg_values_supported = vec![op_key.alg.as_str().to_string()];
        // Federation OP advertises automatic registration + request objects.
        metadata.extra.insert(
            "client_registration_types_supported".into(),
            serde_json::json!(["automatic"]),
        );
        metadata.request_parameter_supported = true;

        let store = Arc::new(InMemoryClientStore::with_clients(cfg.clients));
        let dyn_store: Arc<dyn tunnelbana_oidc::client::ClientStore> = store.clone();
        let codec = TokenCodec::new(&bx.secret).with_previous_secrets(&bx.previous_secrets);
        let lifetimes = TokenLifetimes {
            code_ttl: cfg.code_ttl.unwrap_or(600),
            access_token_ttl: cfg.access_token_ttl.unwrap_or(3600),
            id_token_ttl: cfg.id_token_ttl.unwrap_or(3600),
        };
        let provider = Provider::new(metadata, op_key, dyn_store, codec, lifetimes);

        // Build trust anchors map.
        let mut trust_anchors: TrustAnchors = HashMap::new();
        for ta in &fed.trust_anchor {
            let jwks = JwkSet {
                keys: ta
                    .keys
                    .iter()
                    .map(|k| serde_json::from_value(k.clone()))
                    .collect::<std::result::Result<_, _>>()
                    .map_err(|e| Error::Config(format!("trust anchor {}: {e}", ta.entity_id)))?,
            };
            trust_anchors.insert(ta.entity_id.clone(), jwks);
        }

        Ok(Box::new(FederationFrontend {
            name: bx.name.clone(),
            issuer,
            endpoint_base: module_base,
            provider,
            clients: store,
            mapper: bx.attribute_mapper.clone(),
            http: bx.http_client.clone(),
            fed_key,
            authority_hints: fed.authority_hints.clone(),
            trust_anchors,
            ec_lifetime: fed.entity_configuration_lifetime,
            rp_cache_ttl: fed.rp_cache_ttl,
            organization_name: fed.organization_name.clone(),
            organization_uri: fed.organization_uri.clone(),
            trust_marks: fed.trust_marks.clone(),
        }))
    }

    fn route(&self, suffix: &str) -> String {
        format!("{}/{}", self.name, suffix)
    }

    /// Build and sign the federation entity configuration.
    fn entity_configuration(&self) -> Result<String> {
        let mut openid_provider = self.provider.discovery_document();
        if let Some(obj) = openid_provider.as_object_mut() {
            obj.insert(
                "client_registration_types_supported".into(),
                serde_json::json!(["automatic"]),
            );
        }

        let mut federation_entity = serde_json::Map::new();
        if let Some(n) = &self.organization_name {
            federation_entity.insert("organization_name".into(), Value::String(n.clone()));
        }
        if let Some(u) = &self.organization_uri {
            federation_entity.insert("homepage_uri".into(), Value::String(u.clone()));
        }

        let metadata = serde_json::json!({
            "openid_provider": openid_provider,
            "federation_entity": Value::Object(federation_entity),
        });

        federation::build_entity_configuration(
            &self.fed_key,
            &self.issuer,
            &self.fed_key.to_public_jwks(),
            &self.authority_hints,
            metadata,
            &self.trust_marks,
            self.ec_lifetime,
        )
    }

    /// Resolve and register an unknown RP via the trust anchors.
    async fn auto_register(&self, client_id: &str) -> Result<Client> {
        let resolved =
            federation::resolve_via_trust_anchors(&self.http, client_id, &self.trust_anchors)
                .await?;
        let rp_meta = resolved
            .metadata
            .get("openid_relying_party")
            .ok_or_else(|| Error::Authn("resolved metadata has no openid_relying_party".into()))?;

        let redirect_uris = rp_meta
            .get("redirect_uris")
            .and_then(|v| v.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|x| x.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();
        let jwks: Option<JwkSet> = rp_meta
            .get("jwks")
            .and_then(|v| serde_json::from_value(v.clone()).ok());
        let client_name = rp_meta
            .get("client_name")
            .and_then(|v| v.as_str())
            .map(String::from);

        let client = Client {
            client_id: client_id.to_string(),
            client_secret: None,
            redirect_uris,
            response_types: vec!["code".to_string()],
            grant_types: vec!["authorization_code".to_string()],
            token_endpoint_auth_method: AUTH_PRIVATE_KEY_JWT.to_string(),
            jwks,
            scope: rp_meta
                .get("scope")
                .and_then(|v| v.as_str())
                .map(String::from),
            subject_type: rp_meta
                .get("subject_type")
                .and_then(|v| v.as_str())
                .unwrap_or("pairwise")
                .to_string(),
            client_name,
        };
        self.clients
            .put_with_ttl(client.clone(), self.rp_cache_ttl)
            .await;
        tracing::info!(client_id = %client_id, "auto-registered federation RP");
        Ok(client)
    }

    /// Unpack and verify an RFC 9101 request object, merging its claims into the
    /// flat parameter map.
    async fn unpack_request_object(
        &self,
        params: &mut BTreeMap<String, String>,
        client: &Client,
    ) -> Result<()> {
        let Some(request_jwt) = params.remove("request") else {
            return Ok(());
        };
        let jwks = client
            .jwks
            .as_ref()
            .ok_or_else(|| Error::Authn("client has no keys to verify request object".into()))?;
        let validation = jose_rs::jwt::Validation::new();
        let claims = tunnelbana_oidc::jwt::verify_with_jwks(jwks, &request_jwt, &validation)?;

        // Merge the request object's parameters as plain values.
        let merged = serde_json::to_value(&claims.extra).unwrap_or_default();
        if let Some(obj) = merged.as_object() {
            for (k, v) in obj {
                if let Some(s) = v.as_str() {
                    params.insert(k.clone(), s.to_string());
                }
            }
        }
        Ok(())
    }

    fn store_authz_request(&self, ctx: &mut Context, req: &AuthorizationRequest) -> Result<()> {
        let value = serde_json::to_value(req)?;
        ctx.state.set_value(&self.name, AUTHZ_KEY, value);
        Ok(())
    }

    fn load_authz_request(&self, ctx: &Context) -> Option<AuthorizationRequest> {
        let value = ctx.state.get_value(&self.name, AUTHZ_KEY)?;
        serde_json::from_value(value.clone()).ok()
    }

    async fn handle_authorization(&self, ctx: &mut Context) -> Result<FrontendAction> {
        let mut params = ctx.request.query.clone();

        // The client_id is required to look up keys (for request objects) and to
        // auto-register.
        let client_id = params
            .get("client_id")
            .cloned()
            .ok_or_else(|| Error::BadRequest("missing client_id".into()))?;

        // Ensure the client is known (auto-register from the federation if not).
        let client = match self.provider.clients.get(&client_id).await {
            Some(c) => c,
            None => match self.auto_register(&client_id).await {
                Ok(c) => c,
                Err(e) => {
                    return Ok(FrontendAction::Respond(
                        OAuthError::new(OAuthErrorCode::InvalidRequest, e.to_string())
                            .to_response(),
                    ))
                }
            },
        };

        // Unpack a request object if present.
        if params.contains_key("request") {
            if let Err(e) = self.unpack_request_object(&mut params, &client).await {
                return Ok(FrontendAction::Respond(
                    OAuthError::new(OAuthErrorCode::InvalidRequest, e.to_string()).to_response(),
                ));
            }
        }

        let req = match AuthorizationRequest::from_params(&params) {
            Ok(r) => r,
            Err(e) => return Ok(FrontendAction::Respond(e.to_response())),
        };
        if let Err(e) = self.provider.validate_authorization_request(&req).await {
            return Ok(FrontendAction::Respond(e.to_response()));
        }

        self.store_authz_request(ctx, &req)?;
        let mut request = InternalData::request(req.client_id.clone());
        if let Some(name) = client.client_name {
            request.requester_name = vec![name];
        }
        Ok(FrontendAction::StartAuth {
            request,
            target_backend: None,
        })
    }

    async fn handle_token(&self, ctx: &mut Context) -> Response {
        let form = ctx.request.form.clone();
        let auth_header = ctx.request.authorization().map(|s| s.to_string());
        // Audience for `private_key_jwt` is the advertised token endpoint, which
        // lives under the endpoint base — not necessarily the issuer/entity_id.
        let token_url = format!("{}/token", self.endpoint_base);
        match self
            .provider
            .handle_token_request(&form, auth_header.as_deref(), &token_url, None)
            .await
        {
            Ok(resp) => Response::json(&resp)
                .map(|r| r.with_header("cache-control", "no-store"))
                .unwrap_or_else(|e| {
                    OAuthError::new(OAuthErrorCode::ServerError, e.to_string()).to_response()
                }),
            Err(e) => e.to_response(),
        }
    }

    async fn handle_userinfo(&self, ctx: &mut Context) -> Response {
        let Some(token) = ctx.request.bearer_token() else {
            return OAuthError::new(OAuthErrorCode::AccessDenied, "missing bearer token")
                .to_response();
        };
        // The federation frontend does not offer DPoP, so no proof is presented;
        // a DPoP-bound token reaching here is rejected by the provider.
        match self.provider.userinfo(token, None).await {
            Ok(claims) => Response::json(&claims).unwrap_or_else(|e| {
                OAuthError::new(OAuthErrorCode::ServerError, e.to_string()).to_response()
            }),
            Err(e) => e.to_response(),
        }
    }
}

#[async_trait]
impl Frontend for FederationFrontend {
    fn name(&self) -> &str {
        &self.name
    }

    fn register_endpoints(&self, _backend_names: &[String]) -> Vec<Route> {
        vec![
            Route::new(
                &regex::escape(&self.route(".well-known/openid-federation")),
                "entity_configuration",
            ),
            Route::new(
                &regex::escape(&self.route(".well-known/openid-configuration")),
                "discovery",
            ),
            Route::new(&regex::escape(&self.route("jwks")), "jwks"),
            Route::new(
                &regex::escape(&self.route("authorization")),
                "authorization",
            ),
            Route::new(&regex::escape(&self.route("token")), "token"),
            Route::new(&regex::escape(&self.route("userinfo")), "userinfo"),
        ]
    }

    async fn handle_endpoint(&self, ctx: &mut Context, route_id: &str) -> Result<FrontendAction> {
        match route_id {
            "entity_configuration" => {
                let jwt = self.entity_configuration()?;
                Ok(FrontendAction::Respond(
                    Response::new(200)
                        .with_header("content-type", "application/entity-statement+jwt")
                        .with_body(jwt.into_bytes()),
                ))
            }
            "discovery" => Ok(FrontendAction::Respond(Response::json(
                &self.provider.discovery_document(),
            )?)),
            "jwks" => Ok(FrontendAction::Respond(Response::json(
                &self.provider.jwks_document(),
            )?)),
            "authorization" => self.handle_authorization(ctx).await,
            "token" => Ok(FrontendAction::Respond(self.handle_token(ctx).await)),
            "userinfo" => Ok(FrontendAction::Respond(self.handle_userinfo(ctx).await)),
            other => Err(Error::NoBoundEndpoint(other.to_string())),
        }
    }

    async fn handle_authn_response(
        &self,
        ctx: &mut Context,
        response: InternalData,
    ) -> Result<Response> {
        let req = self
            .load_authz_request(ctx)
            .ok_or_else(|| Error::State("no in-flight authorization request".into()))?;
        let external = self.mapper.from_internal("openid", &response.attributes);
        let sub = response
            .subject_id
            .clone()
            .or_else(|| self.mapper.compose_subject_id(&response.attributes))
            .ok_or_else(|| Error::Authn("no subject identifier available".into()))?;
        let acr = response.auth_info.auth_class_ref.clone();
        match self
            .provider
            .authorization_redirect(&req, &sub, &external, acr)
        {
            Ok(r) => Ok(r),
            Err(e) => Ok(e.to_redirect(&req.redirect_uri)),
        }
    }

    async fn handle_backend_error(&self, ctx: &mut Context, error: &Error) -> Result<Response> {
        if let Some(req) = self.load_authz_request(ctx) {
            let oerr = OAuthError::new(OAuthErrorCode::AccessDenied, error.to_string())
                .with_state(req.state.clone());
            return Ok(oerr.to_redirect(&req.redirect_uri));
        }
        Ok(Response::text(500, format!("{error}")))
    }
}
