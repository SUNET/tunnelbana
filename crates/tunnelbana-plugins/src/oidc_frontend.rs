//! OIDC frontend — the proxy acts as an OpenID Provider (OP) to downstream RPs.

use std::sync::Arc;

use async_trait::async_trait;
use serde::Deserialize;
use tunnelbana_core::attributes::AttributeMapper;
use tunnelbana_core::context::Context;
use tunnelbana_core::error::{Error, Result};
use tunnelbana_core::http::Response;
use tunnelbana_core::internal::InternalData;
use tunnelbana_core::plugin::{BuildContext, Frontend, FrontendAction, Route};
use tunnelbana_oidc::client::{Client, InMemoryClientStore};
use tunnelbana_oidc::metadata::ProviderMetadata;
use tunnelbana_oidc::oauth_error::{OAuthError, OAuthErrorCode};
use tunnelbana_oidc::provider::{Provider, TokenLifetimes};
use tunnelbana_oidc::request::AuthorizationRequest;
use tunnelbana_oidc::tokens::TokenCodec;

use crate::keyload::load_signing_key;

/// State namespace key under which the in-flight authorization request is held.
const AUTHZ_KEY: &str = "authz_request";

#[derive(Debug, Deserialize)]
struct OidcFrontendConfig {
    #[serde(default)]
    signing_key_path: Option<String>,
    #[serde(default)]
    signing_jwk: Option<serde_json::Value>,
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
    /// Extra metadata fields to merge into the discovery document.
    #[serde(default)]
    extra_metadata: serde_json::Map<String, serde_json::Value>,
}

/// The OIDC OP frontend plugin.
pub struct OidcFrontend {
    name: String,
    issuer: String,
    provider: Provider,
    mapper: Arc<AttributeMapper>,
}

impl OidcFrontend {
    pub fn build(bx: &BuildContext) -> Result<Box<dyn Frontend>> {
        let cfg: OidcFrontendConfig = bx.parse_config()?;
        let module_base = bx.module_base();
        let issuer = module_base.clone();

        let signing_key = load_signing_key(
            cfg.signing_jwk.as_ref(),
            cfg.signing_key_path.as_deref(),
            cfg.signing_jwk_path.as_deref(),
            cfg.signing_algorithm.as_deref(),
            cfg.signing_key_id.as_deref(),
        )?;

        let mut metadata = ProviderMetadata::new(issuer.clone(), &module_base);
        // Advertise the signing alg actually in use.
        metadata.id_token_signing_alg_values_supported = vec![signing_key.alg.as_str().to_string()];
        // Surface mappable claims in discovery.
        for internal in mapper_openid_claims(&bx.attribute_mapper) {
            if !metadata.claims_supported.contains(&internal) {
                metadata.claims_supported.push(internal);
            }
        }
        for (k, v) in cfg.extra_metadata {
            metadata.extra.insert(k, v);
        }

        let clients = Arc::new(InMemoryClientStore::with_clients(cfg.clients));
        let codec = TokenCodec::new(&bx.secret).with_previous_secrets(&bx.previous_secrets);
        let lifetimes = TokenLifetimes {
            code_ttl: cfg.code_ttl.unwrap_or(600),
            access_token_ttl: cfg.access_token_ttl.unwrap_or(3600),
            id_token_ttl: cfg.id_token_ttl.unwrap_or(3600),
        };
        let provider = Provider::new(metadata, signing_key, clients, codec, lifetimes);

        Ok(Box::new(OidcFrontend {
            name: bx.name.clone(),
            issuer,
            provider,
            mapper: bx.attribute_mapper.clone(),
        }))
    }

    fn route(&self, suffix: &str) -> String {
        format!("{}/{}", self.name, suffix)
    }
}

#[async_trait]
impl Frontend for OidcFrontend {
    fn name(&self) -> &str {
        &self.name
    }

    fn register_endpoints(&self, _backend_names: &[String]) -> Vec<Route> {
        vec![
            Route::new(
                &regex::escape(&self.route(".well-known/openid-configuration")),
                "discovery",
            ),
            Route::new(&regex::escape(&self.route("jwks")), "jwks"),
            Route::new(&regex::escape(&self.route("authorization")), "authorization"),
            Route::new(&regex::escape(&self.route("token")), "token"),
            Route::new(&regex::escape(&self.route("userinfo")), "userinfo"),
        ]
    }

    async fn handle_endpoint(&self, ctx: &mut Context, route_id: &str) -> Result<FrontendAction> {
        match route_id {
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

        // Map internal attributes to OpenID claims.
        let external = self.mapper.from_internal("openid", &response.attributes);

        // Subject id: explicit, else composed from configured attrs, else error.
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
        // If we have the in-flight request, redirect the error to the RP.
        if let Some(req) = self.load_authz_request(ctx) {
            let oerr = OAuthError::new(OAuthErrorCode::AccessDenied, error.to_string())
                .with_state(req.state.clone());
            return Ok(oerr.to_redirect(&req.redirect_uri));
        }
        Ok(Response::text(500, format!("{error}")))
    }
}

impl OidcFrontend {
    async fn handle_authorization(&self, ctx: &mut Context) -> Result<FrontendAction> {
        let params = ctx.request.query.clone();
        let req = match AuthorizationRequest::from_params(&params) {
            Ok(r) => r,
            Err(e) => return Ok(FrontendAction::Respond(e.to_response())),
        };

        let client = match self.provider.validate_authorization_request(&req).await {
            Ok(c) => c,
            // redirect_uri is unvalidated on failure → must not redirect.
            Err(e) => return Ok(FrontendAction::Respond(e.to_response())),
        };

        // Persist the request for the response path.
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
        let token_url = format!("{}/token", self.issuer);
        match self
            .provider
            .handle_token_request(&form, auth_header.as_deref(), &token_url)
            .await
        {
            Ok(resp) => match Response::json(&resp) {
                Ok(r) => r.with_header("cache-control", "no-store"),
                Err(e) => OAuthError::new(OAuthErrorCode::ServerError, e.to_string()).to_response(),
            },
            Err(e) => e.to_response(),
        }
    }

    async fn handle_userinfo(&self, ctx: &mut Context) -> Response {
        let Some(token) = ctx.request.bearer_token() else {
            return OAuthError::new(OAuthErrorCode::AccessDenied, "missing bearer token")
                .to_response();
        };
        match self.provider.userinfo(token).await {
            Ok(claims) => Response::json(&claims).unwrap_or_else(|e| {
                OAuthError::new(OAuthErrorCode::ServerError, e.to_string()).to_response()
            }),
            Err(e) => e.to_response(),
        }
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
}

/// Collect the internal attribute names that have an `openid` mapping (for the
/// discovery `claims_supported` list).
fn mapper_openid_claims(mapper: &AttributeMapper) -> Vec<String> {
    mapper
        .raw()
        .attributes
        .iter()
        .filter(|(_, profiles)| profiles.contains_key("openid"))
        .flat_map(|(_, profiles)| profiles.get("openid").cloned().unwrap_or_default())
        .collect()
}
