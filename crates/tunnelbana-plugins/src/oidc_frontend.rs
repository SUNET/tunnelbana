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
use tunnelbana_oidc::client::InMemoryClientStore;
use tunnelbana_oidc::metadata::ProviderMetadata;
use tunnelbana_oidc::oauth_error::{OAuthError, OAuthErrorCode};
use tunnelbana_oidc::provider::{Provider, TokenLifetimes};
use tunnelbana_oidc::request::AuthorizationRequest;
use tunnelbana_oidc::tokens::TokenCodec;

use crate::dpop::{DpopRuntime, DpopSettings};
use crate::keyload::{load_signing_key, scoped_secret};

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
    clients: Vec<serde_json::Value>,
    /// Path to a JSON file holding a bare array of additional clients, merged
    /// with `clients`. A duplicate `client_id` across the two is a boot error.
    #[serde(default)]
    clients_file: Option<String>,
    #[serde(default)]
    code_ttl: Option<u64>,
    #[serde(default)]
    access_token_ttl: Option<u64>,
    #[serde(default)]
    id_token_ttl: Option<u64>,
    #[serde(default)]
    refresh_token_ttl: Option<u64>,
    /// Maximum accepted age (seconds, measured from `iat`) of `private_key_jwt`
    /// client assertions at the token endpoint. Defaults to grindvakt's 300;
    /// widen only for clients that cannot mint fresh assertions per request.
    /// `exp` and a single-use `jti` are always required.
    #[serde(default)]
    client_assertion_max_age: Option<u64>,
    /// Extra metadata fields to merge into the discovery document.
    #[serde(default)]
    extra_metadata: serde_json::Map<String, serde_json::Value>,
    /// DPoP (RFC 9449) settings; disabled unless `dpop.enabled = true`.
    #[serde(default)]
    dpop: DpopSettings,
    /// Pin every flow from this frontend to a named backend. Overrides
    /// `custom_routing` and the default backend.
    #[serde(default)]
    backend: Option<String>,
}

/// The OIDC OP frontend plugin.
pub struct OidcFrontend {
    name: String,
    issuer: String,
    provider: Provider,
    mapper: Arc<AttributeMapper>,
    /// DPoP runtime (config + replay store) when enabled, else `None`.
    dpop: Option<DpopRuntime>,
    /// Backend name every flow is pinned to, if configured.
    backend: Option<String>,
}

impl OidcFrontend {
    pub fn build(bx: &BuildContext) -> Result<Box<dyn Frontend>> {
        let cfg: OidcFrontendConfig = bx.parse_config()?;
        crate::oidc_common::validate_authenticating_authority_mapping(
            &bx.attribute_mapper,
            &bx.name,
        )?;
        let module_base = bx.module_base();
        let issuer = module_base.clone();

        let signing_key = load_signing_key(
            cfg.signing_jwk.as_ref(),
            cfg.signing_key_path.as_deref(),
            cfg.signing_jwk_path.as_deref(),
            cfg.signing_algorithm.as_deref(),
            cfg.signing_key_id.as_deref(),
        )?;

        let dpop = cfg.dpop.build_runtime(&bx.secret, &bx.name)?;

        let mut metadata = ProviderMetadata::new(issuer.clone(), &module_base);
        // Advertise the signing alg actually in use.
        metadata.id_token_signing_alg_values_supported =
            vec![signing_key.alg().as_str().to_string()];
        // When DPoP is enabled, advertise it (RFC 9449 §5.1).
        if dpop.is_some() {
            metadata.dpop_signing_alg_values_supported = vec!["ES256".to_string()];
        }
        crate::oidc_common::advertise_mapped_claims(&mut metadata, &bx.attribute_mapper);
        for (k, v) in cfg.extra_metadata {
            metadata.extra.insert(k, v);
        }

        let client_list =
            crate::client_loader::load_clients(cfg.clients, cfg.clients_file.as_deref())?;
        let clients = Arc::new(InMemoryClientStore::with_clients(client_list));
        // Mix the frontend instance name into the sealing key material, so a
        // token sealed by one frontend cannot be opened by another frontend
        // sharing the same master secret.
        let codec = TokenCodec::new(&scoped_secret(&bx.secret, &bx.name)).with_previous_secrets(
            &bx.previous_secrets
                .iter()
                .map(|s| scoped_secret(s, &bx.name))
                .collect::<Vec<_>>(),
        );
        let lifetimes = TokenLifetimes {
            code_ttl: cfg.code_ttl.unwrap_or(600),
            access_token_ttl: cfg.access_token_ttl.unwrap_or(3600),
            id_token_ttl: cfg.id_token_ttl.unwrap_or(3600),
            refresh_token_ttl: cfg.refresh_token_ttl.unwrap_or(2_592_000),
        };
        let mut provider = Provider::new(metadata, signing_key, clients, codec, lifetimes);
        if let Some(max_age) = cfg.client_assertion_max_age {
            provider = provider.with_client_assertion_max_age(max_age);
        }

        Ok(Box::new(OidcFrontend {
            name: bx.name.clone(),
            issuer,
            provider,
            mapper: bx.attribute_mapper.clone(),
            dpop,
            backend: cfg.backend,
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
            Route::exact(self.route(".well-known/openid-configuration"), "discovery"),
            Route::exact(self.route("jwks"), "jwks"),
            Route::exact(self.route("authorization"), "authorization"),
            Route::exact(self.route("token"), "token"),
            Route::exact(self.route("userinfo"), "userinfo"),
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
        let mut external = self.mapper.from_internal("openid", &response.attributes);

        // Subject id: explicit, else composed from configured attrs, else error.
        let sub = response
            .subject_id
            .clone()
            .or_else(|| self.mapper.compose_subject_id(&response.attributes))
            .ok_or_else(|| Error::Authn("no subject identifier available".into()))?;

        let acr = response.auth_info.auth_class_ref.clone();

        let extra_claims = crate::oidc_common::authenticating_authority_claims(
            &self.mapper,
            &mut external,
            response.auth_info.issuer.as_deref(),
        );

        match self.provider.authorization_redirect_with_claims(
            &req,
            &sub,
            &external,
            acr,
            &extra_claims,
        ) {
            Ok(r) => Ok(r),
            Err(e) => Ok(e.to_redirect(&req.redirect_uri)),
        }
    }

    async fn handle_backend_error(&self, ctx: &mut Context, error: &Error) -> Result<Response> {
        tracing::warn!(frontend = %self.name, error = %error, "backend authentication failed");
        // If we have the in-flight request, redirect the error to the RP.
        if let Some(req) = self.load_authz_request(ctx) {
            let oerr = crate::oidc_common::backend_authorization_error(
                &req,
                error,
                ctx.interaction_required(),
            );
            return Ok(oerr.to_redirect(&req.redirect_uri));
        }
        Ok(Response::text(500, "authentication could not be completed"))
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
        crate::oidc_common::apply_prompt_constraints(&req, &mut request);
        Ok(FrontendAction::StartAuth {
            request,
            target_backend: self.backend.clone(),
        })
    }

    async fn handle_token(&self, ctx: &mut Context) -> Response {
        let form = ctx.request.form.clone();
        let auth_header = ctx.request.authorization().map(|s| s.to_string());
        let method = ctx.request.method.clone();
        let token_url = format!("{}/token", self.issuer);

        // Validate an optional DPoP proof up front (RFC 9449). The htm/htu bind
        // the proof to this request; a `use_dpop_nonce` challenge is a complete
        // response on its own.
        let dpop_proof = match self.dpop_for_token(ctx, &method, &token_url).await {
            Ok(p) => p,
            Err(resp) => return resp,
        };

        match self
            .provider
            .handle_token_request(
                &form,
                auth_header.as_deref(),
                &token_url,
                dpop_proof.as_ref(),
            )
            .await
        {
            Ok(resp) => match Response::json(&resp) {
                Ok(r) => r.with_header("cache-control", "no-store"),
                Err(e) => {
                    tracing::error!(frontend = %self.name, error = %e, "token response serialization failed");
                    OAuthError::new(OAuthErrorCode::ServerError, "response could not be created")
                        .to_response()
                }
            },
            Err(e) => e.to_response(),
        }
    }

    /// Validate the optional `DPoP` header on the **token** request, binding it
    /// to `htm`/`htu`. `Ok(None)` when DPoP is disabled or no proof was sent.
    async fn dpop_for_token(
        &self,
        ctx: &Context,
        htm: &str,
        htu: &str,
    ) -> std::result::Result<Option<tunnelbana_oidc::dpop::DpopProof>, Response> {
        let Some((rt, proof_jwt)) = self.dpop_request(ctx) else {
            return Ok(None);
        };
        let outcome = tunnelbana_oidc::dpop::validate_proof(
            rt.store.as_ref(),
            &rt.config,
            proof_jwt,
            htm,
            htu,
        )
        .await;
        self.map_dpop_result(rt, outcome)
    }

    /// Validate the optional `DPoP` header on a **resource** request (userinfo),
    /// additionally binding it to `access_token` via `ath`. `Ok(None)` when DPoP
    /// is disabled or no proof was sent.
    async fn dpop_for_resource(
        &self,
        ctx: &Context,
        htm: &str,
        htu: &str,
        access_token: &str,
    ) -> std::result::Result<Option<tunnelbana_oidc::dpop::DpopProof>, Response> {
        let Some((rt, proof_jwt)) = self.dpop_request(ctx) else {
            return Ok(None);
        };
        let outcome = tunnelbana_oidc::dpop::validate_resource_proof(
            rt.store.as_ref(),
            &rt.config,
            proof_jwt,
            htm,
            htu,
            access_token,
        )
        .await;
        self.map_dpop_result(rt, outcome)
    }

    /// The DPoP runtime and the presented proof JWT, when both are present.
    fn dpop_request<'a>(&'a self, ctx: &'a Context) -> Option<(&'a DpopRuntime, &'a str)> {
        let rt = self.dpop.as_ref()?;
        let proof = ctx.request.headers.get("dpop")?;
        Some((rt, proof.as_str()))
    }

    /// Map a DPoP validation outcome onto either the proof or a verbatim error /
    /// nonce-challenge response (RFC 9449 §8).
    fn map_dpop_result(
        &self,
        rt: &DpopRuntime,
        outcome: std::result::Result<
            tunnelbana_oidc::dpop::DpopProof,
            tunnelbana_oidc::dpop::DpopError,
        >,
    ) -> std::result::Result<Option<tunnelbana_oidc::dpop::DpopProof>, Response> {
        use tunnelbana_oidc::dpop::{self, DpopError};
        match outcome {
            Ok(p) => Ok(Some(p)),
            // RFC 9449 §8: challenge the client with a fresh nonce.
            Err(DpopError::NonceRequired) => {
                let body = serde_json::json!({
                    "error": "use_dpop_nonce",
                    "error_description": "Authorization server requires nonce in DPoP proof",
                });
                let resp = Response::json_status(400, &body)
                    .unwrap_or_else(|_| Response::new(400))
                    .with_header("DPoP-Nonce", dpop::issue_nonce(&rt.config))
                    .with_header("cache-control", "no-store");
                Err(resp)
            }
            Err(DpopError::Server(m)) => {
                tracing::error!(frontend = %self.name, error = %m, "DPoP validation failed internally");
                Err(
                    OAuthError::new(OAuthErrorCode::ServerError, "DPoP validation failed")
                        .to_response(),
                )
            }
            Err(e) => {
                tracing::debug!(frontend = %self.name, error = %e, "invalid DPoP proof");
                Err(OAuthError::invalid_dpop_proof("DPoP proof is invalid").to_response())
            }
        }
    }

    async fn handle_userinfo(&self, ctx: &mut Context) -> Response {
        // Accept the access token under either the `Bearer` or `DPoP` auth
        // scheme. A DPoP-bound token presented as plain `Bearer` (no proof) is
        // ultimately rejected by the provider's cnf.jkt check.
        let Some(token) = presented_access_token(ctx) else {
            return OAuthError::new(OAuthErrorCode::AccessDenied, "missing access token")
                .to_response();
        };
        let method = ctx.request.method.clone();
        let userinfo_url = format!("{}/userinfo", self.issuer);

        // If a DPoP proof accompanies the request, validate it (binding htm/htu
        // and the access-token hash) and capture its key thumbprint.
        let proof = match self
            .dpop_for_resource(ctx, &method, &userinfo_url, &token)
            .await
        {
            Ok(p) => p,
            Err(resp) => return resp,
        };
        let presented_jkt = proof.as_ref().map(|p| p.jkt.as_str());

        match self.provider.userinfo(&token, presented_jkt).await {
            Ok(claims) => Response::json(&claims).unwrap_or_else(|e| {
                tracing::error!(frontend = %self.name, error = %e, "UserInfo serialization failed");
                OAuthError::new(OAuthErrorCode::ServerError, "response could not be created")
                    .to_response()
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

/// Extract the presented access token from the `Authorization` header under
/// either the `Bearer` or `DPoP` auth scheme (RFC 9449 §7.1). The scheme keyword
/// itself is not load-bearing for security — sender-constraint is enforced by the
/// proof (`ath` + `cnf.jkt`), not by which keyword was used.
fn presented_access_token(ctx: &Context) -> Option<String> {
    let auth = ctx.request.authorization()?;
    let (scheme, token) = auth.split_once(' ')?;
    if scheme.eq_ignore_ascii_case("DPoP") || scheme.eq_ignore_ascii_case("Bearer") {
        return Some(token.trim().to_string());
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use tunnelbana_core::plugin::NullHttpClient;

    #[test]
    fn frontend_build_rejects_reserved_authenticating_authority_claim_names() {
        for reserved in crate::oidc_common::RESERVED_ID_TOKEN_CLAIMS {
            let mapper = Arc::new(
                AttributeMapper::from_toml(&format!(
                    r#"
                    [attributes.authenticating_authority]
                    openid = ["{reserved}"]
                    "#
                ))
                .unwrap(),
            );
            let bx = BuildContext {
                name: "OIDC".to_string(),
                base_url: "https://proxy.example.com".to_string(),
                config: serde_json::json!({}),
                attribute_mapper: mapper,
                http_client: Arc::new(NullHttpClient),
                secret: "test-secret".to_string(),
                previous_secrets: Vec::new(),
            };

            let error = match OidcFrontend::build(&bx) {
                Ok(_) => panic!("reserved claim {reserved} was accepted"),
                Err(error) => error,
            };
            assert!(
                error.to_string().contains(&format!(
                    "authenticating_authority cannot map to reserved ID-token claim {reserved}"
                )),
                "unexpected error for {reserved}: {error}"
            );
        }
    }
}
