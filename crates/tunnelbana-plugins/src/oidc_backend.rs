//! OIDC backend — the proxy acts as a relying party (RP) to an upstream OP.

use std::sync::Arc;

use async_trait::async_trait;
use serde::Deserialize;
use tunnelbana_core::attributes::AttributeMapper;
use tunnelbana_core::context::Context;
use tunnelbana_core::error::{Error, Result};
use tunnelbana_core::http::{HttpClient, Response};
use tunnelbana_core::internal::{AuthenticationInformation, InternalData, SubjectType};
use tunnelbana_core::plugin::{Backend, BackendAction, BuildContext, Route};
use tunnelbana_core::util::{now_rfc3339, random_token};
use tunnelbana_oidc::pkce;
use tunnelbana_oidc::rp::{self, ClientAuth, ProviderInfo, RpClient};

use crate::keyload::load_signing_key;

#[derive(Debug, Deserialize)]
struct OidcBackendConfig {
    /// Upstream issuer for discovery (used when explicit endpoints are absent).
    #[serde(default)]
    issuer: Option<String>,
    #[serde(default)]
    authorization_endpoint: Option<String>,
    #[serde(default)]
    token_endpoint: Option<String>,
    #[serde(default)]
    userinfo_endpoint: Option<String>,
    #[serde(default)]
    jwks_uri: Option<String>,

    client_id: String,
    #[serde(default)]
    client_secret: Option<String>,
    #[serde(default)]
    token_endpoint_auth_method: Option<String>,
    #[serde(default)]
    scope: Option<String>,

    // For private_key_jwt.
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
}

pub struct OidcBackend {
    name: String,
    client: RpClient,
    config: OidcBackendConfig,
    http: Arc<dyn HttpClient>,
    mapper: Arc<AttributeMapper>,
}

impl OidcBackend {
    pub fn build(bx: &BuildContext) -> Result<Box<dyn Backend>> {
        let cfg: OidcBackendConfig = bx.parse_config()?;
        let redirect_uri = format!("{}/callback", bx.module_base());
        let _ = &redirect_uri;

        let auth = match cfg.token_endpoint_auth_method.as_deref() {
            Some("none") => ClientAuth::None,
            Some("client_secret_post") => {
                ClientAuth::ClientSecretPost(cfg.client_secret.clone().unwrap_or_default())
            }
            Some("private_key_jwt") => {
                let key = load_signing_key(
                    cfg.signing_jwk.as_ref(),
                    cfg.signing_key_path.as_deref(),
                    cfg.signing_jwk_path.as_deref(),
                    cfg.signing_algorithm.as_deref(),
                    cfg.signing_key_id.as_deref(),
                )?;
                ClientAuth::PrivateKeyJwt(key)
            }
            // Default: client_secret_basic if a secret is present, else none.
            _ => match &cfg.client_secret {
                Some(secret) => ClientAuth::ClientSecretBasic(secret.clone()),
                None => ClientAuth::None,
            },
        };

        let client = RpClient {
            client_id: cfg.client_id.clone(),
            redirect_uri: redirect_uri.clone(),
            auth,
            scope: cfg
                .scope
                .clone()
                .unwrap_or_else(|| "openid profile email".to_string()),
        };

        Ok(Box::new(OidcBackend {
            name: bx.name.clone(),
            client,
            config: cfg,
            http: bx.http_client.clone(),
            mapper: bx.attribute_mapper.clone(),
        }))
    }

    /// Resolve upstream endpoints from static config or via discovery.
    async fn provider_info(&self) -> Result<ProviderInfo> {
        if let (Some(a), Some(t)) = (
            &self.config.authorization_endpoint,
            &self.config.token_endpoint,
        ) {
            return Ok(ProviderInfo {
                issuer: self.config.issuer.clone().unwrap_or_else(|| a.clone()),
                authorization_endpoint: a.clone(),
                token_endpoint: t.clone(),
                userinfo_endpoint: self.config.userinfo_endpoint.clone(),
                jwks_uri: self.config.jwks_uri.clone(),
            });
        }
        let issuer = self.config.issuer.as_ref().ok_or_else(|| {
            Error::Config("oidc backend needs issuer or explicit endpoints".into())
        })?;
        let meta = rp::discover(&self.http, issuer).await?;
        Ok(meta.into())
    }
}

#[async_trait]
impl Backend for OidcBackend {
    fn name(&self) -> &str {
        &self.name
    }

    fn register_endpoints(&self) -> Vec<Route> {
        vec![Route::exact(format!("{}/callback", self.name), "callback")]
    }

    async fn start_auth(&self, ctx: &mut Context, _request: InternalData) -> Result<Response> {
        let provider = self.provider_info().await?;

        let state = random_token(24);
        let nonce = random_token(24);
        let verifier = random_token(32);
        let challenge = pkce::s256_challenge(&verifier);

        ctx.state.set_str(&self.name, "oidc_state", &state);
        ctx.state.set_str(&self.name, "oidc_nonce", &nonce);
        ctx.state.set_str(&self.name, "code_verifier", &verifier);

        let url = rp::authorization_url(
            &provider,
            &self.client,
            &state,
            &nonce,
            Some(&challenge),
            &[],
        );
        Ok(Response::redirect(url))
    }

    async fn handle_endpoint(&self, ctx: &mut Context, route_id: &str) -> Result<BackendAction> {
        if route_id != "callback" {
            return Err(Error::NoBoundEndpoint(route_id.to_string()));
        }

        // CSRF: state must match what we stored.
        let expected_state = ctx
            .state
            .get_str(&self.name, "oidc_state")
            .ok_or_else(|| Error::Authn("missing stored state".into()))?;
        let got_state = ctx
            .request
            .param("state")
            .ok_or_else(|| Error::BadRequest("missing state".into()))?;
        if got_state != expected_state {
            return Err(Error::Authn("state mismatch".into()));
        }

        if let Some(err) = ctx.request.param("error") {
            return Err(Error::Authn(format!("upstream error: {err}")));
        }
        let code = ctx
            .request
            .param("code")
            .ok_or_else(|| Error::BadRequest("missing code".into()))?
            .to_string();

        let nonce = ctx.state.get_str(&self.name, "oidc_nonce");
        let verifier = ctx.state.get_str(&self.name, "code_verifier");

        let provider = self.provider_info().await?;
        let tokens = rp::exchange_code(
            &self.http,
            &provider,
            &self.client,
            &code,
            verifier.as_deref(),
        )
        .await?;

        // Verify the id_token.
        let id_token = tokens
            .id_token
            .as_ref()
            .ok_or_else(|| Error::Authn("no id_token in token response".into()))?;
        let jwks_uri = provider
            .jwks_uri
            .as_ref()
            .ok_or_else(|| Error::Config("provider has no jwks_uri".into()))?;
        let jwks = rp::fetch_jwks(&self.http, jwks_uri).await?;
        let id_claims = rp::verify_id_token(
            &jwks,
            id_token,
            &provider.issuer,
            &self.client.client_id,
            nonce.as_deref(),
        )?;

        let sub = id_claims
            .sub
            .clone()
            .ok_or_else(|| Error::Authn("id_token missing sub".into()))?;

        // Merge id_token claims and userinfo.
        let mut merged = serde_json::to_value(&id_claims.extra).unwrap_or_default();
        if let (Some(userinfo_ep), Some(access_token)) =
            (&provider.userinfo_endpoint, &tokens.access_token)
        {
            if let Ok(userinfo) = rp::fetch_userinfo(&self.http, userinfo_ep, access_token).await {
                merge_json(&mut merged, &userinfo);
            }
        }

        let external = rp::claims_to_attributes(&merged);
        let internal_attrs = self.mapper.to_internal("openid", &external);

        let response = InternalData {
            auth_info: AuthenticationInformation {
                auth_class_ref: id_claims
                    .extra
                    .get("acr")
                    .and_then(|v| v.as_str())
                    .map(String::from),
                timestamp: Some(now_rfc3339()),
                issuer: Some(provider.issuer.clone()),
            },
            requester: None,
            requester_name: Vec::new(),
            subject_id: Some(sub),
            subject_type: SubjectType::Public,
            attributes: internal_attrs,
        };

        // Clean up per-flow state.
        ctx.state.clear_namespace(&self.name);

        Ok(BackendAction::AuthResponse(response))
    }
}

fn merge_json(base: &mut serde_json::Value, extra: &serde_json::Value) {
    if let (Some(b), Some(e)) = (base.as_object_mut(), extra.as_object()) {
        for (k, v) in e {
            b.entry(k.clone()).or_insert_with(|| v.clone());
        }
    }
}
