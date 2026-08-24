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

        // Statically configured endpoints require an explicit `issuer`:
        // falling back to the authorization endpoint as the expected `iss`
        // would accept id_tokens from an issuer nobody configured.
        if (cfg.authorization_endpoint.is_some() || cfg.token_endpoint.is_some())
            && cfg.issuer.is_none()
        {
            return Err(Error::Config(format!(
                "oidc backend {}: issuer is required when endpoints are configured statically",
                bx.name
            )));
        }
        // Endpoints and the issuer are redirected to or fetched with
        // credentials attached; require https (plain http only for loopback
        // hosts, for local development).
        for (what, url) in [
            ("issuer", &cfg.issuer),
            ("authorization_endpoint", &cfg.authorization_endpoint),
            ("token_endpoint", &cfg.token_endpoint),
            ("userinfo_endpoint", &cfg.userinfo_endpoint),
            ("jwks_uri", &cfg.jwks_uri),
        ] {
            if let Some(url) = url {
                crate::url_check::require_https(url, &format!("oidc backend {}: {what}", bx.name))?;
            }
        }

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
            // build() guarantees `issuer` is set alongside static endpoints.
            let issuer = self.config.issuer.clone().ok_or_else(|| {
                Error::Config("oidc backend: issuer is required with static endpoints".into())
            })?;
            return Ok(ProviderInfo {
                issuer,
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

    async fn start_auth(&self, ctx: &mut Context, request: InternalData) -> Result<Response> {
        let provider = self.provider_info().await?;

        // Forward the requester's authentication constraints as an OIDC
        // `prompt`; never silently drop them.
        let prompt = match (request.force_authn, request.is_passive) {
            (false, false) => None,
            (true, false) => Some("login"),
            (false, true) => Some("none"),
            (true, true) => {
                return Err(Error::Authn(
                    "force_authn and is_passive cannot be honored together upstream".into(),
                ))
            }
        };

        let state = random_token(24);
        let nonce = random_token(24);
        let verifier = random_token(32);
        let challenge = pkce::s256_challenge(&verifier);

        ctx.state.set_str(&self.name, "oidc_state", &state);
        ctx.state.set_str(&self.name, "oidc_nonce", &nonce);
        ctx.state.set_str(&self.name, "code_verifier", &verifier);
        ctx.state.set_value(
            &self.name,
            "is_passive",
            serde_json::Value::Bool(request.is_passive),
        );

        let extra: &[(&str, &str)] = match prompt {
            Some(p) => &[("prompt", p)],
            None => &[],
        };
        let url = rp::authorization_url(
            &provider,
            &self.client,
            &state,
            &nonce,
            Some(&challenge),
            extra,
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

        if let Some(err) = ctx.request.param("error").map(str::to_string) {
            let is_passive = ctx
                .state
                .get_value(&self.name, "is_passive")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false);
            if is_passive && err == "login_required" {
                ctx.mark_interaction_required();
            }
            return Err(Error::Authn(format!("upstream error: {err}")));
        }
        let code = ctx
            .request
            .param("code")
            .ok_or_else(|| Error::BadRequest("missing code".into()))?
            .to_string();

        // A missing stored nonce must fail closed, exactly like a missing
        // stored state: passing `None` to id_token verification would silently
        // skip the nonce check.
        let nonce = ctx
            .state
            .get_str(&self.name, "oidc_nonce")
            .ok_or_else(|| Error::Authn("missing stored nonce".into()))?;
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
            Some(&nonce),
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
            let userinfo = rp::fetch_userinfo(&self.http, userinfo_ep, access_token).await?;
            require_matching_userinfo_subject(&userinfo, &sub)?;
            merge_json(&mut merged, &userinfo);
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
            force_authn: false,
            is_passive: false,
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

fn require_matching_userinfo_subject(
    userinfo: &serde_json::Value,
    id_token_sub: &str,
) -> Result<()> {
    let userinfo_sub = userinfo
        .as_object()
        .and_then(|claims| claims.get("sub"))
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| Error::Authn("userinfo response missing sub".into()))?;
    if userinfo_sub != id_token_sub {
        return Err(Error::Authn(
            "userinfo sub does not match id_token sub".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod subject_tests {
    use super::*;

    #[test]
    fn userinfo_subject_must_be_present_and_match() {
        assert!(
            require_matching_userinfo_subject(&serde_json::json!({ "sub": "alice" }), "alice")
                .is_ok()
        );
        assert!(require_matching_userinfo_subject(
            &serde_json::json!({ "sub": "mallory" }),
            "alice"
        )
        .is_err());
        assert!(require_matching_userinfo_subject(&serde_json::json!({}), "alice").is_err());
    }
}

#[cfg(test)]
mod prompt_tests {
    use super::*;
    use tunnelbana_core::http::HttpRequestData;
    use tunnelbana_core::plugin::NullHttpClient;
    use tunnelbana_core::state::State;

    fn backend() -> Box<dyn Backend> {
        let config = serde_json::json!({
            "client_id": "client",
            "issuer": "https://op.example",
            "authorization_endpoint": "https://op.example/authorize",
            "token_endpoint": "https://op.example/token",
        });
        OidcBackend::build(&BuildContext {
            name: "oidc".to_string(),
            base_url: "https://proxy.example".to_string(),
            config,
            attribute_mapper: Arc::new(AttributeMapper::from_toml("").unwrap()),
            http_client: Arc::new(NullHttpClient),
            secret: "secret".to_string(),
            previous_secrets: Vec::new(),
        })
        .unwrap()
    }

    async fn start_auth_url(request: InternalData) -> String {
        let sp = backend();
        let mut ctx = Context::new(HttpRequestData::default(), State::new());
        let resp = sp.start_auth(&mut ctx, request).await.unwrap();
        resp.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("location"))
            .map(|(_, v)| v.clone())
            .expect("location header")
    }

    #[tokio::test]
    async fn force_authn_maps_to_prompt_login() {
        let mut request = InternalData::request("https://sp.example");
        request.force_authn = true;
        let url = start_auth_url(request).await;
        assert!(url.contains("prompt=login"), "got {url}");
    }

    #[tokio::test]
    async fn is_passive_maps_to_prompt_none() {
        let mut request = InternalData::request("https://sp.example");
        request.is_passive = true;
        let url = start_auth_url(request).await;
        assert!(url.contains("prompt=none"), "got {url}");
    }

    #[tokio::test]
    async fn no_constraints_send_no_prompt() {
        let url = start_auth_url(InternalData::request("https://sp.example")).await;
        assert!(!url.contains("prompt="), "got {url}");
    }

    #[tokio::test]
    async fn conflicting_constraints_error() {
        let mut request = InternalData::request("https://sp.example");
        request.force_authn = true;
        request.is_passive = true;
        let sp = backend();
        let mut ctx = Context::new(HttpRequestData::default(), State::new());
        assert!(sp.start_auth(&mut ctx, request).await.is_err());
    }

    #[tokio::test]
    async fn passive_login_required_callback_restores_interaction_marker() {
        let sp = backend();
        let mut request = InternalData::request("https://sp.example");
        request.is_passive = true;
        let mut start_ctx = Context::new(HttpRequestData::default(), State::new());
        sp.start_auth(&mut start_ctx, request).await.unwrap();
        let state = start_ctx
            .state
            .get_str("oidc", "oidc_state")
            .expect("stored OIDC state");

        let mut callback_request = HttpRequestData::default();
        callback_request.query.insert("state".into(), state);
        callback_request
            .query
            .insert("error".into(), "login_required".into());
        let mut callback_ctx = Context::new(callback_request, start_ctx.state);
        assert!(sp
            .handle_endpoint(&mut callback_ctx, "callback")
            .await
            .is_err());
        assert!(callback_ctx.interaction_required());
    }
}

#[cfg(test)]
mod build_tests {
    use super::*;
    use tunnelbana_core::context::Context;
    use tunnelbana_core::http::HttpRequestData;
    use tunnelbana_core::plugin::NullHttpClient;
    use tunnelbana_core::state::State;

    fn bx(config: serde_json::Value) -> BuildContext {
        BuildContext {
            name: "OIDC".to_string(),
            base_url: "https://proxy.example.com".to_string(),
            config,
            attribute_mapper: Arc::new(AttributeMapper::from_toml("").unwrap()),
            http_client: Arc::new(NullHttpClient),
            secret: "test-secret".to_string(),
            previous_secrets: Vec::new(),
        }
    }

    fn static_endpoints() -> serde_json::Value {
        serde_json::json!({
            "issuer": "https://op.example.com",
            "authorization_endpoint": "https://op.example.com/authorize",
            "token_endpoint": "https://op.example.com/token",
            "client_id": "rp-1",
        })
    }

    #[test]
    fn static_endpoints_require_explicit_issuer() {
        let mut config = static_endpoints();
        config.as_object_mut().unwrap().remove("issuer");
        let err = OidcBackend::build(&bx(config))
            .err()
            .expect("build must fail");
        assert!(err.to_string().contains("issuer is required"), "got: {err}");
    }

    #[test]
    fn non_https_endpoints_are_rejected_at_build() {
        let mut config = static_endpoints();
        config["token_endpoint"] = serde_json::json!("http://op.example.com/token");
        let err = OidcBackend::build(&bx(config))
            .err()
            .expect("build must fail");
        assert!(err.to_string().contains("https is required"), "got: {err}");

        let mut config = static_endpoints();
        config["issuer"] = serde_json::json!("http://op.example.com");
        assert!(OidcBackend::build(&bx(config)).is_err());
    }

    #[test]
    fn loopback_http_is_allowed_for_local_dev() {
        let config = serde_json::json!({
            "issuer": "http://localhost:8080",
            "authorization_endpoint": "http://localhost:8080/authorize",
            "token_endpoint": "http://127.0.0.1:8080/token",
            "client_id": "rp-1",
        });
        assert!(OidcBackend::build(&bx(config)).is_ok());
    }

    #[test]
    fn https_static_endpoints_with_issuer_build() {
        assert!(OidcBackend::build(&bx(static_endpoints())).is_ok());
    }

    #[tokio::test]
    async fn callback_without_stored_nonce_fails_closed() {
        let backend = OidcBackend::build(&bx(static_endpoints())).unwrap();
        let mut ctx = Context::new(HttpRequestData::default(), State::new());
        // A flow with a valid stored state but no stored nonce: the nonce
        // check must fail closed rather than be silently skipped.
        ctx.state.set_str("OIDC", "oidc_state", "st-1");
        ctx.request.query.insert("state".into(), "st-1".into());
        ctx.request.query.insert("code".into(), "code-1".into());
        let err = backend
            .handle_endpoint(&mut ctx, "callback")
            .await
            .err()
            .expect("callback must fail");
        assert!(
            err.to_string().contains("missing stored nonce"),
            "got: {err}"
        );
    }
}
