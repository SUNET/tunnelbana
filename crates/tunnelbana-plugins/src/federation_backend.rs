//! OpenID Federation backend: the proxy acts as a federation-aware relying
//! party (RP) towards an upstream OP. Instead of `.well-known` discovery and a
//! pre-registered client, it serves its own signed RP entity configuration,
//! resolves the OP's metadata through configured trust anchors, and
//! authenticates to the token endpoint with `private_key_jwt` using its
//! entity id as the client id (automatic registration).
//!
//! The upstream OP is either fixed (`op_entity_id`) or chosen per flow via
//! **discovery**: when `discovery.enable` is set, `start_auth` redirects the
//! browser to an external OpenID Federation home-organization discovery
//! service (`discovery.service`, e.g. upptackt). The service lets the user
//! pick their OP and sends them back to this RP's published
//! `initiate_login_uri` (`<name>/initiate`) as an OpenID Connect Core §4
//! Third-Party Initiated Login whose `iss` drives the rest of the flow.
//!
//! An earlier revision rendered the OP-selection page inside the proxy from a
//! trust anchor's collection endpoint. That code is kept commented out below
//! (look for "In-proxy discovery") for anyone who wants to run discovery
//! inside the proxy again; see ADR 0025.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::RwLock;

use async_trait::async_trait;
use jose_rs::jwk::JwkSet;
use serde::Deserialize;
use serde_json::Value;
use tunnelbana_core::attributes::AttributeMapper;
use tunnelbana_core::context::Context;
use tunnelbana_core::error::{Error, Result};
use tunnelbana_core::http::{HttpClient, Response};
use tunnelbana_core::internal::{AuthenticationInformation, InternalData, SubjectType};
use tunnelbana_core::keys::SigningKey;
use tunnelbana_core::plugin::{Backend, BackendAction, BuildContext, Route};
use tunnelbana_core::util::{now_rfc3339, now_secs, random_token};
use tunnelbana_oidc::discovery;
use tunnelbana_oidc::federation::{self, TrustAnchors};
use tunnelbana_oidc::pkce;
use tunnelbana_oidc::rp::{self, ClientAuth, ProviderInfo, RpClient};

use crate::keyload::load_signing_key;

const DISCOVERY_VERIFIER_KEY: &str = "disco_verifier";
const DISCOVERY_VERIFIER_PARAM: &str = "tb_discovery_verifier";

#[derive(Debug, Deserialize)]
struct TrustAnchorConfig {
    entity_id: String,
    /// Pre-distributed verification keys (JWK objects).
    keys: Vec<Value>,
}

#[derive(Debug, Deserialize)]
struct FederationConfig {
    // Federation signing key: signs the RP entity configuration.
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
    trust_anchor: Vec<TrustAnchorConfig>,
    #[serde(default = "default_ec_lifetime")]
    entity_configuration_lifetime: u64,
    /// How long a resolved OP metadata document is reused before re-resolving.
    #[serde(default = "default_op_cache_ttl")]
    op_cache_ttl: u64,
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
fn default_op_cache_ttl() -> u64 {
    3600
}
// In-proxy discovery (kept for reference, see ADR 0025):
// fn default_disco_title() -> String {
//     "Select your identity provider".to_string()
// }
// fn default_op_list_ttl() -> u64 {
//     3600
// }

/// OP-discovery configuration (mutually exclusive with a fixed `op_entity_id`).
///
/// Discovery is delegated to an external home-organization discovery service:
/// `start_auth` sends the browser to `service` and the service returns the
/// user to `<module_base>/initiate` with the chosen OP in `iss`.
#[derive(Debug, Deserialize)]
struct DiscoveryConfig {
    #[serde(default)]
    enable: bool,
    /// Endpoint URL of the external OpenID Federation discovery service
    /// (e.g. an upptackt deployment). Required when `enable` is set.
    #[serde(default)]
    service: Option<String>,
    // ── In-proxy discovery (kept for reference, see ADR 0025) ───────────────
    // The proxy used to render its own OP-selection page from a trust
    // anchor's collection endpoint. To bring that back, restore these fields
    // together with the other "In-proxy discovery" blocks in this file.
    // /// A trust anchor's collection/listing endpoint enumerating the
    // /// federation's OPs (e.g. an inmor `…/collection`).
    // #[serde(default)]
    // collection_endpoint: Option<String>,
    // #[serde(default = "default_disco_title")]
    // page_title: String,
    // /// How long the fetched OP list is cached before re-fetching.
    // #[serde(default = "default_op_list_ttl")]
    // cache_ttl: u64,
}

#[derive(Debug, Deserialize)]
struct FederationBackendConfig {
    /// Federation entity identifier of this RP. It is also the OAuth2
    /// `client_id` sent upstream (automatic registration). Defaults to the
    /// module base (`<base_url>/<name>`); the entity configuration must be
    /// reachable at `<entity_id>/.well-known/openid-federation`.
    #[serde(default)]
    entity_id: Option<String>,
    /// Entity id of the upstream OP to authenticate against. Required unless
    /// `discovery.enable` is set (the two are mutually exclusive).
    #[serde(default)]
    op_entity_id: Option<String>,
    /// OP discovery via an external discovery service instead of a fixed OP.
    #[serde(default)]
    discovery: Option<DiscoveryConfig>,
    #[serde(default)]
    scope: Option<String>,

    // Client-authentication key for `private_key_jwt`. Defaults to the
    // federation signing key when absent.
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

    federation: FederationConfig,
}

/// The OP metadata recovered from a trust-anchor resolve response.
#[derive(Clone)]
struct ResolvedOp {
    entity_id: String,
    provider: ProviderInfo,
    metadata: Value,
    federation_jwks: JwkSet,
}

/// Runtime state for OP discovery via an external discovery service.
struct Discovery {
    /// Endpoint URL of the external discovery service.
    service: String,
    /// Where the service sends the user back: `<module_base>/initiate`,
    /// published as `initiate_login_uri` in the RP entity configuration.
    initiate_login_uri: String,
    // ── In-proxy discovery (kept for reference, see ADR 0025) ───────────────
    // collection_endpoint: String,
    // page_title: String,
    // cache_ttl: u64,
    // /// Cached OP list: (expires_at_secs, entities).
    // op_list_cache: RwLock<Option<(u64, Vec<federation::CollectionEntity>)>>,
}

impl Discovery {
    fn target_link_uri(&self, verifier: &str) -> String {
        format!(
            "{}?{}={verifier}",
            self.initiate_login_uri, DISCOVERY_VERIFIER_PARAM
        )
    }
}

pub struct FederationBackend {
    name: String,
    entity_id: String,
    /// Fixed upstream OP; `None` when discovery is enabled.
    op_entity_id: Option<String>,
    discovery: Option<Discovery>,
    client: RpClient,
    client_jwks: JwkSet,
    http: Arc<dyn HttpClient>,
    mapper: Arc<AttributeMapper>,
    // Federation state.
    fed_key: SigningKey,
    authority_hints: Vec<String>,
    trust_anchors: TrustAnchors,
    ec_lifetime: u64,
    op_cache_ttl: u64,
    organization_name: Option<String>,
    organization_uri: Option<String>,
    trust_marks: Vec<Value>,
    /// Cached resolved OP metadata, keyed by OP entity id: (expires_at, op).
    resolved: RwLock<HashMap<String, (u64, ResolvedOp)>>,
}

impl FederationBackend {
    pub fn build(bx: &BuildContext) -> Result<Box<dyn Backend>> {
        let cfg: FederationBackendConfig = bx.parse_config()?;
        let module_base = bx.module_base();
        let entity_id = cfg.entity_id.clone().unwrap_or_else(|| module_base.clone());
        let redirect_uri = format!("{module_base}/callback");

        let fed = &cfg.federation;
        if fed.trust_anchor.is_empty() {
            return Err(Error::Config(format!(
                "oidc_federation backend {}: at least one trust_anchor is required",
                bx.name
            )));
        }

        // Either a fixed OP or discovery, never both, never neither.
        let discovery = match cfg.discovery {
            Some(d) if d.enable => {
                if cfg.op_entity_id.is_some() {
                    return Err(Error::Config(format!(
                        "oidc_federation backend {}: set either op_entity_id or discovery.enable, not both",
                        bx.name
                    )));
                }
                let service = d.service.ok_or_else(|| {
                    Error::Config(format!(
                        "oidc_federation backend {}: discovery.enable requires service \
                         (the external discovery service URL)",
                        bx.name
                    ))
                })?;
                // Fail fast on an unusable service URL or RP entity id: the
                // same helper builds the live redirect in start_auth.
                discovery::discovery_request_url(&service, &entity_id, None, None).map_err(
                    |e| {
                        Error::Config(format!(
                            "oidc_federation backend {}: discovery.service: {e}",
                            bx.name
                        ))
                    },
                )?;
                Some(Discovery {
                    service,
                    initiate_login_uri: format!("{module_base}/initiate"),
                    // In-proxy discovery (kept for reference, see ADR 0025):
                    // collection_endpoint,
                    // page_title: d.page_title,
                    // cache_ttl: d.cache_ttl,
                    // op_list_cache: RwLock::new(None),
                })
            }
            _ => {
                if cfg.op_entity_id.is_none() {
                    return Err(Error::Config(format!(
                        "oidc_federation backend {}: either op_entity_id or discovery.enable is required",
                        bx.name
                    )));
                }
                None
            }
        };
        let fed_key = load_signing_key(
            fed.signing_jwk.as_ref(),
            fed.signing_key_path.as_deref(),
            fed.signing_jwk_path.as_deref(),
            fed.signing_algorithm.as_deref(),
            fed.signing_key_id.as_deref(),
        )?;

        // Client-auth key: dedicated if configured, else the federation key.
        let has_client_key = cfg.signing_jwk.is_some()
            || cfg.signing_key_path.is_some()
            || cfg.signing_jwk_path.is_some();
        let client_key = if has_client_key {
            load_signing_key(
                cfg.signing_jwk.as_ref(),
                cfg.signing_key_path.as_deref(),
                cfg.signing_jwk_path.as_deref(),
                cfg.signing_algorithm.as_deref(),
                cfg.signing_key_id.as_deref(),
            )?
        } else {
            fed_key.clone()
        };
        let client_jwks = client_key.to_public_jwks();

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

        let client = RpClient {
            client_id: entity_id.clone(),
            redirect_uri,
            auth: ClientAuth::PrivateKeyJwt(client_key),
            scope: cfg
                .scope
                .clone()
                .unwrap_or_else(|| "openid profile email".to_string()),
        };

        Ok(Box::new(FederationBackend {
            name: bx.name.clone(),
            entity_id,
            op_entity_id: cfg.op_entity_id.clone(),
            discovery,
            client,
            client_jwks,
            http: bx.http_client.clone(),
            mapper: bx.attribute_mapper.clone(),
            fed_key,
            authority_hints: fed.authority_hints.clone(),
            trust_anchors,
            ec_lifetime: fed.entity_configuration_lifetime,
            op_cache_ttl: fed.op_cache_ttl,
            organization_name: fed.organization_name.clone(),
            organization_uri: fed.organization_uri.clone(),
            trust_marks: fed.trust_marks.clone(),
            resolved: RwLock::new(HashMap::new()),
        }))
    }

    /// Build and sign this RP's federation entity configuration.
    fn entity_configuration(&self) -> Result<String> {
        let mut relying_party = serde_json::Map::new();
        relying_party.insert(
            "redirect_uris".into(),
            serde_json::json!([self.client.redirect_uri]),
        );
        relying_party.insert(
            "client_registration_types".into(),
            serde_json::json!(["automatic"]),
        );
        relying_party.insert("response_types".into(), serde_json::json!(["code"]));
        relying_party.insert(
            "grant_types".into(),
            serde_json::json!(["authorization_code"]),
        );
        relying_party.insert(
            "token_endpoint_auth_method".into(),
            Value::String("private_key_jwt".into()),
        );
        relying_party.insert("jwks".into(), serde_json::to_value(&self.client_jwks)?);
        relying_party.insert("scope".into(), Value::String(self.client.scope.clone()));
        if let Some(d) = &self.discovery {
            // The discovery service resolves this RP through the federation
            // and sends the user back here (third-party initiated login), so
            // the return endpoint must be published in our metadata.
            relying_party.insert(
                "initiate_login_uri".into(),
                Value::String(d.initiate_login_uri.clone()),
            );
        }
        if let Some(n) = &self.organization_name {
            relying_party.insert("client_name".into(), Value::String(n.clone()));
        }

        let mut federation_entity = serde_json::Map::new();
        if let Some(n) = &self.organization_name {
            federation_entity.insert("organization_name".into(), Value::String(n.clone()));
        }
        if let Some(u) = &self.organization_uri {
            federation_entity.insert("homepage_uri".into(), Value::String(u.clone()));
        }

        let metadata = serde_json::json!({
            "openid_relying_party": Value::Object(relying_party),
            "federation_entity": Value::Object(federation_entity),
        });

        federation::build_entity_configuration(
            &self.fed_key,
            &self.entity_id,
            &self.fed_key.to_public_jwks(),
            &self.authority_hints,
            metadata,
            &self.trust_marks,
            self.ec_lifetime,
        )
    }

    /// Resolve a given OP's metadata through the trust anchors, with a
    /// per-OP TTL cache so steady-state flows do not hit the resolve endpoint.
    async fn resolve_op(&self, op_entity_id: &str) -> Result<ResolvedOp> {
        if let Some((expires, op)) = self
            .resolved
            .read()
            .expect("lock")
            .get(op_entity_id)
            .cloned()
        {
            if expires > now_secs() {
                return Ok(op);
            }
        }

        let resolved =
            federation::resolve_via_trust_anchors(&self.http, op_entity_id, &self.trust_anchors)
                .await?;
        let op_meta = resolved
            .metadata
            .get("openid_provider")
            .ok_or_else(|| Error::Authn("resolved metadata has no openid_provider".into()))?;

        let get = |key: &str| -> Option<String> {
            op_meta.get(key).and_then(|v| v.as_str()).map(String::from)
        };
        let authorization_endpoint = get("authorization_endpoint").ok_or_else(|| {
            Error::Authn("resolved OP metadata has no authorization_endpoint".into())
        })?;
        let token_endpoint = get("token_endpoint")
            .ok_or_else(|| Error::Authn("resolved OP metadata has no token_endpoint".into()))?;
        let op = ResolvedOp {
            entity_id: resolved.subject,
            provider: ProviderInfo {
                issuer: get("issuer").unwrap_or_else(|| op_entity_id.to_string()),
                authorization_endpoint,
                token_endpoint,
                userinfo_endpoint: get("userinfo_endpoint"),
                jwks_uri: get("jwks_uri"),
            },
            metadata: op_meta.clone(),
            federation_jwks: resolved.subject_jwks,
        };

        self.resolved.write().expect("lock").insert(
            op_entity_id.to_string(),
            (now_secs() + self.op_cache_ttl, op.clone()),
        );
        tracing::info!(op = %op_entity_id, "resolved upstream OP via trust anchor");
        Ok(op)
    }

    /// Begin an OIDC code flow with a specific OP: resolve it, mint PKCE +
    /// state + nonce, persist them (and the chosen OP) in the state cookie,
    /// and return the authorization redirect.
    async fn start_auth_with_op(&self, ctx: &mut Context, op_entity_id: &str) -> Result<Response> {
        let op = self.resolve_op(op_entity_id).await?;

        let state = random_token(24);
        let nonce = random_token(24);
        let verifier = random_token(32);
        let challenge = pkce::s256_challenge(&verifier);

        ctx.state.set_str(&self.name, "oidc_state", &state);
        ctx.state.set_str(&self.name, "oidc_nonce", &nonce);
        ctx.state.set_str(&self.name, "code_verifier", &verifier);
        ctx.state.set_str(&self.name, "op_entity_id", op_entity_id);

        // Automatic registration authenticates the authorization request
        // itself: a signed request object (RFC 9101) proves possession of the
        // client keys published in our entity configuration, and federation
        // OPs (e.g. Shibboleth) use it as the trigger to resolve our trust
        // chain on the fly. The plain query parameters stay alongside for
        // OPs that ignore the `request` parameter.
        let ClientAuth::PrivateKeyJwt(client_key) = &self.client.auth else {
            return Err(Error::Internal(
                "federation RP always uses private_key_jwt".into(),
            ));
        };
        let request_object = rp::signed_request_object(
            &op.provider,
            &self.client,
            client_key,
            &state,
            &nonce,
            Some(&challenge),
        )?;

        let url = rp::authorization_url(
            &op.provider,
            &self.client,
            &state,
            &nonce,
            Some(&challenge),
            &[("request", &request_object)],
        );
        Ok(Response::redirect(url))
    }

    // ── In-proxy discovery (kept for reference, see ADR 0025) ───────────────
    //
    // /// Fetch the federation's OP list for the discovery page (TTL-cached). A
    // /// fetch failure yields an empty list (logged), so the page still renders.
    // async fn fetch_op_list(&self, d: &Discovery) -> Vec<federation::CollectionEntity> {
    //     if let Some((expires, list)) = d.op_list_cache.read().expect("lock").clone() {
    //         if expires > now_secs() {
    //             return list;
    //         }
    //     }
    //     match federation::fetch_collection(&self.http, &d.collection_endpoint, "openid_provider")
    //         .await
    //     {
    //         Ok(list) => {
    //             *d.op_list_cache.write().expect("lock") =
    //                 Some((now_secs() + d.cache_ttl, list.clone()));
    //             list
    //         }
    //         Err(e) => {
    //             tracing::error!(error = %e, endpoint = %d.collection_endpoint, "failed to fetch OP collection");
    //             Vec::new()
    //         }
    //     }
    // }
    //
    // /// Render the self-contained OP-selection page.
    // fn render_discovery_page(
    //     &self,
    //     d: &Discovery,
    //     ops: &[federation::CollectionEntity],
    //     error: Option<&str>,
    // ) -> Response {
    //     Response::html(render_discovery_html(&self.name, &d.page_title, ops, error))
    // }

    /// The OP's id_token verification keys via the OpenID Federation JWK set
    /// representations (`jwks`, `signed_jwks_uri`, then `jwks_uri`).
    async fn op_jwks(&self, op: &ResolvedOp) -> Result<JwkSet> {
        federation::entity_metadata_jwks(
            &self.http,
            &op.metadata,
            &op.entity_id,
            &op.federation_jwks,
        )
        .await
    }
}

#[async_trait]
impl Backend for FederationBackend {
    fn name(&self) -> &str {
        &self.name
    }

    fn register_endpoints(&self) -> Vec<Route> {
        let mut routes = vec![
            Route::exact(
                format!("{}/.well-known/openid-federation", self.name),
                "entity_configuration",
            ),
            Route::exact(format!("{}/callback", self.name), "callback"),
        ];
        if self.discovery.is_some() {
            routes.push(Route::exact(format!("{}/initiate", self.name), "initiate"));
            // In-proxy discovery selection endpoint (kept for reference,
            // see ADR 0025):
            // routes.push(Route::exact(format!("{}/disco", self.name), "disco"));
        }
        routes
    }

    async fn start_auth(&self, ctx: &mut Context, _request: InternalData) -> Result<Response> {
        match &self.discovery {
            // Discovery: send the browser to the external discovery service.
            // The frontend's in-flight request already rides the encrypted
            // state cookie, so the round-trip needs no extra server state
            // (cf. ADR 0007); a one-time verifier ties the eventual /initiate
            // return to a redirect this proxy actually issued.
            Some(d) => {
                let verifier = random_token(16);
                ctx.state
                    .set_str(&self.name, DISCOVERY_VERIFIER_KEY, &verifier);
                let target_link_uri = d.target_link_uri(&verifier);
                // A request-path micro-service (e.g. idp_hinting) may have
                // pinned an upstream; forward it as the discovery hint.
                let hint = ctx
                    .decoration(tunnelbana_core::context::KEY_TARGET_ENTITYID)
                    .and_then(|v| v.as_str())
                    .map(str::to_string);
                let url = match discovery::discovery_request_url(
                    &d.service,
                    &self.entity_id,
                    hint.as_deref(),
                    Some(&target_link_uri),
                ) {
                    Ok(url) => url,
                    // A hint that is not a valid entity id must not kill the
                    // flow; the user just picks the OP without a default.
                    Err(e) if hint.is_some() => {
                        tracing::warn!(error = %e, "ignoring unusable OP hint for discovery");
                        discovery::discovery_request_url(
                            &d.service,
                            &self.entity_id,
                            None,
                            Some(&target_link_uri),
                        )?
                    }
                    Err(e) => return Err(e),
                };
                Ok(Response::redirect(url))
            }
            // In-proxy discovery (kept for reference, see ADR 0025): show the
            // OP-selection page rendered by the proxy itself.
            // Some(d) => {
            //     let ops = self.fetch_op_list(d).await;
            //     Ok(self.render_discovery_page(d, &ops, None))
            // }
            // Fixed OP.
            None => {
                let op_entity_id = self
                    .op_entity_id
                    .clone()
                    .expect("op_entity_id present when discovery disabled");
                self.start_auth_with_op(ctx, &op_entity_id).await
            }
        }
    }

    async fn handle_endpoint(&self, ctx: &mut Context, route_id: &str) -> Result<BackendAction> {
        match route_id {
            "entity_configuration" => {
                let jwt = self.entity_configuration()?;
                Ok(BackendAction::Respond(
                    Response::new(200)
                        .with_header("content-type", "application/entity-statement+jwt")
                        .with_body(jwt.into_bytes()),
                ))
            }
            "initiate" => self.handle_initiate(ctx).await,
            // In-proxy discovery (kept for reference, see ADR 0025):
            // "disco" => self.handle_disco(ctx).await,
            "callback" => self.handle_callback(ctx).await,
            other => Err(Error::NoBoundEndpoint(other.to_string())),
        }
    }
}

impl FederationBackend {
    /// Handle the return call from the external discovery service: an OpenID
    /// Connect Core §4 Third-Party Initiated Login carrying the chosen OP in
    /// `iss`. The OP is only used after it resolves through the configured
    /// trust anchors, so the parameter cannot make the proxy authenticate
    /// against an arbitrary issuer.
    async fn handle_initiate(&self, ctx: &mut Context) -> Result<BackendAction> {
        let discovery = self
            .discovery
            .as_ref()
            .ok_or_else(|| Error::NoBoundEndpoint("initiate".into()))?;
        let verifier = ctx
            .state
            .get_str(&self.name, DISCOVERY_VERIFIER_KEY)
            .ok_or_else(|| {
                Error::Authn(
                    "third-party initiated login without a discovery flow in flight".into(),
                )
            })?;
        let login = discovery::parse_third_party_initiated_login(&ctx.request.query)?;
        let expected_target_link_uri = discovery.target_link_uri(&verifier);
        if login.target_link_uri.as_deref() != Some(expected_target_link_uri.as_str()) {
            return Err(Error::Authn(
                "third-party initiated login missing or mismatched target_link_uri".into(),
            ));
        }
        // `target_link_uri` is for session-less RPs; here it is only a
        // one-time return-path verifier and is never used as a redirect target.
        let redirect = self.start_auth_with_op(ctx, &login.iss).await?;
        ctx.state
            .set_value(&self.name, DISCOVERY_VERIFIER_KEY, Value::Null);
        Ok(BackendAction::Respond(redirect))
    }

    // ── In-proxy discovery (kept for reference, see ADR 0025) ───────────────
    //
    // /// Handle an OP selection from the discovery page: validate the chosen
    // /// entity against the federation's OP list, then start auth with it.
    // async fn handle_disco(&self, ctx: &mut Context) -> Result<BackendAction> {
    //     let d = self
    //         .discovery
    //         .as_ref()
    //         .ok_or_else(|| Error::NoBoundEndpoint("disco".into()))?;
    //
    //     let selected = ctx
    //         .request
    //         .param("entity_id")
    //         .map(str::to_string)
    //         .filter(|s| !s.is_empty());
    //     let ops = self.fetch_op_list(d).await;
    //
    //     let Some(selected) = selected else {
    //         return Ok(BackendAction::Respond(self.render_discovery_page(
    //             d,
    //             &ops,
    //             Some("Please select an identity provider."),
    //         )));
    //     };
    //     // Only entities the trust anchor actually lists are accepted, so the
    //     // selection cannot be used to make the proxy resolve arbitrary ids.
    //     if !ops.iter().any(|e| e.entity_id == selected) {
    //         return Ok(BackendAction::Respond(self.render_discovery_page(
    //             d,
    //             &ops,
    //             Some("Unknown identity provider; please choose one from the list."),
    //         )));
    //     }
    //     match self.start_auth_with_op(ctx, &selected).await {
    //         Ok(redirect) => Ok(BackendAction::Respond(redirect)),
    //         Err(e) => Ok(BackendAction::Respond(self.render_discovery_page(
    //             d,
    //             &ops,
    //             Some(&format!("Could not start login with that provider: {e}")),
    //         ))),
    //     }
    // }

    async fn handle_callback(&self, ctx: &mut Context) -> Result<BackendAction> {
        // CSRF: state must match what we stored at start_auth.
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

        // The OP chosen at start (fixed or via discovery) was persisted in state.
        let op_entity_id = ctx
            .state
            .get_str(&self.name, "op_entity_id")
            .ok_or_else(|| Error::State("no OP selected in state".into()))?;
        let op = self.resolve_op(&op_entity_id).await?;
        let tokens = rp::exchange_code(
            &self.http,
            &op.provider,
            &self.client,
            &code,
            verifier.as_deref(),
        )
        .await?;

        let id_token = tokens
            .id_token
            .as_ref()
            .ok_or_else(|| Error::Authn("no id_token in token response".into()))?;
        let jwks = self.op_jwks(&op).await?;
        let id_claims = rp::verify_id_token(
            &jwks,
            id_token,
            &op.provider.issuer,
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
            (&op.provider.userinfo_endpoint, &tokens.access_token)
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
                issuer: Some(op.provider.issuer.clone()),
            },
            requester: None,
            requester_name: Vec::new(),
            subject_id: Some(sub),
            subject_type: SubjectType::Pairwise,
            attributes: internal_attrs,
        };

        ctx.state.clear_namespace(&self.name);
        Ok(BackendAction::AuthResponse(response))
    }
}

fn merge_json(base: &mut Value, extra: &Value) {
    if let (Some(b), Some(e)) = (base.as_object_mut(), extra.as_object()) {
        for (k, v) in e {
            b.entry(k.clone()).or_insert_with(|| v.clone());
        }
    }
}

// ── In-proxy discovery (kept for reference, see ADR 0025) ──────────────────
//
// /// Minimal HTML attribute/text escaping for the discovery page.
// fn html_escape(s: &str) -> String {
//     let mut out = String::with_capacity(s.len());
//     for c in s.chars() {
//         match c {
//             '&' => out.push_str("&amp;"),
//             '<' => out.push_str("&lt;"),
//             '>' => out.push_str("&gt;"),
//             '"' => out.push_str("&quot;"),
//             '\'' => out.push_str("&#x27;"),
//             _ => out.push(c),
//         }
//     }
//     out
// }
//
// /// Render the self-contained OP-selection page. Each OP is a form that POSTs
// /// its `entity_id` back to `/<name>/disco`.
// fn render_discovery_html(
//     name: &str,
//     page_title: &str,
//     ops: &[federation::CollectionEntity],
//     error: Option<&str>,
// ) -> String {
//     let title = html_escape(page_title);
//     let action = format!("/{}/disco", html_escape(name));
//
//     let error_html = error
//         .map(|e| {
//             format!(
//                 r#"<div class="error" role="alert">{}</div>"#,
//                 html_escape(e)
//             )
//         })
//         .unwrap_or_default();
//
//     let items = if ops.is_empty() {
//         r#"<p class="empty">No identity providers are available right now.</p>"#.to_string()
//     } else {
//         ops.iter()
//             .map(|op| {
//                 let eid = html_escape(&op.entity_id);
//                 let display = html_escape(&op.display_name);
//                 let logo = match &op.logo_uri {
//                     Some(u) if !u.is_empty() => format!(
//                         r#"<img class="logo" src="{}" alt="" width="28" height="28">"#,
//                         html_escape(u)
//                     ),
//                     _ => r#"<span class="logo placeholder" aria-hidden="true">&#127970;</span>"#
//                         .to_string(),
//                 };
//                 format!(
//                     r#"<form method="post" action="{action}">
// <input type="hidden" name="entity_id" value="{eid}">
// <button type="submit" class="op">{logo}<span class="meta"><span class="name">{display}</span><span class="eid">{eid}</span></span></button>
// </form>"#
//                 )
//             })
//             .collect::<Vec<_>>()
//             .join("\n")
//     };
//
//     format!(
//         r#"<!DOCTYPE html>
// <html lang="en">
// <head>
// <meta charset="utf-8">
// <meta name="viewport" content="width=device-width, initial-scale=1">
// <title>{title}</title>
// <style>
// :root {{ color-scheme: light dark; }}
// * {{ box-sizing: border-box; }}
// body {{ margin: 0; min-height: 100vh; display: flex; align-items: center; justify-content: center;
//   font-family: system-ui, -apple-system, "Segoe UI", Roboto, sans-serif; background: #f5f6f8; color: #1c1e21; }}
// .card {{ background: #fff; max-width: 28rem; width: calc(100% - 2rem); margin: 2rem auto;
//   border-radius: 12px; box-shadow: 0 1px 3px rgba(0,0,0,.12), 0 8px 24px rgba(0,0,0,.08); padding: 1.75rem; }}
// h1 {{ font-size: 1.25rem; margin: 0 0 1.25rem; }}
// .error {{ background: #fdecea; color: #8a1c1c; border-radius: 8px; padding: .6rem .8rem; margin-bottom: 1rem; font-size: .9rem; }}
// .empty {{ color: #65676b; font-size: .95rem; }}
// form {{ margin: 0 0 .6rem; }}
// .op {{ display: flex; align-items: center; gap: .85rem; width: 100%; text-align: left; cursor: pointer;
//   background: #fff; border: 1px solid #dadde1; border-radius: 10px; padding: .7rem .9rem; font: inherit; color: inherit; }}
// .op:hover {{ border-color: #1877f2; background: #f0f6ff; }}
// .logo {{ flex: 0 0 28px; width: 28px; height: 28px; border-radius: 6px; display: inline-flex; align-items: center; justify-content: center; }}
// .logo.placeholder {{ background: #e4e6eb; font-size: 1rem; }}
// .meta {{ display: flex; flex-direction: column; min-width: 0; }}
// .name {{ font-weight: 600; }}
// .eid {{ color: #65676b; font-size: .8rem; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }}
// @media (prefers-color-scheme: dark) {{
//   body {{ background: #18191a; color: #e4e6eb; }}
//   .card {{ background: #242526; box-shadow: none; }}
//   .op {{ background: #3a3b3c; border-color: #3e4042; }}
//   .op:hover {{ background: #2d3a4f; border-color: #1877f2; }}
//   .logo.placeholder {{ background: #4e4f50; }}
//   .eid {{ color: #b0b3b8; }}
// }}
// </style>
// </head>
// <body>
// <main class="card">
// <h1>{title}</h1>
// {error_html}
// {items}
// </main>
// </body>
// </html>"#
//     )
// }
