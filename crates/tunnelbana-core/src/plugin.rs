//! Plugin traits (Frontend, Backend, MicroService), the values they return into
//! the proxy flow, and a static constructor registry.

use crate::attributes::AttributeMapper;
use crate::context::Context;
use crate::error::Result;
use crate::http::{HttpClient, Response};
use crate::internal::InternalData;
use std::collections::HashMap;
use std::sync::Arc;

/// A registered endpoint: a path matcher plus an opaque handler id the plugin
/// understands.
#[derive(Clone)]
pub struct Route {
    pub pattern: regex::Regex,
    pub id: String,
}

impl Route {
    /// Build a route from an anchored or unanchored regex pattern.
    pub fn new(pattern: &str, id: impl Into<String>) -> Self {
        let anchored = if pattern.starts_with('^') {
            pattern.to_string()
        } else {
            format!("^{pattern}$")
        };
        Route {
            pattern: regex::Regex::new(&anchored).expect("invalid route regex"),
            id: id.into(),
        }
    }
}

/// What a frontend endpoint produced.
pub enum FrontendAction {
    /// A complete HTTP response (e.g. discovery doc, jwks, token endpoint).
    Respond(Response),
    /// Begin authentication: forward this request to a backend. Optionally pin
    /// a target backend by name.
    StartAuth {
        request: InternalData,
        target_backend: Option<String>,
    },
}

/// What a backend endpoint produced.
pub enum BackendAction {
    /// A complete HTTP response (e.g. SP metadata).
    Respond(Response),
    /// An authentication response to forward back to the originating frontend.
    AuthResponse(InternalData),
}

/// A frontend speaks a protocol to downstream RPs/SPs.
#[async_trait::async_trait]
pub trait Frontend: Send + Sync {
    fn name(&self) -> &str;

    /// Register the endpoints this frontend serves. `backend_names` lets a
    /// frontend mount per-backend routes if it wishes.
    fn register_endpoints(&self, backend_names: &[String]) -> Vec<Route>;

    /// Handle an inbound hit on one of this frontend's endpoints.
    async fn handle_endpoint(&self, ctx: &mut Context, route_id: &str) -> Result<FrontendAction>;

    /// Render an internal authentication response back into the frontend's
    /// protocol (e.g. a signed SAML Response or an OIDC redirect/id_token).
    async fn handle_authn_response(
        &self,
        ctx: &mut Context,
        response: InternalData,
    ) -> Result<Response>;

    /// Render an error back to the downstream RP/SP.
    async fn handle_backend_error(
        &self,
        ctx: &mut Context,
        error: &crate::error::Error,
    ) -> Result<Response>;
}

/// A backend speaks a protocol to upstream IdPs/OPs.
#[async_trait::async_trait]
pub trait Backend: Send + Sync {
    fn name(&self) -> &str;

    fn register_endpoints(&self) -> Vec<Route>;

    /// Begin authentication with the upstream IdP/OP (returns e.g. a redirect).
    async fn start_auth(&self, ctx: &mut Context, request: InternalData) -> Result<Response>;

    /// Handle an inbound hit on one of this backend's endpoints (e.g. ACS).
    async fn handle_endpoint(&self, ctx: &mut Context, route_id: &str) -> Result<BackendAction>;
}

/// A micro-service intercepts the request and/or response path.
#[async_trait::async_trait]
pub trait MicroService: Send + Sync {
    fn name(&self) -> &str;

    /// Transform the request-path internal data (frontend → backend).
    async fn process_request(
        &self,
        _ctx: &mut Context,
        data: InternalData,
    ) -> Result<InternalData> {
        Ok(data)
    }

    /// Transform the response-path internal data (backend → frontend).
    async fn process_response(
        &self,
        _ctx: &mut Context,
        data: InternalData,
    ) -> Result<InternalData> {
        Ok(data)
    }

    /// Optional endpoints (e.g. a consent callback).
    fn register_endpoints(&self) -> Vec<Route> {
        Vec::new()
    }

    /// Handle an inbound hit on one of this micro-service's endpoints.
    async fn handle_endpoint(&self, _ctx: &mut Context, _route_id: &str) -> Result<Response> {
        Err(crate::error::Error::NoBoundEndpoint(
            "micro-service endpoint not implemented".into(),
        ))
    }
}

/// Shared services handed to plugin constructors.
pub struct BuildContext {
    pub name: String,
    pub base_url: String,
    pub config: serde_json::Value,
    pub attribute_mapper: Arc<AttributeMapper>,
    pub http_client: Arc<dyn HttpClient>,
    /// The global state-encryption secret, for plugins to derive their own
    /// domain-separated keys (e.g. the OIDC token codec key).
    pub secret: String,
    /// Previous state-encryption secrets, for decryption only — lets plugins
    /// (e.g. the OIDC token codec) keep opening material sealed before a key
    /// rotation. Never used to seal new tokens.
    pub previous_secrets: Vec<String>,
}

impl BuildContext {
    /// Deserialize the plugin config into a typed struct.
    pub fn parse_config<T: serde::de::DeserializeOwned>(&self) -> Result<T> {
        serde_json::from_value(self.config.clone())
            .map_err(|e| crate::error::Error::Config(format!("plugin {}: {e}", self.name)))
    }

    /// This module's URL prefix, e.g. `https://proxy/<name>`.
    pub fn module_base(&self) -> String {
        format!("{}/{}", self.base_url.trim_end_matches('/'), self.name)
    }
}

type FrontendCtor = fn(&BuildContext) -> Result<Box<dyn Frontend>>;
type BackendCtor = fn(&BuildContext) -> Result<Box<dyn Backend>>;
type MicroServiceCtor = fn(&BuildContext) -> Result<Box<dyn MicroService>>;

/// Maps a `type` string from config to a plugin constructor.
#[derive(Default)]
pub struct Registry {
    frontends: HashMap<String, FrontendCtor>,
    backends: HashMap<String, BackendCtor>,
    microservices: HashMap<String, MicroServiceCtor>,
}

impl Registry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register_frontend(&mut self, kind: &str, ctor: FrontendCtor) {
        self.frontends.insert(kind.to_string(), ctor);
    }
    pub fn register_backend(&mut self, kind: &str, ctor: BackendCtor) {
        self.backends.insert(kind.to_string(), ctor);
    }
    pub fn register_microservice(&mut self, kind: &str, ctor: MicroServiceCtor) {
        self.microservices.insert(kind.to_string(), ctor);
    }

    pub fn build_frontend(&self, kind: &str, bx: &BuildContext) -> Result<Box<dyn Frontend>> {
        let ctor = self
            .frontends
            .get(kind)
            .ok_or_else(|| crate::error::Error::UnknownModule(format!("frontend type {kind}")))?;
        ctor(bx)
    }
    pub fn build_backend(&self, kind: &str, bx: &BuildContext) -> Result<Box<dyn Backend>> {
        let ctor = self
            .backends
            .get(kind)
            .ok_or_else(|| crate::error::Error::UnknownModule(format!("backend type {kind}")))?;
        ctor(bx)
    }
    pub fn build_microservice(
        &self,
        kind: &str,
        bx: &BuildContext,
    ) -> Result<Box<dyn MicroService>> {
        let ctor = self.microservices.get(kind).ok_or_else(|| {
            crate::error::Error::UnknownModule(format!("microservice type {kind}"))
        })?;
        ctor(bx)
    }
}

/// A no-op outbound client useful for tests.
pub struct NullHttpClient;

#[async_trait::async_trait]
impl HttpClient for NullHttpClient {
    async fn get(&self, _url: &str) -> Result<crate::http::HttpFetchResponse> {
        Err(crate::error::Error::Internal(
            "no http client configured".into(),
        ))
    }
    async fn post_form(
        &self,
        _url: &str,
        _form: &[(String, String)],
        _headers: &[(String, String)],
    ) -> Result<crate::http::HttpFetchResponse> {
        Err(crate::error::Error::Internal(
            "no http client configured".into(),
        ))
    }
}
