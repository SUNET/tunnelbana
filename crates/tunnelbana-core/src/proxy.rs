//! The proxy orchestrator: load state → route → dispatch → save state.
//!
//! This is the Rust analogue of SATOSA's `base.py:SATOSABase.run`.

use crate::context::{Context, STATE_KEY_BASE};
use crate::error::{Error, Result};
use crate::http::{HttpRequestData, Response};
use crate::plugin::{Backend, BackendAction, Frontend, FrontendAction, MicroService};
use crate::router::{ModuleKind, Router};
use crate::state::StateSealer;
use std::collections::HashMap;

/// Key within the base state namespace recording the originating frontend.
const KEY_TARGET_FRONTEND: &str = "target_frontend";

/// A fully assembled proxy ready to serve requests.
pub struct Proxy {
    frontends: HashMap<String, Box<dyn Frontend>>,
    backends: HashMap<String, Box<dyn Backend>>,
    /// Micro-services in pipeline order (request path forward, response path forward).
    microservices: Vec<Box<dyn MicroService>>,
    router: Router,
    sealer: StateSealer,
    /// Default backend used when none is pinned by the frontend or a micro-service.
    default_backend: Option<String>,
}

impl Proxy {
    /// Assemble a proxy from already-instantiated plugins.
    pub fn new(
        frontends: Vec<Box<dyn Frontend>>,
        backends: Vec<Box<dyn Backend>>,
        microservices: Vec<Box<dyn MicroService>>,
        sealer: StateSealer,
    ) -> Self {
        let backend_names: Vec<String> = backends.iter().map(|b| b.name().to_string()).collect();
        let default_backend = backend_names.first().cloned();

        let mut router = Router::new();
        // Precedence: frontends, then micro-services, then backends.
        for f in &frontends {
            router.add(
                ModuleKind::Frontend,
                f.name(),
                &f.register_endpoints(&backend_names),
            );
        }
        for m in &microservices {
            router.add(ModuleKind::MicroService, m.name(), &m.register_endpoints());
        }
        for b in &backends {
            router.add(ModuleKind::Backend, b.name(), &b.register_endpoints());
        }

        let frontends = frontends
            .into_iter()
            .map(|f| (f.name().to_string(), f))
            .collect();
        let backends = backends
            .into_iter()
            .map(|b| (b.name().to_string(), b))
            .collect();

        Self {
            frontends,
            backends,
            microservices,
            router,
            sealer,
            default_backend,
        }
    }

    pub fn sealer(&self) -> &StateSealer {
        &self.sealer
    }

    /// Run the full request flow and return a response (with the state cookie
    /// attached).
    pub async fn run(&self, request: HttpRequestData) -> Response {
        let cookie_value = request.cookies.get(self.sealer.cookie_name()).cloned();
        let state = self.sealer.unseal(cookie_value.as_deref());
        let mut ctx = Context::new(request, state);

        let result = self.dispatch(&mut ctx).await;

        let mut response = match result {
            Ok(r) => r,
            Err(e) => self.render_error(&mut ctx, e).await,
        };

        // Attach the (possibly cleared) state cookie.
        if let Ok(cookie) = self.sealer.seal(&ctx.state) {
            response.headers.push(("set-cookie".to_string(), cookie));
        }
        response
    }

    async fn dispatch(&self, ctx: &mut Context) -> Result<Response> {
        let path = ctx.path().to_string();
        let m = self
            .router
            .resolve(&path)
            .ok_or_else(|| Error::NoBoundEndpoint(path.clone()))?;

        match m.kind {
            ModuleKind::Frontend => self.dispatch_frontend(ctx, &m.module, &m.route_id).await,
            ModuleKind::Backend => self.dispatch_backend(ctx, &m.module, &m.route_id).await,
            ModuleKind::MicroService => {
                let ms = self
                    .microservices
                    .iter()
                    .find(|x| x.name() == m.module)
                    .ok_or_else(|| Error::UnknownModule(m.module.clone()))?;
                ms.handle_endpoint(ctx, &m.route_id).await
            }
        }
    }

    async fn dispatch_frontend(
        &self,
        ctx: &mut Context,
        module: &str,
        route_id: &str,
    ) -> Result<Response> {
        ctx.target_frontend = Some(module.to_string());
        let frontend = self
            .frontends
            .get(module)
            .ok_or_else(|| Error::UnknownModule(module.to_string()))?;

        match frontend.handle_endpoint(ctx, route_id).await? {
            FrontendAction::Respond(r) => Ok(r),
            FrontendAction::StartAuth {
                mut request,
                target_backend,
            } => {
                // Record requester + originating frontend for the return path.
                if let Some(req) = request.requester.clone() {
                    ctx.set_requester(&req);
                }
                ctx.state
                    .set_str(STATE_KEY_BASE, KEY_TARGET_FRONTEND, module);

                // Request-path micro-services.
                for ms in &self.microservices {
                    request = ms.process_request(ctx, request).await?;
                }

                // Select backend: explicit pin > micro-service pin > default.
                let backend_name = target_backend
                    .or_else(|| ctx.target_backend.clone())
                    .or_else(|| self.default_backend.clone())
                    .ok_or_else(|| Error::Config("no backend configured".into()))?;
                ctx.target_backend = Some(backend_name.clone());

                let backend = self
                    .backends
                    .get(&backend_name)
                    .ok_or_else(|| Error::UnknownModule(backend_name.clone()))?;
                backend.start_auth(ctx, request).await
            }
        }
    }

    async fn dispatch_backend(
        &self,
        ctx: &mut Context,
        module: &str,
        route_id: &str,
    ) -> Result<Response> {
        ctx.target_backend = Some(module.to_string());
        let backend = self
            .backends
            .get(module)
            .ok_or_else(|| Error::UnknownModule(module.to_string()))?;

        match backend.handle_endpoint(ctx, route_id).await? {
            BackendAction::Respond(r) => Ok(r),
            BackendAction::AuthResponse(mut response) => {
                // Recover originating frontend and requester before response-path
                // micro-services so requester-scoped policy sees the same data
                // the frontend will render.
                let frontend_name = ctx
                    .state
                    .get_str(STATE_KEY_BASE, KEY_TARGET_FRONTEND)
                    .or_else(|| ctx.target_frontend.clone())
                    .ok_or_else(|| Error::State("no originating frontend in state".into()))?;
                ctx.target_frontend = Some(frontend_name.clone());

                if response.requester.is_none() {
                    response.requester = ctx.requester();
                }

                // Response-path micro-services.
                for ms in &self.microservices {
                    response = ms.process_response(ctx, response).await?;
                }

                let frontend = self
                    .frontends
                    .get(&frontend_name)
                    .ok_or_else(|| Error::UnknownModule(frontend_name.clone()))?;
                let resp = frontend.handle_authn_response(ctx, response).await?;
                // Session complete — clear the state cookie.
                ctx.state.delete = true;
                Ok(resp)
            }
        }
    }

    /// Render an error, preferring the originating frontend's protocol error
    /// rendering when one is known.
    async fn render_error(&self, ctx: &mut Context, error: Error) -> Response {
        let status = error.status_hint();
        if let Some(fe_name) = ctx
            .target_frontend
            .clone()
            .or_else(|| ctx.state.get_str(STATE_KEY_BASE, KEY_TARGET_FRONTEND))
        {
            if let Some(frontend) = self.frontends.get(&fe_name) {
                if let Ok(r) = frontend.handle_backend_error(ctx, &error).await {
                    return r;
                }
            }
        }
        tracing::warn!(error = %error, "request failed");
        Response::text(status, format!("{error}"))
    }
}
