//! The proxy orchestrator: load state → route → dispatch → save state.
//!
//! This is the Rust analogue of SATOSA's `base.py:SATOSABase.run`.

use crate::context::{Context, STATE_KEY_BASE};
use crate::error::{Error, Result};
use crate::http::{HttpRequestData, Response};
use crate::internal::InternalData;
use crate::plugin::{
    Backend, BackendAction, Frontend, FrontendAction, MicroService, MicroServiceAction,
    MicroServiceResponseAction,
};
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

        // Attach the (possibly cleared) state cookie. A response whose state
        // cannot be sealed (e.g. over the cookie size limit) must NOT go out
        // without it: the client would continue a multi-step flow (discovery,
        // ACS return) that can never resume. Fail the request explicitly and
        // clear the broken state instead.
        match self.sealer.seal(&ctx.state) {
            Ok(cookie) => response.headers.push(("set-cookie".to_string(), cookie)),
            Err(e) => {
                tracing::error!(error = %e, "failed to seal state cookie; failing the request");
                response = Response::text(500, "request failed");
                let mut cleared = crate::state::State::new();
                cleared.delete = true;
                if let Ok(cookie) = self.sealer.seal(&cleared) {
                    response.headers.push(("set-cookie".to_string(), cookie));
                }
            }
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
                let idx = self
                    .microservices
                    .iter()
                    .position(|x| x.name() == m.module)
                    .ok_or_else(|| Error::UnknownModule(m.module.clone()))?;
                match self.microservices[idx]
                    .handle_endpoint(ctx, &m.route_id)
                    .await?
                {
                    MicroServiceAction::Respond(r) => Ok(r),
                    MicroServiceAction::ResumeRequest { request } => {
                        // The resuming service restored ctx.target_frontend from
                        // its snapshot; fall back to the state cookie, and fail
                        // cleanly when no originating frontend is recoverable.
                        let frontend_name = ctx
                            .target_frontend
                            .clone()
                            .or_else(|| ctx.state.get_str(STATE_KEY_BASE, KEY_TARGET_FRONTEND))
                            .ok_or_else(|| {
                                Error::State("resume without an originating frontend".into())
                            })?;
                        ctx.target_frontend = Some(frontend_name.clone());
                        ctx.state
                            .set_str(STATE_KEY_BASE, KEY_TARGET_FRONTEND, &frontend_name);
                        // Persist the restored requester exactly as the
                        // initial frontend dispatch does: backends answer with
                        // `requester: None` and `dispatch_backend` refills it
                        // from base state, so without this the response path
                        // would run under a stale (or missing) requester while
                        // the request path ran under the snapshot's.
                        if let Some(req) = request.requester.clone() {
                            ctx.set_requester(&req);
                        }
                        // Resume with the micro-services *after* the resuming
                        // one (SATOSA parity: `super().process` continues the
                        // remaining chain), then dispatch to a backend.
                        self.finish_request(ctx, request, idx + 1, None).await
                    }
                    MicroServiceAction::ResumeResponse { response } => {
                        self.finish_response(ctx, response, idx + 1).await
                    }
                }
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
                request,
                target_backend,
            } => {
                // Record requester + originating frontend for the return path.
                if let Some(req) = request.requester.clone() {
                    ctx.set_requester(&req);
                }
                ctx.state
                    .set_str(STATE_KEY_BASE, KEY_TARGET_FRONTEND, module);

                self.finish_request(ctx, request, 0, target_backend).await
            }
        }
    }

    /// Run the request-path micro-services from `start_index`, select a
    /// backend and start authentication. Entered with `start_index == 0` from
    /// frontend dispatch, or mid-chain when a micro-service endpoint resumes a
    /// suspended flow ([`MicroServiceAction::ResumeRequest`]).
    async fn finish_request(
        &self,
        ctx: &mut Context,
        mut request: InternalData,
        start_index: usize,
        pinned_backend: Option<String>,
    ) -> Result<Response> {
        for ms in self.microservices.iter().skip(start_index) {
            request = ms.process_request(ctx, request).await?;
        }

        // Select backend: explicit pin > micro-service pin > default.
        let backend_name = pinned_backend
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

                self.finish_response(ctx, response, 0).await
            }
        }
    }

    /// Run response-path micro-services from `start_index`, then render the
    /// final result through the originating frontend. A service may interrupt
    /// the chain with an HTTP response and later resume it from its endpoint.
    async fn finish_response(
        &self,
        ctx: &mut Context,
        mut response: InternalData,
        start_index: usize,
    ) -> Result<Response> {
        for ms in self.microservices.iter().skip(start_index) {
            match ms.process_response_action(ctx, response).await? {
                MicroServiceResponseAction::Continue(next) => response = next,
                MicroServiceResponseAction::Respond(http) => return Ok(http),
            }
        }

        let frontend_name = ctx
            .target_frontend
            .clone()
            .or_else(|| ctx.state.get_str(STATE_KEY_BASE, KEY_TARGET_FRONTEND))
            .ok_or_else(|| Error::State("no originating frontend in state".into()))?;
        ctx.target_frontend = Some(frontend_name.clone());
        let frontend = self
            .frontends
            .get(&frontend_name)
            .ok_or(Error::UnknownModule(frontend_name))?;
        let rendered = frontend.handle_authn_response(ctx, response).await?;
        // Session complete — clear the state cookie. Interrupted response
        // chains deliberately retain it until their callback resumes here.
        ctx.state.delete = true;
        Ok(rendered)
    }

    /// Render an error, preferring an error-redirect decoration, then the
    /// originating frontend's protocol error rendering when one is known.
    async fn render_error(&self, ctx: &mut Context, error: Error) -> Response {
        if let Some(url) = ctx
            .decoration(crate::context::KEY_ERROR_REDIRECT)
            .and_then(|v| v.as_str())
        {
            if is_valid_error_redirect(url) {
                tracing::warn!(error = %error, redirect = url, "request failed; redirecting");
                return Response::redirect(url);
            }
            tracing::warn!(
                error = %error,
                "ignoring error_redirect decoration that is not an absolute http(s) URL"
            );
        }
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
        // Internal error details stay in the server log; clients get a generic body.
        Response::text(status, "request failed")
    }
}

/// An `error_redirect` decoration is written by micro-services (including
/// operator-supplied Python code) and is emitted verbatim as a `Location`
/// header. Require an absolute http(s) URL with a non-empty authority and no
/// control characters or spaces, so a value that was (against guidance)
/// derived from request input cannot smuggle a scheme such as `javascript:`
/// or split the response header.
fn is_valid_error_redirect(url: &str) -> bool {
    let rest = ["https://", "http://"].iter().find_map(|scheme| {
        url.get(..scheme.len())
            .filter(|prefix| prefix.eq_ignore_ascii_case(scheme))
            .map(|_| &url[scheme.len()..])
    });
    match rest {
        Some(rest) if !rest.is_empty() => !url.chars().any(|c| c.is_ascii_control() || c == ' '),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::KEY_ERROR_REDIRECT;
    use crate::state::State;

    #[test]
    fn error_redirect_validation_accepts_only_absolute_http_urls() {
        assert!(is_valid_error_redirect("https://sp.example/error"));
        assert!(is_valid_error_redirect("http://sp.example/error?code=x"));
        assert!(is_valid_error_redirect("HTTPS://sp.example/error"));

        for url in [
            "",
            "https://",
            "http://",
            "javascript:alert(1)",
            "data:text/html,x",
            "//evil.example/phish",
            "/relative/path",
            "https://sp.example/\r\nSet-Cookie: x=y",
            "https://sp.example/a b",
            "httpsx://sp.example/",
        ] {
            assert!(!is_valid_error_redirect(url), "accepted {url:?}");
        }
    }

    #[tokio::test]
    async fn valid_error_redirect_decoration_redirects() {
        let sealer = StateSealer::new("a-32-byte-or-longer-test-secret!!", "TB_STATE");
        let proxy = Proxy::new(vec![], vec![], vec![], sealer);
        let mut ctx = Context::new(HttpRequestData::default(), State::new());
        ctx.decorate(
            KEY_ERROR_REDIRECT,
            serde_json::Value::String("https://sp.example/error".into()),
        );
        let response = proxy
            .render_error(&mut ctx, Error::Internal("boom".into()))
            .await;
        assert_eq!(response.status, 302);
        assert!(response
            .headers
            .iter()
            .any(|(n, v)| n == "location" && v == "https://sp.example/error"));
    }

    #[tokio::test]
    async fn invalid_error_redirect_decoration_falls_back_to_generic_error() {
        let sealer = StateSealer::new("a-32-byte-or-longer-test-secret!!", "TB_STATE");
        let proxy = Proxy::new(vec![], vec![], vec![], sealer);
        for url in ["javascript:alert(1)", "https://sp.example/\r\nX: y"] {
            let mut ctx = Context::new(HttpRequestData::default(), State::new());
            ctx.decorate(KEY_ERROR_REDIRECT, serde_json::Value::String(url.into()));
            let response = proxy
                .render_error(&mut ctx, Error::Internal("boom".into()))
                .await;
            assert_ne!(response.status, 302);
            assert!(response.headers.iter().all(|(n, _)| n != "location"));
            assert_eq!(String::from_utf8(response.body).unwrap(), "request failed");
        }
    }

    struct RecordingService {
        name: String,
        calls: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
        resume: bool,
    }

    #[async_trait::async_trait]
    impl MicroService for RecordingService {
        fn name(&self) -> &str {
            &self.name
        }

        async fn process_request(
            &self,
            _ctx: &mut Context,
            data: crate::internal::InternalData,
        ) -> crate::error::Result<crate::internal::InternalData> {
            self.calls.lock().unwrap().push(self.name.clone());
            Ok(data)
        }

        fn register_endpoints(&self) -> Vec<crate::plugin::Route> {
            if self.resume {
                vec![crate::plugin::Route::exact("resume-here", "resume")]
            } else {
                Vec::new()
            }
        }

        async fn handle_endpoint(
            &self,
            ctx: &mut Context,
            _route_id: &str,
        ) -> crate::error::Result<MicroServiceAction> {
            // Mimic a discovery-style service: restore the originating
            // frontend (when one was recorded) and hand back the flow data.
            ctx.target_frontend = ctx.state.get_str(STATE_KEY_BASE, KEY_TARGET_FRONTEND);
            Ok(MicroServiceAction::ResumeRequest {
                request: crate::internal::InternalData::request("sp-resumed"),
            })
        }
    }

    struct RecordingBackend {
        received: std::sync::Arc<std::sync::Mutex<Option<crate::internal::InternalData>>>,
    }

    #[async_trait::async_trait]
    impl Backend for RecordingBackend {
        fn name(&self) -> &str {
            "backend"
        }
        fn register_endpoints(&self) -> Vec<crate::plugin::Route> {
            Vec::new()
        }
        async fn start_auth(
            &self,
            _ctx: &mut Context,
            request: crate::internal::InternalData,
        ) -> crate::error::Result<Response> {
            *self.received.lock().unwrap() = Some(request);
            Ok(Response::text(200, "auth started"))
        }
        async fn handle_endpoint(
            &self,
            _ctx: &mut Context,
            _route_id: &str,
        ) -> crate::error::Result<BackendAction> {
            Ok(BackendAction::Respond(Response::text(200, "ok")))
        }
    }

    fn resume_proxy(
        calls: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
        received: std::sync::Arc<std::sync::Mutex<Option<crate::internal::InternalData>>>,
    ) -> Proxy {
        let services: Vec<Box<dyn MicroService>> = vec![
            Box::new(RecordingService {
                name: "before".into(),
                calls: calls.clone(),
                resume: false,
            }),
            Box::new(RecordingService {
                name: "resumer".into(),
                calls: calls.clone(),
                resume: true,
            }),
            Box::new(RecordingService {
                name: "after".into(),
                calls,
                resume: false,
            }),
        ];
        let sealer = StateSealer::new("a-32-byte-or-longer-test-secret!!", "TB_STATE");
        Proxy::new(
            vec![],
            vec![Box::new(RecordingBackend { received })],
            services,
            sealer,
        )
    }

    /// The happy-path resume contract: a `ResumeRequest` from a mid-chain
    /// micro-service endpoint (1) runs only the request-path services listed
    /// *after* the resuming one, (2) hands the restored `InternalData` to
    /// the backend, and (3) persists the restored requester into base state
    /// - the same bookkeeping the initial frontend dispatch performs - so
    /// the later response path (which refills `response.requester` from base
    /// state) sees the requester the resumed request ran under.
    #[tokio::test]
    async fn resume_runs_only_later_services_and_reaches_backend() {
        let calls = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let received = std::sync::Arc::new(std::sync::Mutex::new(None));
        let proxy = resume_proxy(calls.clone(), received.clone());

        // Seed a state cookie that carries the originating frontend, as the
        // first pass through the frontend would have.
        let mut state = State::new();
        state.set_str(STATE_KEY_BASE, KEY_TARGET_FRONTEND, "frontend");
        let cookie = proxy.sealer().seal(&state).unwrap();
        let cookie_value = cookie
            .split_once(';')
            .map(|(nv, _)| nv)
            .and_then(|nv| nv.split_once('='))
            .map(|(_, v)| v.to_string())
            .unwrap();

        let mut request = HttpRequestData {
            path: "resume-here".to_string(),
            ..Default::default()
        };
        request
            .cookies
            .insert(proxy.sealer().cookie_name().to_string(), cookie_value);

        let response = proxy.run(request).await;
        assert_eq!(String::from_utf8(response.body).unwrap(), "auth started");
        // Only the services after the resuming one ran.
        assert_eq!(*calls.lock().unwrap(), vec!["after".to_string()]);
        // The backend received the restored data.
        assert_eq!(
            received
                .lock()
                .unwrap()
                .as_ref()
                .and_then(|d| d.requester.clone())
                .as_deref(),
            Some("sp-resumed")
        );
        // The restored requester was persisted to base state (as the initial
        // frontend dispatch does): the backend's AuthResponse leg refills
        // `response.requester` from there, so the response path must see the
        // requester the resumed request path ran under.
        let resumed_cookie = response
            .headers
            .iter()
            .find(|(n, _)| n == "set-cookie")
            .and_then(|(_, v)| v.split(';').next())
            .and_then(|nv| nv.split_once('='))
            .map(|(_, v)| v.to_string())
            .expect("state cookie after resume");
        let state = proxy.sealer().unseal(Some(&resumed_cookie));
        assert_eq!(
            state
                .get_str(STATE_KEY_BASE, crate::context::KEY_REQUESTER)
                .as_deref(),
            Some("sp-resumed")
        );
    }

    struct StateStuffer;

    #[async_trait::async_trait]
    impl MicroService for StateStuffer {
        fn name(&self) -> &str {
            "stuffer"
        }
        fn register_endpoints(&self) -> Vec<crate::plugin::Route> {
            vec![crate::plugin::Route::exact("stuff", "stuff")]
        }
        async fn handle_endpoint(
            &self,
            ctx: &mut Context,
            _route_id: &str,
        ) -> crate::error::Result<MicroServiceAction> {
            // Incompressible filler (hex of a hash chain): the deflate step
            // inside the sealer must not squeeze it under the cookie limit.
            use sha2::{Digest, Sha256};
            let mut chunk: [u8; 32] = [0; 32];
            let mut big = String::new();
            while big.len() < 16 * 1024 {
                chunk = Sha256::digest(chunk).into();
                for b in chunk {
                    big.push_str(&format!("{b:02x}"));
                }
            }
            ctx.state.set_str("stuffer", "big", big);
            Ok(MicroServiceAction::Respond(Response::redirect(
                "https://disco.example/ds",
            )))
        }
    }

    #[tokio::test]
    async fn unsealable_state_fails_the_request_instead_of_dropping_the_cookie() {
        let sealer = StateSealer::new("a-32-byte-or-longer-test-secret!!", "TB_STATE");
        let proxy = Proxy::new(vec![], vec![], vec![Box::new(StateStuffer)], sealer);
        let request = HttpRequestData {
            path: "stuff".to_string(),
            ..Default::default()
        };
        let response = proxy.run(request).await;
        // The redirect that could never resume is replaced by an explicit
        // error, and the broken state is cleared rather than silently
        // omitted.
        assert_eq!(response.status, 500);
        assert_eq!(String::from_utf8(response.body).unwrap(), "request failed");
        assert!(response.headers.iter().all(|(n, _)| n != "location"));
        let cookie = response
            .headers
            .iter()
            .find(|(n, _)| n == "set-cookie")
            .map(|(_, v)| v.clone())
            .expect("clearing cookie attached");
        assert!(
            cookie.contains("Max-Age=0"),
            "not a clearing cookie: {cookie}"
        );
    }

    #[tokio::test]
    async fn resume_without_recoverable_frontend_fails_cleanly() {
        let calls = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let received = std::sync::Arc::new(std::sync::Mutex::new(None));
        let proxy = resume_proxy(calls.clone(), received.clone());

        let request = HttpRequestData {
            path: "resume-here".to_string(),
            ..Default::default()
        };
        let response = proxy.run(request).await;
        assert_eq!(String::from_utf8(response.body).unwrap(), "request failed");
        assert!(calls.lock().unwrap().is_empty());
        assert!(received.lock().unwrap().is_none());
    }

    struct ResponseRecordingService {
        name: String,
        calls: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
        backends: std::sync::Arc<std::sync::Mutex<Vec<Option<String>>>>,
        resume: bool,
    }

    #[async_trait::async_trait]
    impl MicroService for ResponseRecordingService {
        fn name(&self) -> &str {
            &self.name
        }

        async fn process_response(
            &self,
            ctx: &mut Context,
            data: crate::internal::InternalData,
        ) -> crate::error::Result<crate::internal::InternalData> {
            self.calls.lock().unwrap().push(self.name.clone());
            self.backends
                .lock()
                .unwrap()
                .push(ctx.target_backend.clone());
            Ok(data)
        }

        fn register_endpoints(&self) -> Vec<crate::plugin::Route> {
            self.resume
                .then(|| crate::plugin::Route::exact("resume-response", "resume"))
                .into_iter()
                .collect()
        }

        async fn handle_endpoint(
            &self,
            ctx: &mut Context,
            _route_id: &str,
        ) -> crate::error::Result<MicroServiceAction> {
            // A suspending response service such as stepup restores the
            // original backend before asking the proxy to resume the chain.
            ctx.target_backend = Some("original-backend".into());
            Ok(MicroServiceAction::ResumeResponse {
                response: crate::internal::InternalData {
                    requester: Some("sp".into()),
                    auth_info: crate::internal::AuthenticationInformation {
                        issuer: Some("issuer".into()),
                        ..Default::default()
                    },
                    ..Default::default()
                },
            })
        }
    }

    struct RecordingFrontend;

    #[async_trait::async_trait]
    impl Frontend for RecordingFrontend {
        fn name(&self) -> &str {
            "frontend"
        }

        fn register_endpoints(&self, _backend_names: &[String]) -> Vec<crate::plugin::Route> {
            Vec::new()
        }

        async fn handle_endpoint(
            &self,
            _ctx: &mut Context,
            _route_id: &str,
        ) -> crate::error::Result<FrontendAction> {
            unreachable!()
        }

        async fn handle_authn_response(
            &self,
            _ctx: &mut Context,
            response: crate::internal::InternalData,
        ) -> crate::error::Result<Response> {
            Ok(Response::text(
                200,
                response.requester.unwrap_or_else(|| "missing".into()),
            ))
        }

        async fn handle_backend_error(
            &self,
            _ctx: &mut Context,
            _error: &crate::error::Error,
        ) -> crate::error::Result<Response> {
            Ok(Response::text(500, "frontend error"))
        }
    }

    #[tokio::test]
    async fn response_resume_runs_only_later_services_then_frontend() {
        let calls = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let backends = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let services: Vec<Box<dyn MicroService>> = vec![
            Box::new(ResponseRecordingService {
                name: "before".into(),
                calls: calls.clone(),
                backends: backends.clone(),
                resume: false,
            }),
            Box::new(ResponseRecordingService {
                name: "resumer".into(),
                calls: calls.clone(),
                backends: backends.clone(),
                resume: true,
            }),
            Box::new(ResponseRecordingService {
                name: "after".into(),
                calls: calls.clone(),
                backends: backends.clone(),
                resume: false,
            }),
        ];
        let sealer = StateSealer::new("a-32-byte-or-longer-test-secret!!", "TB_STATE");
        let proxy = Proxy::new(vec![Box::new(RecordingFrontend)], vec![], services, sealer);
        let mut state = State::new();
        state.set_str(STATE_KEY_BASE, KEY_TARGET_FRONTEND, "frontend");
        let sealed = proxy.sealer().seal(&state).unwrap();
        let cookie_value = sealed
            .split(';')
            .next()
            .and_then(|value| value.split_once('='))
            .map(|(_, value)| value.to_string())
            .unwrap();
        let mut request = HttpRequestData {
            path: "resume-response".into(),
            ..Default::default()
        };
        request
            .cookies
            .insert(proxy.sealer().cookie_name().to_string(), cookie_value);

        let response = proxy.run(request).await;
        assert_eq!(response.status, 200);
        assert_eq!(String::from_utf8(response.body).unwrap(), "sp");
        assert_eq!(*calls.lock().unwrap(), vec!["after".to_string()]);
        assert_eq!(
            *backends.lock().unwrap(),
            vec![Some("original-backend".to_string())]
        );
        assert!(response
            .headers
            .iter()
            .any(|(name, value)| name == "set-cookie" && value.contains("Max-Age=0")));
    }

    #[tokio::test]
    async fn unhandled_error_returns_generic_body() {
        let sealer = StateSealer::new("a-32-byte-or-longer-test-secret!!", "TB_STATE");
        let proxy = Proxy::new(vec![], vec![], vec![], sealer);
        let request = HttpRequestData {
            path: "no/such/route".to_string(),
            ..Default::default()
        };
        let response = proxy.run(request).await;
        let body = String::from_utf8(response.body).unwrap();
        assert_eq!(body, "request failed");
        // No internal error detail (e.g. the unbound path) leaks to the client.
        assert!(!body.contains("no/such/route"));
    }
}
