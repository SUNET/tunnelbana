# Writing a plugin

A plugin is a Rust type that implements one of three traits from
`tunnelbana_core::plugin` and is registered under a `type` string. This chapter
walks through the traits and the supporting types, then dissects the **OpenID
Federation frontend** (`tunnelbana-plugins/src/federation_frontend.rs`) as a
complete, real example, and finishes with how to register your own.

## The traits

```rust
#[async_trait]
pub trait Frontend: Send + Sync {
    fn name(&self) -> &str;

    /// The endpoints this frontend serves. `backend_names` lets you mount
    /// per-backend routes if needed.
    fn register_endpoints(&self, backend_names: &[String]) -> Vec<Route>;

    /// An inbound hit on one of those endpoints.
    async fn handle_endpoint(&self, ctx: &mut Context, route_id: &str)
        -> Result<FrontendAction>;

    /// Render a successful auth (from a backend) into this protocol.
    async fn handle_authn_response(&self, ctx: &mut Context, response: InternalData)
        -> Result<Response>;

    /// Render a backend error back to the downstream RP/SP.
    async fn handle_backend_error(&self, ctx: &mut Context, error: &Error)
        -> Result<Response>;
}

#[async_trait]
pub trait Backend: Send + Sync {
    fn name(&self) -> &str;
    fn register_endpoints(&self) -> Vec<Route>;
    /// Begin authentication upstream (e.g. return a redirect to the IdP/OP).
    async fn start_auth(&self, ctx: &mut Context, request: InternalData) -> Result<Response>;
    /// An inbound hit on a backend endpoint (e.g. the ACS / callback).
    async fn handle_endpoint(&self, ctx: &mut Context, route_id: &str) -> Result<BackendAction>;
}

#[async_trait]
pub trait MicroService: Send + Sync {
    fn name(&self) -> &str;
    async fn process_request(&self, ctx: &mut Context, data: InternalData) -> Result<InternalData>;
    async fn process_response(&self, ctx: &mut Context, data: InternalData) -> Result<InternalData>;
    fn register_endpoints(&self) -> Vec<Route> { Vec::new() }
    async fn handle_endpoint(&self, ctx: &mut Context, route_id: &str) -> Result<Response>;
}
```

This chapter dissects a **frontend**. For the `MicroService` trait specifically -
how `process_request`/`process_response` map onto the request and response
paths, the decoration signals services exchange, a worked "writing your own"
example, and how to scope a service to specific SPs/IdPs - see the
[Micro-services](micro-services.md) chapter.

The two return enums drive the proxy:

```rust
pub enum FrontendAction {
    Respond(Response),                                   // a finished HTTP response
    StartAuth { request: InternalData, target_backend: Option<String> },
}
pub enum BackendAction {
    Respond(Response),          // a finished HTTP response (e.g. SP metadata)
    AuthResponse(InternalData), // forward back to the originating frontend
}
```

## Supporting types

### `BuildContext`

Every constructor receives a `&BuildContext`:

```rust
pub struct BuildContext {
    pub name: String,                       // this instance's name (from config)
    pub base_url: String,
    pub config: serde_json::Value,          // this plugin's config table
    pub attribute_mapper: Arc<AttributeMapper>,
    pub http_client: Arc<dyn HttpClient>,   // outbound HTTP (reqwest-backed)
    pub secret: String,                     // global state secret, for derived keys
}

impl BuildContext {
    pub fn parse_config<T: DeserializeOwned>(&self) -> Result<T>;  // typed config
    pub fn module_base(&self) -> String;                          // <base_url>/<name>
}
```

Define a `#[derive(Deserialize)]` struct for your config and call
`bx.parse_config()` - the `config` TOML table is already converted to JSON, so
serde does the rest.

### `Route`

```rust
Route::exact("OIDFed/authorization", "authorization")
```

`Route::exact(path, id)` registers a **literal** path, matched by string
equality. This is the right choice for fixed endpoints and is what every
built-in plugin uses: the router keeps exact routes in a hash map and resolves
them in O(1), independent of how many modules are mounted (see
[ADR 0029](https://github.com/SUNET/tunnelbana/blob/main/docs/adr/0029-router-exact-match-dispatch.md)). The second argument is
an opaque `route_id` your `handle_endpoint` matches on. Build paths relative to
`module_base()` so a renamed instance keeps working. Routing matches the request
path with the leading `/` stripped, so a route's name prefix must be non-empty.

If you genuinely need a pattern, `Route::new(pattern, id)` takes a regex
(anchored to `^…$` unless it already starts with `^`). Regex routes fall back to
a linear scan and an exact route always wins over them, so prefer `Route::exact`
unless the path is truly dynamic.

### The `Context`

`handle_endpoint`, `start_auth`, etc. receive `&mut Context`, which carries the
parsed request and the encrypted flow state:

```rust
ctx.request.query.get("client_id");      // query params
ctx.request.form.get("SAMLResponse");    // POST form fields
ctx.request.authorization();             // the Authorization header
ctx.request.bearer_token();              // its bearer token, if any

ctx.state.set_value(&self.name, "authz_request", json_value);
ctx.state.get_value(&self.name, "authz_request");
ctx.state.get_str(&self.name, "authn_id");
ctx.state.clear_namespace(&self.name);   // wipe this plugin's state
```

Always namespace state with your instance `name` so two instances of the same
plugin don't collide.

## Worked example: the OpenID Federation frontend

The federation OP is a good template because it exercises every part of the
`Frontend` trait. The full source is
`tunnelbana-plugins/src/federation_frontend.rs`; the essentials follow.

### 1. Config structs

Nested `#[derive(Deserialize)]` structs mirror the TOML. Note `entity_id` is
optional and defaults to the module base:

```rust
#[derive(Debug, Deserialize)]
struct FederationFrontendConfig {
    #[serde(default)] entity_id: Option<String>,
    #[serde(default)] signing_key_path: Option<String>,
    #[serde(default)] signing_jwk: Option<Value>,
    #[serde(default)] signing_jwk_path: Option<String>,
    #[serde(default)] signing_algorithm: Option<String>,
    #[serde(default)] signing_key_id: Option<String>,
    #[serde(default)] clients: Vec<Client>,
    federation: FederationConfig,
}

#[derive(Debug, Deserialize)]
struct TrustAnchorConfig { entity_id: String, keys: Vec<Value> }
```

### 2. `build` - the constructor

```rust
pub fn build(bx: &BuildContext) -> Result<Box<dyn Frontend>> {
    let cfg: FederationFrontendConfig = bx.parse_config()?;
    let module_base = bx.module_base();

    // entity_id defaults to the module base, but can be overridden so the OP
    // keeps a stable federation identity independent of where endpoints live.
    let issuer = cfg.entity_id.clone().unwrap_or_else(|| module_base.clone());

    // Load keys via the shared helper (PEM, inline JWK, or JWK file).
    let op_key  = load_signing_key(cfg.signing_jwk.as_ref(), cfg.signing_key_path.as_deref(), /*…*/)?;
    let fed_key = load_signing_key(/* federation key fields */)?;

    // Provider metadata: issuer = entity_id, endpoints = module_base.
    let mut metadata = ProviderMetadata::new(issuer.clone(), &module_base);
    metadata.extra.insert("client_registration_types_supported".into(),
                          serde_json::json!(["automatic"]));
    metadata.request_parameter_supported = true;

    // … build the Provider, trust-anchor JWKS map, etc. …

    Ok(Box::new(FederationFrontend { name: bx.name.clone(), issuer,
        endpoint_base: module_base, /* … */ http: bx.http_client.clone(), /* … */ }))
}
```

Two lessons here:

- **Derive, don't hardcode.** `issuer`/`entity_id` and the endpoint base are
  kept separate so the public identifier and the URL layout can differ.
- **Take what you need from `BuildContext`** - the HTTP client (for trust-chain
  resolution), the attribute mapper, and `secret` (for the token codec).

### 3. `register_endpoints` - the routes

```rust
fn register_endpoints(&self, _backend_names: &[String]) -> Vec<Route> {
    vec![
        Route::exact(self.route(".well-known/openid-federation"), "entity_configuration"),
        Route::exact(self.route(".well-known/openid-configuration"), "discovery"),
        Route::exact(self.route("jwks"),          "jwks"),
        Route::exact(self.route("authorization"), "authorization"),
        Route::exact(self.route("token"),         "token"),
        Route::exact(self.route("userinfo"),      "userinfo"),
    ]
}
// where:  fn route(&self, suffix: &str) -> String { format!("{}/{}", self.name, suffix) }
```

### 4. `handle_endpoint` - dispatch on `route_id`

```rust
async fn handle_endpoint(&self, ctx: &mut Context, route_id: &str) -> Result<FrontendAction> {
    match route_id {
        "entity_configuration" => Ok(FrontendAction::Respond(
            Response::new(200)
                .with_header("content-type", "application/entity-statement+jwt")
                .with_body(self.entity_configuration()?.into_bytes()))),
        "discovery" => Ok(FrontendAction::Respond(Response::json(&self.provider.discovery_document())?)),
        "jwks"      => Ok(FrontendAction::Respond(Response::json(&self.provider.jwks_document())?)),
        "authorization" => self.handle_authorization(ctx).await,
        "token"     => Ok(FrontendAction::Respond(self.handle_token(ctx).await)),
        "userinfo"  => Ok(FrontendAction::Respond(self.handle_userinfo(ctx).await)),
        other => Err(Error::NoBoundEndpoint(other.to_string())),
    }
}
```

The authorization endpoint is where this frontend hands off to a backend. It
auto-registers the RP from the federation, verifies the request object, stores
the request in state, then returns `StartAuth`:

```rust
async fn handle_authorization(&self, ctx: &mut Context) -> Result<FrontendAction> {
    let client_id = ctx.request.query.get("client_id").cloned()
        .ok_or_else(|| Error::BadRequest("missing client_id".into()))?;

    // Known client, or auto-register by resolving its trust chain.
    let client = match self.provider.clients.get(&client_id).await {
        Some(c) => c,
        None => self.auto_register(&client_id).await?,   // uses self.http + trust anchors
    };

    // … unpack the request object (RFC 9101), validate the request …
    self.store_authz_request(ctx, &req)?;                // stash in encrypted state

    let mut request = InternalData::request(req.client_id.clone());
    Ok(FrontendAction::StartAuth { request, target_backend: None })
}
```

### 5. `handle_authn_response` - render the result

When the backend returns an `AuthResponse`, the proxy hands the `InternalData`
back to the frontend, which turns it into a protocol response - here, an OIDC
redirect carrying an authorization code:

```rust
async fn handle_authn_response(&self, ctx: &mut Context, response: InternalData)
    -> Result<Response>
{
    let req = self.load_authz_request(ctx)
        .ok_or_else(|| Error::State("no in-flight authorization request".into()))?;
    // Map internal attributes → OIDC claims, compose the subject, then redirect.
    let external = self.mapper.from_internal("openid", &response.attributes);
    let sub = response.subject_id.clone()
        .or_else(|| self.mapper.compose_subject_id(&response.attributes))
        .ok_or_else(|| Error::Authn("no subject identifier".into()))?;
    match self.provider.authorization_redirect(&req, &sub, &external, response.auth_info.auth_class_ref) {
        Ok(r)  => Ok(r),
        Err(e) => Ok(e.to_redirect(&req.redirect_uri)),
    }
}
```

### 6. `handle_backend_error` - render failures

If the backend fails (including an upstream IdP saying "access denied" or the
user cancelling), the frontend turns it into a protocol-appropriate error -
here, an OAuth `access_denied` redirect to the RP:

```rust
async fn handle_backend_error(&self, ctx: &mut Context, error: &Error) -> Result<Response> {
    if let Some(req) = self.load_authz_request(ctx) {
        let oerr = OAuthError::new(OAuthErrorCode::AccessDenied, error.to_string())
            .with_state(req.state.clone());
        return Ok(oerr.to_redirect(&req.redirect_uri));
    }
    Ok(Response::text(500, format!("{error}")))
}
```

## Registering your plugin

Constructors are installed into a `Registry`, keyed by the `type` string. The
built-ins live in `register_all`:

```rust
// tunnelbana-plugins/src/lib.rs
pub fn register_all(registry: &mut Registry) {
    registry.register_frontend("oidc",            oidc_frontend::OidcFrontend::build);
    registry.register_frontend("oidc_federation", federation_frontend::FederationFrontend::build);
    registry.register_frontend("saml2",           saml2_frontend::Saml2Frontend::build);
    registry.register_backend("oidc",             oidc_backend::OidcBackend::build);
    registry.register_backend("saml2",            saml2_backend::Saml2Backend::build);
    registry.register_microservice("static_attributes", microservices::StaticAttributes::build);
    registry.register_microservice("filter_attributes", microservices::FilterAttributes::build);
    registry.register_microservice("custom_routing",    microservices::CustomRouting::build);
}
```

To add **`my_frontend`**:

1. Write the module with a `pub fn build(bx: &BuildContext) -> Result<Box<dyn Frontend>>`
   and a type implementing `Frontend`.
2. Add `registry.register_frontend("my_frontend", my_frontend::MyFrontend::build);`
   - either by editing `register_all`, or in your own binary:

   ```rust
   let mut registry = Registry::new();
   tunnelbana_plugins::register_all(&mut registry);   // the built-ins
   registry.register_frontend("my_frontend", my_crate::MyFrontend::build);
   ```
3. Select it from config:

   ```toml
   [[frontend]]
   type = "my_frontend"
   name = "Mine"
     [frontend.config]
     # → deserialized by your MyFrontendConfig
   ```

## Conventions to follow

- **Keep frontends and backends mutually oblivious.** They exchange only
  `InternalData`; never leak one protocol's concepts into the other side.
- **Namespace your state** with the instance `name`, and clear it when the flow
  completes (`ctx.state.clear_namespace(&self.name)`).
- **Stay stateless.** Use the encrypted cookie for flow state; don't add a
  server-side session store without a strong reason.
- **Map at the edges.** Use `attribute_mapper.to_internal(profile, …)` on the
  way in and `from_internal(profile, …)` on the way out so the rest of the
  pipeline only sees internal attribute names.
- **Inject outbound HTTP** via `bx.http_client`; don't reach for a global
  client. This keeps the protocol logic testable.
