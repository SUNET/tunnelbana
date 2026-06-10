# Micro-services

A **micro-service** is the third plugin kind (alongside frontends and backends).
Where a frontend speaks a protocol *down* to RPs/SPs and a backend speaks one
*up* to IdPs/OPs, a micro-service sits **in the middle of the flow** and
transforms the `InternalData` as it passes between them — without either side
knowing it is there. It is tunnelbana's analogue of a SATOSA *micro-service*.

Typical jobs: inject or filter attributes, choose the backend by requester,
enforce consent, look up entitlements, rewrite the subject id.

## The trait

```rust
#[async_trait]
pub trait MicroService: Send + Sync {
    fn name(&self) -> &str;

    /// Transform the request-path data (frontend → backend). Default: identity.
    async fn process_request(&self, ctx: &mut Context, data: InternalData)
        -> Result<InternalData> { Ok(data) }

    /// Transform the response-path data (backend → frontend). Default: identity.
    async fn process_response(&self, ctx: &mut Context, data: InternalData)
        -> Result<InternalData> { Ok(data) }

    /// Optional own endpoints (e.g. a consent callback page).
    fn register_endpoints(&self) -> Vec<Route> { Vec::new() }

    /// Inbound hit on one of those endpoints.
    async fn handle_endpoint(&self, ctx: &mut Context, route_id: &str) -> Result<Response>;
}
```

Both transform methods have a **default identity implementation**, so a
micro-service only overrides the side(s) it cares about: a request-path service
implements `process_request`, a response-path service implements
`process_response`. The supporting types (`BuildContext`, `Route`, `Context`)
are exactly the ones described in [Writing a plugin](writing-a-plugin.md); read
that chapter first for `parse_config`, state namespacing, and the conventions.

## Where they run in the pipeline

The [`Proxy`](architecture.md) holds its micro-services as an **ordered list**
(the order they appear in the config) and invokes them at two precise points —
see `tunnelbana-core/src/proxy.rs`:

```
   inbound request
        │
   ┌────▼─────────┐
   │  frontend    │  handle_endpoint → StartAuth { request, target_backend? }
   └────┬─────────┘
        │  request InternalData
   ┌────▼──────────────────────────────┐
   │  micro-services, in listed order   │  process_request(ctx, data)   ← REQUEST PATH
   └────┬──────────────────────────────┘
        │  backend selected: explicit pin > micro-service pin > default
   ┌────▼─────────┐
   │  backend     │  start_auth → … upstream IdP/OP … → handle_endpoint → AuthResponse(data)
   └────┬─────────┘
        │  response InternalData
   ┌────▼──────────────────────────────┐
   │  micro-services, in listed order   │  process_response(ctx, data)  ← RESPONSE PATH
   └────┬──────────────────────────────┘
        │
   ┌────▼─────────┐
   │  frontend    │  handle_authn_response → protocol response to the RP/SP
   └──────────────┘
```

Key facts that follow from this:

- **They only run on the auth flow.** `process_request` fires when a frontend
  returns `StartAuth`; `process_response` fires when a backend returns
  `AuthResponse`. Endpoints that merely `Respond` (discovery, JWKS, token,
  SP metadata) never touch the micro-service chain.
- **Order is the config order**, and it is the *same* order on both paths
  (request path forward, response path forward) — there is no automatic
  reversal. List them accordingly.
- **A request-path service can steer routing** by setting
  `ctx.target_backend`. Backend selection precedence is: a backend the frontend
  pinned in `StartAuth` → a backend a micro-service pinned in `ctx.target_backend`
  → the default (the first configured backend). `custom_routing` uses exactly
  this hook.
- **The data is the contract.** A micro-service receives and returns
  `InternalData` — `attributes`, `requester`, `subject_id`, `auth_info`. Mutate
  that; don't reach into protocol-specific structures.
- **Own endpoints are dispatched directly.** If a micro-service registers
  routes, an inbound hit goes straight to its `handle_endpoint` (the request/
  response transform chain is not involved). This is how a consent service would
  serve and handle its own approval page.

## The built-ins

The bundled micro-services (`tunnelbana-plugins/src/microservices.rs`) are small
and worth reading as templates. Their config is in the
[built-in plugin reference](built-in-plugins.md#micro-services).

| `type` | Path | What it does |
| --- | --- | --- |
| `static_attributes` | response | Adds fixed attributes (does not overwrite existing ones). |
| `filter_attributes` | response | Keeps only allow-listed internal attributes; drops the rest. |
| `custom_routing` | request | Pins `ctx.target_backend` from the `requester`, with an optional default. |
| `attribute_processor` | response | Rewrites attribute values through per-attribute processor chains (regex substitution). See [below](#attribute_processor-value-transforms). |
| `attribute_authorization` | response | Rejects the authentication unless response attributes satisfy regex allow/deny rules. See [below](#attribute_authorization-regex-allowdeny-rules). |

For instance, `filter_attributes` is the whole pattern in a few lines:

```rust
#[async_trait]
impl MicroService for FilterAttributes {
    fn name(&self) -> &str { &self.name }

    async fn process_response(&self, _ctx: &mut Context, mut data: InternalData)
        -> Result<InternalData>
    {
        data.attributes.retain(|k, _| self.allowed.contains(k));
        Ok(data)
    }
}
```

## `attribute_processor`: value transforms

The SATOSA-parity attribute transformer (ADR 0011, SATOSA: `AttributeProcessor`
+ `RegexSubProcessor`). It runs on the **response path** and rewrites the
values of named internal attributes through a chain of processors, in place —
it never adds or removes attributes, only changes values.

Config is a `process` list; each entry names one internal attribute and its
processor chain. The only processor kind today is `regex_sub`:

```toml
[[microservice]]
type = "attribute_processor"
name = "rewrite"
  [[microservice.config.process]]
  attribute = "mail"                          # internal attribute name
    [[microservice.config.process.processors]]
    name = "regex_sub"
    match_pattern = '@legacy\.example\.org$'  # regex, applied unanchored
    replace_pattern = '@example.org'          # every match replaced
```

This example rewrites a retired mail domain on the fly:
`anna@legacy.example.org` → `anna@example.org`.

How it behaves, precisely:

- **Internal names.** `attribute` is the *internal* attribute name from your
  attribute map — `mail`, not the wire name
  `urn:oid:0.9.2342.19200300.100.1.3`. The backend has already mapped inbound
  protocol attributes by the time this runs.
- **All values, all matches.** Every value of the attribute is rewritten, and
  replacement applies to every match within a value (like Python's `re.sub`).
- **Group references.** Use the regex crate's `$1`/`${1}` syntax. Python-style
  `\1` (as found in SATOSA configs) is accepted and converted automatically,
  so a SATOSA `regex_sub_replace_pattern: _\1` ports verbatim as
  `replace_pattern = '_\1'`. Prefer TOML *literal* strings (single quotes) so
  backslashes need no escaping.
- **Chaining.** A rule may list several processors; they run in order, each
  seeing the previous one's output. Several `[[microservice.config.process]]`
  rules can target different attributes.
- **Fail-fast config.** Patterns compile at startup; a bad regex or an unknown
  processor `name` aborts boot rather than surfacing mid-flow.
- **Ordering.** Place it **before** services that *match on* the transformed
  value (such as `attribute_authorization` below), and note that the subject
  id composed via `user_id_from_attrs` is taken **before** micro-services run
  — the transform affects the released attribute, not NameID minting (same as
  SATOSA).

## `attribute_authorization`: regex allow/deny rules

The SATOSA-parity authorization gate (ADR 0012, SATOSA:
`AttributeAuthorization`). It runs on the **response path** and *rejects the
authentication* — not merely filters — when response attributes don't satisfy
the configured rules. The originating frontend renders the rejection as a
protocol error (SAML error response / OIDC `access_denied`).

Rules nest **requester → provider → attribute → list of regexes**, where
*requester* is the downstream SP/RP and *provider* is the upstream IdP/OP
issuer. At the requester and provider levels the lookup is: exact key, else
`""`, else `"default"` (`""` and `"default"` are synonymous wildcards):

```toml
[[microservice]]
type = "attribute_authorization"
name = "authz"
  [microservice.config]
  force_attributes_presence_on_allow = true

  # Any requester, any provider: mail must be present and non-empty.
  [microservice.config.attribute_allow.default.default]
  mail = ["."]

  # One locked-down SP additionally requires a staff affiliation.
  [microservice.config.attribute_allow."https://locked.example".default]
  mail = ["."]
  affiliation = ["^staff$"]

  # Deny example (SATOSA's doc case): reject eppn values without an '@'.
  # [microservice.config.attribute_deny.default.default]
  # edupersonprincipalname = ["^[^@]+$"]
```

Semantics (identical to SATOSA's, ported from
`satosa/micro_services/attribute_authorization.py`):

- **Allow rules.** For each attribute in the selected allow set: if the
  attribute is present, at least one of its values must match at least one
  regex (unanchored search, like `re.search`) — otherwise the flow is
  rejected. If the attribute is **absent**, it is rejected only when
  `force_attributes_presence_on_allow = true`; the
  `mail = ["."]` + force-presence pair above is the idiom for "must be
  present and non-empty".
- **Deny rules.** The mirror image: if any value of a listed attribute matches
  any regex, the flow is rejected. `force_attributes_presence_on_deny = true`
  rejects when the attribute is absent.
- **Selected, not merged.** A requester-specific block *replaces* the
  `default` block entirely — rules are never inherited or combined. In the
  example above, `https://locked.example` must therefore repeat the
  `mail` rule alongside its `affiliation` rule.
- **Internal names**, as everywhere: `mail`, `edupersonprincipalname` —
  not the wire names (`urn:oid:…`, `eduPersonPrincipalName`).
- **Fail-fast config.** All regexes compile at startup.
- **Ordering.** List it **after** `attribute_processor` so the rules see the
  transformed values, and make sure nothing earlier in the chain (e.g. a
  `filter_attributes`) strips an attribute you gate on.

## Writing your own

Suppose we want a **response-path** service that rejects the flow unless the
authenticated user's email is in an allow-listed domain. Email only exists once
the backend has returned its attributes, so this is `process_response` work. Add
to `tunnelbana-plugins/src/microservices.rs` (or a new module):

```rust
use async_trait::async_trait;
use serde::Deserialize;
use tunnelbana_core::context::Context;
use tunnelbana_core::error::{Error, Result};
use tunnelbana_core::internal::InternalData;
use tunnelbana_core::plugin::{BuildContext, MicroService};

#[derive(Debug, Deserialize)]
struct AllowEmailsConfig {
    /// Email domains permitted to complete the flow, e.g. `["example.com"]`.
    #[serde(default)]
    allowed_domains: Vec<String>,
}

/// Aborts the flow unless the user's `mail` attribute is in an allowed domain.
pub struct AllowEmails {
    name: String,
    allowed_domains: Vec<String>,
}

impl AllowEmails {
    pub fn build(bx: &BuildContext) -> Result<Box<dyn MicroService>> {
        let cfg: AllowEmailsConfig = bx.parse_config()?;
        Ok(Box::new(AllowEmails { name: bx.name.clone(), allowed_domains: cfg.allowed_domains }))
    }
}

#[async_trait]
impl MicroService for AllowEmails {
    fn name(&self) -> &str { &self.name }

    async fn process_response(&self, _ctx: &mut Context, data: InternalData)
        -> Result<InternalData>
    {
        // `mail` is the *internal* attribute name (see the attribute map); the
        // backend has already mapped the protocol-specific claim onto it.
        let domain = data
            .attr_first("mail")
            .and_then(|email| email.rsplit_once('@').map(|(_, d)| d.to_ascii_lowercase()));

        match domain {
            Some(d) if self.allowed_domains.iter().any(|a| a.eq_ignore_ascii_case(&d)) => Ok(data),
            // Returning an error here aborts the flow; the originating frontend
            // renders it as a protocol error (e.g. an OAuth access_denied).
            _ => Err(Error::Authn("email domain not allowed".into())),
        }
    }
}
```

Notes that come straight from the pipeline rules above:

- Implement **only** `process_response` here — `process_request`,
  `register_endpoints` and `handle_endpoint` keep their defaults. Because it runs
  on the response path, the backend's attributes (including `mail`) are already
  populated.
- Returning `Err(..)` from a transform aborts the flow; `render_error` hands it
  to the originating frontend's `handle_backend_error`, so the RP/SP sees a
  protocol-appropriate error rather than a raw 500.
- Need outbound HTTP (entitlement lookup, etc.)? Use `bx.http_client` — never a
  global client — so the service stays testable. Keep this crate **actix-free**.
- Need to remember something across the request/response halves of one flow?
  Stash it in `ctx.state` under your instance `name` (see the state-namespacing
  convention in [Writing a plugin](writing-a-plugin.md)).

## Wiring it in

Two steps: register the constructor under a `type` string, then reference that
type from config.

### 1. Register the constructor

The built-ins are registered in `register_all`
(`tunnelbana-plugins/src/lib.rs`). Add your line:

```rust
pub fn register_all(registry: &mut Registry) {
    // … existing frontends/backends …
    registry.register_microservice("static_attributes", microservices::StaticAttributes::build);
    registry.register_microservice("filter_attributes", microservices::FilterAttributes::build);
    registry.register_microservice("custom_routing",    microservices::CustomRouting::build);
    registry.register_microservice("allow_emails",      microservices::AllowEmails::build); // ← new
}
```

The registry is just a `type`-string → constructor lookup (a `HashMap`), so the
**order of these lines is irrelevant** — registering `allow_emails` before or
after `filter_attributes` makes no difference. Execution order is decided purely
by the order of the `[[microservice]]` blocks in the config (step 2); that's
where "before `filter_attributes`" matters.

If you'd rather not touch the bundled crate, register it in your **own binary**
after pulling in the built-ins:

```rust
let mut registry = Registry::new();
tunnelbana_plugins::register_all(&mut registry);          // the built-ins
registry.register_microservice("allow_emails", my_crate::AllowEmails::build);
```

### 2. Reference it from config

```toml
[[microservice]]
type = "allow_emails"       # the string you registered
name = "gate"               # unique instance label (see below)
  [microservice.config]
  allowed_domains = ["example.com", "example.org"]
```

`name` identifies *this instance* (as opposed to `type`, which picks the code).
The proxy uses it to (a) mount any endpoints the service registers under
`<base_url>/<name>/…` and route hits to it, (b) namespace whatever it stashes in
`ctx.state`, and (c) label it in the startup log — and it's what lets you run two
instances of the same `type` with different configs. This `allow_emails` service
registers no endpoints and uses no state, so here `name` is purely a label: pick
anything unique.

Remember the **order** of `[[microservice]]` blocks is the execution order on
both paths. Put a request-path router (`custom_routing`) before services that act
on the chosen backend; put response shapers (`static_attributes`,
`filter_attributes`) in the order you want them applied — typically inject first,
then filter. A response-path gate like this one reads an attribute (`mail`), so
list it **before** any `filter_attributes` that might strip that attribute,
otherwise the gate sees nothing to check.

## Rebuild and run

Micro-services live in the `tunnelbana-plugins` crate and are compiled into the
`tunnelbana` binary, so wiring one in is a recompile (not a config-only change).
Per the project's package rule, prefix anything that fetches from a registry
with `sfw`.

```bash
# compile (and pull any new deps through Socket Firewall)
sfw cargo build --workspace

# keep the suite green and clippy clean
cargo test --workspace
cargo clippy --workspace        # zero warnings

# run with your config
cargo run -p tunnelbana -- config/proxy.toml
```

On startup tunnelbana logs `loaded microservice name=… kind=…` for each one, and
**fails fast** if a `type` is not registered or a service rejects its own config
(e.g. a bad value in `[microservice.config]`). A successful boot with your new
line in the log means it's in the pipeline.
