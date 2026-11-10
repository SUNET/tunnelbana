# Architecture

tunnelbana is a workspace of five crates, using external protocol libraries:

| Crate                | Role |
| -------------------- | ---- |
| `tunnelbana-core`    | Framework: `Context`, `InternalData`, encrypted state cookie, plugin traits + `Registry`, router, the `Proxy` orchestrator, TOML config, attribute mapping, TTL/disk cache. **Web-framework agnostic.** Re-exports `grindvakt`'s generic primitives (`error`, `http`, `keys`, `mac`, `util`) so the whole workspace shares one type universe. |
| `tunnelbana-oidc`    | A thin compatibility **shim** that re-exports `grindvakt`'s OAuth2 / OIDC / OpenID Federation surface under the old `tunnelbana_oidc::*` paths. New code should depend on `grindvakt` directly. |
| `tunnelbana-plugins` | The concrete frontends, backends and micro-services, plus `register_all`. |
| `tunnelbana-python` | The isolated PyO3 boundary for trusted synchronous Python micro-services, strict conversion and execution controls. |
| `tunnelbana`         | The actix-web binary: config load, plugin instantiation, a `reqwest` HTTP client, request/response glue. |

The OAuth2 / OIDC / OpenID Federation protocol layer (and the generic `error`,
`http`, `keys`, `mac`, `util` primitives) lives **outside** this workspace in the
standalone [`grindvakt`](https://crates.io/crates/grindvakt) crate, so other
projects can consume it. It depends only on `jose-rs` plus crypto crates - no
proxy or runtime coupling; outbound HTTP is injected via
`grindvakt::http::HttpClient`. SAML lives in the separate `gamlastan` crate.

With Grindvakt 0.8, HTTP adapters must populate `HttpRequestData.query_pairs`
and `form_pairs` directly from the query string and form body, preserving order
and duplicate names. The OIDC and federation authorization/token endpoints
consume these lists and reject duplicate single-valued parameters; rebuilding
them from the convenience `query` / `form` maps loses this validation. Keep those
maps populated as well for existing application lookups. Repeated `resource`
parameters are preserved in the authorization request, but this does not add
resource-specific token audiences.

The standard binary supplies a separate `InMemoryTokenUseStore` for each OP
frontend, retaining process-local token replay protection. Rust embedders can
instead pass a shared atomic store to the ordinary OIDC frontend through
[`build_with_token_use_store`](writing-a-plugin.md#injecting-an-oidc-token-use-store).
There is no TOML store selector, and federation, DPoP and SAML replay stores are
not changed by that constructor. Authorization response generation is asynchronous, and
error redirects use the validated request's query/fragment response mode. Both
issuance and backend errors revalidate the request against the current client
registration before redirecting; failed validation returns an error locally.

Both OP frontends use Grindvakt 0.8.1's caller-managed subject resolver. A compact
registration fingerprint in the authenticated login state binds the response
pipeline's subject to the client validated before login. The resolver compares
that binding against its issuance-time client before preserving the existing
`subject_id` / attribute-composition order. See
[ADR 0058](../adr/0058-grindvakt-081-subject-compatibility.md) for pairwise policy
and upgrade compatibility.

## The request flow

Every request is routed to exactly one module endpoint. Authentication flows
cross from a frontend, through any micro-services, to a backend and back:

```text
            downstream                         upstream
  RP / SP  ─────────────►  ┌───────────┐  ───────────►  IdP / OP
                           │ FRONTEND  │
   1. hit frontend  ──────►│ endpoint  │
                           └─────┬─────┘
                                 │ StartAuth { InternalData }
                           ┌─────▼──────────┐
                           │ micro-services │  process_request()
                           └─────┬──────────┘
                                 │
                           ┌─────▼─────┐
                           │ BACKEND   │  start_auth()  ──► redirect to IdP/OP
                           └───────────┘
                                 ⋮   (user authenticates upstream)
                           ┌───────────┐
   2. backend endpoint ───►│ BACKEND   │  handle_endpoint() → AuthResponse
      (e.g. ACS / callback)└─────┬─────┘
                                 │ InternalData
                           ┌─────▼──────────┐
                           │ micro-services │  process_response()
                           └─────┬──────────┘
                           ┌─────▼─────┐
   3. response to RP/SP ◄──│ FRONTEND  │  handle_authn_response()
                           └───────────┘
```

The two sides never share protocol concepts. They communicate only through
[`InternalData`](#internaldata).

After request services run and a backend is selected, the proxy also tries
`MicroService::try_authenticate` in configuration order unless the request
forces fresh authentication. A returned saved identity must be accepted by
`Backend::restore_authn_context`; the default declines. An accepted identity
is rebound to the current requester and enters the entire response pipeline,
skipping the upstream round trip. The built-in SAML backend supports this
path with issuer/metadata checks; OIDC/federation backends decline it. See
[saved-login reuse](python-microservices.md#reusing-a-saved-login).

## Plugin kinds

There are three plugin traits, all in `tunnelbana_core::plugin`:

- **`Frontend`** - speaks a protocol to downstream RPs/SPs. Serves endpoints
  (discovery, JWKS, authorization, token, ACS POST, …), starts authentication,
  and renders the final response (a signed SAML Response, an OIDC redirect with
  a code, …).
- **`Backend`** - speaks a protocol to an upstream IdP/OP. Starts authentication
  (an AuthnRequest redirect, an authorization request) and handles the return
  endpoint (the SAML ACS, the OIDC callback).
- **`MicroService`** - intercepts the request and/or response path to transform
  `InternalData` (inject attributes, filter attributes, pick a backend).

A plugin is selected by a `type` string in config and instantiated by a
constructor registered in the [`Registry`](writing-a-plugin.md#registering-your-plugin).

## InternalData

The protocol-neutral payload that crosses the proxy. Frontends produce a
*request* form on the way in and consume a *response* form on the way out;
backends do the reverse.

```rust
pub struct InternalData {
    pub auth_info: AuthenticationInformation, // auth_class_ref, timestamp, issuer
    pub requester: Option<String>,            // the downstream RP/SP id
    pub requester_name: Vec<String>,          // human-readable requester names
    pub subject_id: Option<String>,           // the authenticated subject
    pub subject_type: SubjectType,            // Persistent / Transient / …
    pub attributes: BTreeMap<String, Vec<String>>, // internal attribute names
    pub force_authn: bool,                    // require fresh authentication
    pub is_passive: bool,                     // prohibit user interaction
}
```

Attributes here use **internal** names (e.g. `mail`, `givenname`). The
[attribute map](configuration.md#the-attribute-map) translates to and from each
protocol's external names; [Attributes and transforms](attributes.md) is the
full narrative, including the response-path transform pipeline.

`auth_info.timestamp` carries the original upstream authentication time when
known. It is distinct from the time the proxy issues a new assertion or token.
See [authentication freshness](upgrading.md#authentication-time-and-freshness).

## State is a stateless encrypted cookie

In-flight flow state (the pending authorization request, PKCE verifier, the SAML
request id, …) is sealed into a cookie as a JWE (`dir` + `A256GCM`) under a key
derived from `state_encryption_key`. There is **no server-side session store**
for this flow state. The cookie is attacker-reachable data;
see [Security: the state cookie](security-state-cookie.md) for the AEAD
construction, freshness, key rotation, and the threat model.

This does not make every plugin shared-nothing. The built-in DPoP frontend and
SAML backend replay caches are process-local, so their replay-sensitive modes
must run as a single process unless a shared replay store is implemented.

Plugins read and write their own namespace of this state through the request
[`Context`](writing-a-plugin.md#the-context):

```rust
ctx.state.set_value(&self.name, "authz_request", value);
let v = ctx.state.get_value(&self.name, "authz_request");
ctx.state.get_str(&self.name, "authn_id");
ctx.state.clear_namespace(&self.name);
```

OIDC tokens are stateless too: authorization codes and access tokens are
confidential JWE tokens carrying their own state and expiry, and id_tokens are
signed JWTs. Code and refresh-token redemption nevertheless consult the
provider's token-use store to atomically reject replay. Client assertions also
use that store. Its default is in memory; an injected implementation may make
external storage calls. UserInfo validates the self-contained access token and,
when enabled, the separate DPoP proof policy.
