# Architecture

tunnelbana is a workspace of four crates:

| Crate                | Role |
| -------------------- | ---- |
| `tunnelbana-core`    | Framework: `Context`, `InternalData`, encrypted state cookie, plugin traits + `Registry`, router, the `Proxy` orchestrator, TOML config, attribute mapping, key loading, TTL/disk cache. **Web-framework agnostic.** |
| `tunnelbana-oidc`    | Reusable OAuth2 / OIDC / OpenID Federation library on `jose-rs`. No proxy or runtime coupling. |
| `tunnelbana-plugins` | The concrete frontends, backends and micro-services, plus `register_all`. |
| `tunnelbana`         | The actix-web binary: config load, plugin instantiation, a `reqwest` HTTP client, request/response glue. |

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

## Plugin kinds

There are three plugin traits, all in `tunnelbana_core::plugin`:

- **`Frontend`** — speaks a protocol to downstream RPs/SPs. Serves endpoints
  (discovery, JWKS, authorization, token, ACS POST, …), starts authentication,
  and renders the final response (a signed SAML Response, an OIDC redirect with
  a code, …).
- **`Backend`** — speaks a protocol to an upstream IdP/OP. Starts authentication
  (an AuthnRequest redirect, an authorization request) and handles the return
  endpoint (the SAML ACS, the OIDC callback).
- **`MicroService`** — intercepts the request and/or response path to transform
  `InternalData` (inject attributes, filter attributes, pick a backend).

A plugin is selected by a `type` string in config and instantiated by a
constructor registered in the [`Registry`](writing-a-plugin.md#the-registry).

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
}
```

Attributes here use **internal** names (e.g. `mail`, `givenname`). The
[attribute map](configuration.md#the-attribute-map) translates to and from each
protocol's external names.

## State is a stateless encrypted cookie

In-flight flow state (the pending authorization request, PKCE verifier, the SAML
request id, …) is sealed into a cookie as a JWE (`dir` + `A256GCM`) under a key
derived from `state_encryption_key`. There is **no server-side session store**,
so the proxy scales horizontally for free. The cookie is attacker-reachable data;
see [Security: the state cookie](security-state-cookie.md) for the AEAD
construction, freshness, key rotation, and the threat model.

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
signed JWTs. The token and userinfo endpoints do no server lookups.
