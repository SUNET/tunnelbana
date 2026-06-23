# ADR 0027 - Frontend-level backend pin (`backend = "<name>"`)

- **Status:** Accepted
- **Date:** 2026-06-23
- **Component:** `tunnelbana-plugins` - `oidc_frontend.rs`,
  `federation_frontend.rs`, `saml2_frontend.rs` (frontend `config.backend`).
- **Related:** [ADR 0013 - framework decorations](0013-microservice-framework-decorations.md),
  [ADR 0015 - `custom_routing` by target issuer](0015-custom-routing-target-issuer.md),
  [ADR 0016 - `idp_hinting`](0016-idp-hinting-microservice.md).

## Context

A deployment can run several `[[backend]]` instances at once; the proxy keys
them by `name` and treats the **first** as the default
(`Proxy::default_backend`). Until now the per-flow backend choice could only be
made by a request-path micro-service - `custom_routing` (ADR 0015), usually fed
by `idp_hinting` (ADR 0016) - or fall through to that default. The frontend half
of the selection chain existed in the plumbing but was unreachable from config:
`FrontendAction::StartAuth` already carries `target_backend: Option<String>`, and
`Proxy::dispatch_frontend` already consults it *before* any micro-service pin or
the default (`target_backend.or(ctx.target_backend).or(default_backend)`). All
three frontends hardcoded `target_backend: None`.

The common operator need is the simplest one: *"this entry point always
authenticates against that upstream."* A SAML IdP frontend that must always use
an OIDC federation backend, an OIDC OP frontend wired to a SAML SP backend, two
OPs each bound to a different upstream. Expressing that with `custom_routing`
forces a routing service plus per-requester or per-issuer rules to encode what is
really a static, frontend-wide fact - and a request-supplied `idphint` could
still steer the flow elsewhere.

## Decision

Add an optional `backend: Option<String>` field to each frontend's config
(`oidc`, `oidc_federation`, `saml2`). When set, the frontend returns it as
`StartAuth { target_backend: Some(name) }`; when unset (the default) it returns
`None` exactly as before.

- The pin reuses the **existing** proxy precedence - **frontend pin → micro-service
  pin → default backend** - so a pinned frontend deterministically overrides the
  backend selected by `custom_routing` / `idp_hinting`. This is intentional: the
  pin states a fixed property of the entry point, so a request-controlled hint
  must not move it to another backend. Request-path micro-services still run,
  and non-selection effects (for example, target-entity decorations consumed by
  the pinned backend itself) still apply.
- The value is matched exactly against the configured `[[backend]]` names, the
  same string-keyed lookup `custom_routing` uses.
- Validation is deferred to dispatch, consistent with `custom_routing`: an
  unknown name surfaces as `Error::UnknownModule(name)` and fails that flow,
  rather than aborting boot. The frontend `build()` step does not see the
  backend registry, and a frontend is legal in a single-backend deployment where
  the pin is redundant but harmless.
- No change to the response path: the backend that handled the request is
  recovered from the sealed state as before; the pin only affects request-path
  selection.

## Security boundaries

| Threat | Control | Residual risk |
|--------|---------|---------------|
| Request-controlled hint (`idphint`, requester) steering a pinned entry point to an unintended backend | Frontend pin sits above micro-service routing in the fixed precedence; a pinned frontend ignores the backend selected by `custom_routing` / `idp_hinting` | Request-path micro-services still run, so hints/decorations may still influence behavior inside the pinned backend; an operator who *wants* request-driven backend routing must leave `backend` unset - the pin is all-or-nothing per frontend |
| Pin pointing at a non-existent backend | Exact-name lookup fails the flow with `UnknownModule`; selection never silently falls back to the default | Misconfiguration is caught on first use, not at boot (same surface as a stray `custom_routing` rule) |
| Pin bypassing per-backend policy | The pin only selects the backend; attribute release, authorization and the response-path micro-services run unchanged | - |

## Consequences

**Positive**

- A static "frontend always uses backend X" deployment needs one line of config
  and no routing micro-service.
- Uses the precedence and plumbing that already existed; no new proxy code, no
  new decoration key.
- Uniform across all three frontends, so the surface is the same wherever an
  entry point is defined.

**Negative / accepted trade-offs**

- The pin is an unconditional override, not a default-with-override: a frontend
  cannot say "prefer X but let `idp_hinting` redirect." That layered case stays
  the job of `custom_routing` with `default_backend` (leave the frontend
  unpinned). Splitting the difference would reintroduce the request-controlled
  steering the pin exists to prevent.
- An invalid name is a runtime error, not a boot error, because frontends are
  built without visibility into the backend registry. This matches
  `custom_routing` and keeps frontends backend-oblivious.

## References

- `crates/tunnelbana-plugins/src/oidc_frontend.rs`,
  `federation_frontend.rs`, `saml2_frontend.rs` - `config.backend` → `StartAuth`
- `crates/tunnelbana-core/src/proxy.rs` - `dispatch_frontend` selection
  precedence (`target_backend.or(ctx.target_backend).or(default_backend)`)
- `crates/tunnelbana-plugins/tests/proxy_oidc_op.rs` -
  `frontend_backend_pin_overrides_default`
- [Configuration: Backend selection](../src/configuration.md)
