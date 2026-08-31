# ADR 0053 - `disco_to_target_issuer` and flow-resuming micro-service endpoints

- **Status:** Accepted
- **Date:** 2026-08-27
- **Component:** `tunnelbana-core` - `plugin.rs` (`MicroServiceAction`),
  `proxy.rs` (`finish_request` resume entry); `tunnelbana-plugins` -
  `microservices/disco.rs` (`DiscoToTargetIssuer`, config type
  `disco_to_target_issuer`).
- **Related:** [ADR 0007 - discovery service](0007-saml-discovery-service.md),
  [ADR 0013 - framework decorations](0013-microservice-framework-decorations.md),
  [ADR 0015 - routing by target issuer](0015-custom-routing-target-issuer.md),
  [ADR 0016 - idp_hinting](0016-idp-hinting-microservice.md),
  [ADR 0025 - external federation discovery](0025-external-federation-discovery-service.md),
  [ADR 0029 - router exact-match dispatch](0029-router-exact-match-dispatch.md),
  [ADR 0033 - security audit hardening](0033-security-audit-hardening.md).

## Context

SATOSA deployments that bridge one frontend to *several protocol-variant
backends* - the canonical example is iam-proxy-italia, where the SPID and CIE
SAML federations need differently configured SAML backends - use
`DiscoToTargetIssuer`: the flow first reaches a default backend, whose
discovery redirect sends the browser to an IdP-picker page; the picker's
return (`?entityID=…`) is intercepted by the micro-service, which restores
the suspended flow, decorates `KEY_TARGET_ENTITYID`, and **re-enters the
request pipeline** so `DecideBackendByTargetIssuer` can re-route to the
backend matching the chosen federation.

tunnelbana had every piece of this except the re-entry: the SAML2 backend's
`disco_srv` mode (ADR 0007) covers discovery *within one backend*, and
`custom_routing` issuer rules (ADR 0015) consume `KEY_TARGET_ENTITYID` - but a
micro-service endpoint could only return a bare `Response`
(`MicroService::handle_endpoint`), with no way to resume the authentication
flow the way frontend/backend endpoints do via `FrontendAction`/`BackendAction`.

## Decision

**Core:** `MicroService::handle_endpoint` now returns a `MicroServiceAction`:

- `Respond(Response)` - a complete HTTP response (the previous behavior).
- `ResumeRequest { request: InternalData }` - the proxy re-enters the
  request-path pipeline with the restored data, running only the
  micro-services *after* the resuming one (SATOSA parity: `super().process`
  continues the remaining chain; services before it already ran on the first
  pass), then dispatches to a backend under the normal precedence
  (micro-service pin → default). The originating frontend is recovered from
  `ctx.target_frontend` (restored by the resuming service) or the state
  cookie; a resume with no recoverable frontend fails cleanly.

**Service:** `disco_to_target_issuer` ports SATOSA's `DiscoToTargetIssuer`:

- On `process_request` it snapshots `{target_frontend, internal_data}` into
  its own state-cookie namespace and passes the data through unchanged. The
  snapshot rides the cookie that the default backend's discovery redirect
  already sets.
- `disco_endpoints` is a list of **exact literal paths** (deliberate
  divergence from SATOSA's regexes: the discovery service is configured with
  a fixed return URL, exact routes keep the router's O(1) map per ADR 0029,
  and cannot fail to compile). Micro-service routes register before backend
  routes, so an entry such as `Saml2/disco` deliberately **shadows** the
  default SAML2 backend's own `disco_srv` return route - the same intercept
  SATOSA achieves with `.*/disco`. The outbound hop to the IdP-picker page
  remains owned by the default backend's `disco_srv` (or the deployment).
- On the discovery return it requires a well-formed `entityID` query
  parameter (non-empty, ≤ 1024 bytes, no control characters), reads and
  **consumes** the snapshot, restores `target_frontend`, decorates
  `KEY_TARGET_ENTITYID` (first-writer-wins holds trivially - decorations are
  per-request), and returns `ResumeRequest` so `custom_routing` re-picks the
  backend.
- **Unmatched issuers fail closed** (deliberate divergence from SATOSA,
  which accepts any entityID): exactly one of `allowed_issuers` (enumerated
  allowlist, checked before the snapshot is consumed so the user can pick
  again) or `allow_any_issuer = true` must be configured. The explicit
  opt-out exists for MDQ-scale federations where enumerating issuers is
  impossible and signed metadata verification is the effective allowlist.
- The allowlist is **requester-scoped**: `allowed_issuers` maps a requester
  to its issuer set (the standard rule-set levels - exact, else `""`, else
  `"default"`), keyed by the resumed snapshot's requester; a requester with
  no applicable set is rejected. A global list would under-enforce: the
  target-issuer decoration is only consumed by `custom_routing` when an
  `(issuer, requester)` rule matches, but on a miss the flow *falls through*
  to requester/default routing with the decoration still set, so a
  requester with no issuer rule could authenticate at any globally listed
  issuer via the fallback backend's MDQ metadata resolution.
- The serialized snapshot is capped at **2048 bytes** in `process_request`;
  an oversized flow fails with a protocol error *before* the disco redirect.
  Complementing that, `Proxy::run` now fails any response whose state cannot
  be sealed (explicit error + state-clearing cookie) instead of sending it
  without a `Set-Cookie` header, which would strand multi-step flows.

An empty or malformed `disco_endpoints` list, and a missing or ambiguous
issuer policy, are build-time config errors.

## Security boundaries

| Threat | Control | Residual risk |
|--------|---------|---------------|
| Replayed discovery return re-starting authentication | Consume-once: the snapshot is cleared from state before resuming, so the resealed cookie on the response no longer carries it and a repeat fails with "no discovery flow in progress" | A cookie *captured before* the resume still holds the snapshot - inherent to stateless state, bounded by the cookie's absolute TTL (same residual as the state-cookie replay row in ADR 0033) |
| Forged cross-site disco return with no flow open | The endpoint can only *resume* an existing snapshot, never initiate; no snapshot ⇒ clean 4xx (contrast the forged-`/initiate` risk that motivated ADR 0025's verifier - here the return cannot create a flow) | - |
| Attacker-chosen `entityID` steering an open flow | Unmatched issuers fail closed: exactly one of `allowed_issuers` (a **requester-scoped** allowlist - the resumed flow's requester selects its issuer set, checked before the resume, so neither an unlisted issuer nor a requester without an applicable set can ride the decoration through `custom_routing`'s requester/default fallback into a backend's metadata resolution) or an explicit `allow_any_issuer = true` must be configured. Backend selection is additionally gated by `custom_routing`'s mandatory `(issuer, requester)` rules and by signature-verified MDQ / federation metadata at `start_auth` | With `allow_any_issuer = true` (only sound when verified metadata is the effective allowlist), a forged return riding the SameSite=None cookie while a flow is open can pre-select a different *federation-trusted* IdP - the same exposure class as a forged `?idphint` (ADR 0016), surfaced to the user at the IdP login page. An `""`/`"default"` allowlist level extends its issuer set to every requester - an explicit operator choice |
| Header/log injection via `entityID` | Length cap (1024 bytes) and ASCII-control-character rejection before the value reaches decorations or logs | - |
| Oversized snapshot stranding the flow mid-discovery | Two layers: a 2048-byte cap on the serialized snapshot in `process_request` fails the flow with a protocol error *before* the disco redirect; and `Proxy::run` no longer sends any response whose state failed to seal - it returns an explicit error with a state-clearing cookie instead of a cookie-less redirect that could never resume | Operators stacking attribute-heavy request-path services before this one see the flow rejected; reorder the pipeline |

Divergence from ADR 0025's one-time verifier is deliberate: tunnelbana does
not emit the outbound redirect to the discovery page (the default backend or
the deployment does), so there is no place to plant a verifier - and unlike
the federation `/initiate` case, this return cannot *create* trust; the
snapshot is the binding.

## Consequences

**Positive**

- Full SATOSA `DiscoToTargetIssuer` parity: one discovery page can route
  between differently configured backends (the SPID-vs-CIE shape).
- `MicroServiceAction::ResumeRequest` is the generic suspend/resume mechanism
  future interactive micro-services (consent, account linking) need.
- Covered end to end in `crates/tunnelbana-plugins/tests/disco_flow.rs`:
  cross-backend re-route with full flow completion, replay rejection, forged
  returns, and unlisted issuers.

**Negative / accepted trade-offs**

- `MicroService::handle_endpoint`'s return type changed (pre-1.0 API break);
  no in-tree service overrode it before this change.
- Decorations are per-request and are **not** snapshotted: request-path
  decorations set before the discovery hop (e.g. `KEY_REQUESTED_ACCR`) are
  absent after the resume. SATOSA behaves identically (its snapshot is also
  only `target_frontend` + the internal data). Place decoration-writing
  services after `disco_to_target_issuer` when their output must survive the
  hop, or extend the snapshot later - the JSON blob is forward-compatible.
- The resume runs only the services *after* the disco service; operators must
  list `custom_routing` after it (documented; same ordering requirement SATOSA
  has).

## References

- `crates/tunnelbana-core/src/plugin.rs` / `proxy.rs` - `MicroServiceAction`,
  `finish_request`
- `crates/tunnelbana-plugins/src/microservices/disco.rs` - implementation +
  unit tests
- `crates/tunnelbana-plugins/tests/disco_flow.rs` - end-to-end coverage
- `../SATOSA/src/satosa/micro_services/disco.py` - ported behavior
- iam-proxy-italia `conf/microservices/disco_to_target_issuer.yaml` +
  `target_based_routing.yaml` - the deployment shape this enables
