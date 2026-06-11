# ADR 0015 - `custom_routing` by target issuer (`DecideBackendByTargetIssuer`)

- **Status:** Accepted
- **Date:** 2026-06-10
- **Component:** `tunnelbana-plugins` - `microservices/routing.rs`
  (`CustomRouting`, config type `custom_routing`).
- **Related:** [ADR 0013 - framework decorations](0013-microservice-framework-decorations.md),
  [ADR 0016 - `idp_hinting`](0016-idp-hinting-microservice.md).

## Context

SATOSA routes flows to backends with three request-path micro-services:
`DecideBackendByRequester` (who is asking), `DecideBackendByRequesterName`,
and `DecideBackendByTargetIssuer` (where the user wants to authenticate, read
from the `KEY_TARGET_ENTITYID` decoration). tunnelbana's `custom_routing`
covered only the by-requester case; with the target-entity decoration in
place (ADR 0013), a deployment fronting several backends - say a SAML
federation backend and an OIDC upstream - could not send a hinted or
disco-chosen IdP to the right backend.

## Decision

Extend `custom_routing` with an `issuer_rule` list instead of adding a second
routing type (SATOSA's split into three modules is a Python-class artifact,
not a config benefit):

- `[[microservice.config.issuer_rule]]` entries (`issuer` → `backend`) are
  matched against the `KEY_TARGET_ENTITYID` decoration.
- Precedence within the service: **issuer rule → requester rule →
  `default_backend`**. The issuer wins because it is the more specific signal:
  it names the actual authentication target, while the requester is a
  routing heuristic.
- The decoration is only consulted, never written, by this service; producers
  are `idp_hinting` (ADR 0016) or future discovery-style services.
- As before, the proxy-wide precedence still applies above this service: a
  backend pinned by the frontend's `StartAuth` beats anything a micro-service
  sets.

Matching is exact-string on entity ids, like SATOSA's `target_mapping` dict.

## Security boundaries

| Threat | Control | Residual risk |
|--------|---------|---------------|
| Request-controlled hint steering a flow to an unintended backend | `issuer_rule` is a closed, operator-written map; an unmatched issuer falls through to requester rules / default | A *listed* issuer is routable by anyone who can set the hint - list only issuers every requester may use |
| Routing decision bypassing per-backend policy | Routing only picks the backend; attribute release and authorization run unchanged on the response path | - |

## Consequences

**Positive**

- SATOSA `DecideBackendByTargetIssuer` configs port as `issuer_rule` entries;
  `DecideBackendByRequester` configs continue to port as `rule` entries.
- One service, one precedence order - no inter-service ordering puzzles
  between two routing modules.

**Negative / accepted trade-offs**

- No regex/wildcard matching on issuer (SATOSA has none either); large
  federations route per-issuer only for the few special cases, with
  `default_backend` carrying the rest.

## References

- `crates/tunnelbana-plugins/src/microservices/routing.rs` - implementation +
  `routing_by_target_issuer_beats_requester` test
- `../SATOSA/src/satosa/micro_services/custom_routing.py`
  (`DecideBackendByTargetIssuer`, `DecideBackendByRequester`) - ported behavior
