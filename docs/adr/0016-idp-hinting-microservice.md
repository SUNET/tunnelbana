# ADR 0016 - `idp_hinting` micro-service

- **Status:** Accepted
- **Date:** 2026-06-10
- **Component:** `tunnelbana-plugins` - `microservices/routing.rs`
  (`IdpHinting`, config type `idp_hinting`).
- **Related:** [ADR 0013 - framework decorations](0013-microservice-framework-decorations.md),
  [ADR 0015 - routing by target issuer](0015-custom-routing-target-issuer.md),
  [ADR 0007 - discovery service](0007-saml-discovery-service.md).

## Context

A downstream SP/RP that already knows which upstream IdP its user belongs to
can skip discovery by sending a hint query parameter (`?idphint=…` and
variants) on the authentication request. SATOSA's `IdpHinting` micro-service
lifts the first recognized parameter into the `KEY_TARGET_ENTITYID`
decoration. tunnelbana's SAML2 backend honored only its own `?entityID=`
parameter, so OIDC-initiated flows (where the RP controls the authorization
request's extra query parameters) had no way to pre-select the IdP, and the
hint parameter name was not configurable.

## Decision

Port `IdpHinting` as a request-path micro-service:

- Config is a single required, non-empty `allowed_params` list - the
  recognized hint parameter names, checked in order against the inbound
  request's query parameters; the first present, non-empty value wins.
- The value is written to `KEY_TARGET_ENTITYID`. **An existing decoration is
  never overwritten** (SATOSA parity: a discovery choice or earlier service
  beats a hint).
- The service does nothing else: consumption is the SAML2 backend's MDQ
  target resolution and `custom_routing`'s issuer rules (ADRs 0013/0015).
- List it **before** `custom_routing` in the config so issuer rules see the
  hint - pipeline order is config order.

An empty `allowed_params` is a build-time config error rather than a silent
no-op.

## Security boundaries

| Threat | Control | Residual risk |
|--------|---------|---------------|
| Attacker-supplied hint redirecting authentication to a malicious "IdP" | The hint only *selects*; the SAML2 backend resolves the entity via MDQ with metadata-signature and IdP-role verification before sending anything | Phishing *within* the federation: a hint can pre-select any legitimate federation IdP - same exposure as SATOSA |
| Hint overriding an explicit discovery choice | First-writer-wins: an existing decoration is never replaced | - |
| Parameter squatting (`client_id`, `state`, …) | Only operator-listed parameter names are consulted | Operators should choose names that cannot collide with protocol parameters |

## Consequences

**Positive**

- SATOSA `IdpHinting` configs (`allowed_params`) port verbatim.
- Works for any frontend protocol, since the hint rides the query string of
  whatever endpoint starts the flow.

**Negative / accepted trade-offs**

- No validation that the hinted value *is* an entity id - an unknown entity
  simply fails MDQ resolution later with an authentication error (SATOSA
  behaves the same).

## References

- `crates/tunnelbana-plugins/src/microservices/routing.rs` - implementation +
  `idp_hinting_sets_decoration_once` test
- `../SATOSA/src/satosa/micro_services/idp_hinting.py` - ported behavior
