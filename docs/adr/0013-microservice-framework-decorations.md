# ADR 0013 - Micro-service framework: target-entity and error-redirect decorations

- **Status:** Accepted
- **Date:** 2026-06-10
- **Component:** `tunnelbana-core` - `context.rs`, `proxy.rs`;
  `tunnelbana-plugins` - `saml2_backend.rs`, `microservices/` module split.
- **Related:** ADRs [0014](0014-filter-attributes-policy.md)–[0023](0023-custom-logging-microservice.md)
  (the SATOSA micro-service parity batch this enables), [ADR 0007 - discovery
  service](0007-saml-discovery-service.md).

## Context

Porting the remaining SATOSA micro-services (`satosa_parity.md` §4) hit two
framework gaps:

1. SATOSA's `Context.KEY_TARGET_ENTITYID` decoration - written by hinting and
   discovery micro-services, read by issuer-based routing and the SAML
   backend - had no tunnelbana analog. The SAML2 backend only understood an
   explicit `?entityID=` query parameter.
2. SATOSA micro-services can return a `Redirect` response mid-chain
   (`PrimaryIdentifier`'s `on_error`); tunnelbana's `MicroService` transform
   methods only return `InternalData` or an error, and changing their
   signature would churn every plugin.

Separately, the single `microservices.rs` (770 lines before this batch) was
about to triple in size.

## Decision

Add two well-known decoration keys to `tunnelbana_core::context` instead of
changing any trait signature:

- **`KEY_TARGET_ENTITYID`** (`"target_entity_id"`) - the upstream entity
  chosen for this flow. Producers: `idp_hinting` (ADR 0016); consumers:
  `custom_routing` issuer rules (ADR 0015) and the SAML2 backend, whose
  MDQ-mode `start_auth` now resolves the target as explicit `?entityID=`
  parameter → decoration → configured default → discovery redirect.
  Decorations are per-request and never persisted to the state cookie.
- **`KEY_ERROR_REDIRECT`** (`"error_redirect"`) - an absolute URL. When set,
  `Proxy::render_error` answers any flow error with a **302 to that URL**
  instead of the frontend's protocol error rendering. A micro-service
  "returns a redirect" by setting the decoration and returning `Err`, which
  also cleanly aborts the rest of the chain.

The module was split into
`microservices/{policy,routing,processor,authorization,values,generation,hasher,primary_identifier,logging}.rs`
with the shared `level()` helper (SATOSA's `get_dict_defaults`: exact key →
`""` → `"default"`) and test utilities in `mod.rs`. Public paths
(`tunnelbana_plugins::microservices::*`) are unchanged.

## Security boundaries

| Threat | Control | Residual risk |
|--------|---------|---------------|
| Decoration used to steer users to an attacker-chosen IdP | The decoration only *selects*; the SAML2 backend still resolves the entity through MDQ, which verifies metadata signatures and the IdP role before trusting anything | A hint can select any federation IdP; restricting the set is routing/policy configuration |
| Open redirect via `KEY_ERROR_REDIRECT` | Only operator-configured code sets the decoration; request data never reaches it directly | A micro-service that derived the URL from request input would create one - convention documented on the constant |
| Error redirect leaking error detail | The 302 carries no error message; detail stays in the proxy log | - |

## Consequences

**Positive**

- Discovery, hinting, and issuer-routing now share one SATOSA-shaped contract,
  and `start_auth`'s target resolution has a single documented precedence.
- `KEY_ERROR_REDIRECT` gives the future `ERROR_URL` ops feature (gap list
  item 7) its mechanism for free.
- No trait change: existing third-party plugins compile unchanged.

**Negative / accepted trade-offs**

- Decorations are stringly-keyed; a typo fails silently. Mitigated by always
  importing the constants, never writing literals.
- The error-redirect loses protocol-level error reporting to the RP/SP for
  flows that opt into it - that is its purpose, but operators should know the
  SP sees nothing.

## References

- `crates/tunnelbana-core/src/context.rs` - `KEY_TARGET_ENTITYID`,
  `KEY_ERROR_REDIRECT`
- `crates/tunnelbana-core/src/proxy.rs` - `render_error`
- `crates/tunnelbana-plugins/src/saml2_backend.rs` - MDQ `start_auth`
  resolution order
- `../SATOSA/src/satosa/context.py` (`KEY_TARGET_ENTITYID`),
  `../SATOSA/src/satosa/micro_services/primary_identifier.py` (`Redirect`
  return) - mirrored behavior
