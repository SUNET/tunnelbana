# ADR 0055 - eduID SCIM response enrichment through embedded Python

- **Status:** Accepted
- **Date:** 2026-09-02
- **Components:** `python/tunnelbana_scimapi/scim_attributes.py`,
  `tunnelbana-python`, `tunnelbana-core::attributes`, and the SAML2 backend's
  trusted provider-scope decoration.
- **Related:** [ADR 0030 - eduID scimapi micro-services](0030-eduid-scimapi-microservices.md),
  [ADR 0052 - embedded CPython micro-services](0052-embedded-cpython-microservices.md).

## Context

eduID's SATOSA `ScimAttributes` response micro-service selects a SCIM data
owner, reads a user and optionally their groups, replaces upstream attributes
with the selected SCIM profile, and identifies linked accounts eligible for a
later MFA step-up. It depends on SATOSA classes, a live `AttributeMapper`, a
metadata store, and an escape hatch that places the live service object in
`InternalData`. None of those objects belong across Tunnelbana's deliberately
JSON-only Python boundary.

Tunnelbana already has the required response transformation boundary, but two
narrow inputs were missing. SCIM profile attributes use SAML wire names and
must be converted by the same map as native plugins, and the original service
may select a data owner from Shibboleth `<Scope>` values in trusted IdP
metadata.

The future step-up exchange is a separate feature. This decision only defines
the linked-account output it will consume; it does not add endpoints, suspend
the response pipeline, or process SAML step-up messages.

## Decision

- Ship `tunnelbana_scimapi.scim_attributes.ScimAttributes` as a synchronous,
  response-only Python service. It uses eduID's existing `ScimApiUserDB` and
  optional `ScimApiGroupDB`; those dependencies are installed in the configured
  Python virtual environment, not imported into Rust. Resolve both database
  classes while constructing an explicitly configured service so a missing or
  incompatible eduID package fails proxy startup; unconfigured deployments do
  not import it.
- Add the explicit Python plugin option `pass_internal_attributes = true`.
  Opted-in classes receive a fourth constructor argument: a detached copy of
  Tunnelbana's normalized `internal-name -> profile -> mapping` table. Existing
  three-argument classes are unchanged. The copy contains names, OIDs and
  friendly names only—no secrets, state, clients, or Rust handles.
- Require exactly one internal SAML attribute mapping that recognizes
  `eduPersonPrincipalName`; that internal attribute supplies the SCIM
  `external_id` lookup value. Exactly one value must be present at runtime.
- Preserve the SATOSA data-owner precedence: virtual IdP, authenticating IdP,
  explicit fallback, then the lexicographically first mapped provider scope.
  An unresolved owner follows the deny-by-default unknown-user policy. The
  literal owner `no-scim` is an explicit unconditional pass-through.
- In MDQ mode, extract Shibboleth scope values from the already resolved IdP
  role metadata and publish them only after the SAML response passes normal
  validation. The default MDQ trust policy signature-verifies that metadata;
  the explicitly unsafe `allow_unverified` test mode does not. In static mode,
  the operator may supply equivalent trusted `idp_scopes` on the backend.
  Python sees only the JSON `provider_scopes` decoration.
- Treat `provider_scopes` as read-only at the Python boundary, even when the
  key is initially absent. The native SAML backend always publishes the
  authoritative array after validation, including an empty array.
- Select the lexicographically first SCIM profile, map its SAML attributes to
  internal names and replace those internal values. Group membership and
  ownership produce the eduID entitlement strings; duplicate values are not
  added.
- Publish eligible linked accounts as JSON under the non-persistent
  `mfa_stepup_accounts` decoration. An account is eligible only when its
  `parameters.mfa_stepup` value is exactly `true`, its issuer has an
  operator-configured entity-ID mapping, and its identifier is non-empty. The
  decoration is always initialized to an empty list.
- Do not port `only_configure_and_expose_scim` or
  `scim_class_from_ScimAttributes`. A live Python object can neither be safely
  serialized nor exposed through the strict boundary. The JSON decoration is
  the replacement contract.

## Security boundaries

| Threat | Control | Residual risk |
|--------|---------|---------------|
| Python gains proxy secrets or mutable protocol objects | The fourth argument is a detached attribute-name map only; the existing copied context/data boundary is unchanged | Trusted Python still has the Tunnelbana OS account's filesystem/network access |
| Untrusted assertion metadata chooses another tenant's SCIM database | IdP scopes are published after SAML validation and come from MDQ metadata accepted under its configured trust policy, or explicit static backend configuration | The unsafe MDQ `allow_unverified` mode removes metadata authenticity; incorrect operator mappings can still choose the wrong data owner |
| An upstream attribute fabricates SCIM identity | The lookup key is an operator-mapped internal `eduPersonPrincipalName` and must contain exactly one value | Security ultimately depends on the upstream IdP and attribute-release configuration being trusted for that identifier |
| Database hangs consume Python execution capacity | Tunnelbana's global Python semaphore/deadline still applies; deployment guidance requires shorter MongoDB/Neo4j driver timeouts | CPython calls cannot be killed; a timed-out database call keeps its permit until it returns |
| Linked account redirects a future step-up flow to an attacker | Database issuer values are mapped through an operator-controlled issuer-to-entity-ID table; this ADR only publishes data and performs no redirect | The future step-up implementation must additionally resolve trusted provider metadata and validate issuer, subject and LoA |
| SCIM values leak through logs | The adapter logs outcomes and counts only, not identifiers, profile values, database URIs, or configuration | eduID database dependencies retain their own logging behavior and must be configured appropriately |

## Consequences

SCIM enrichment can be deployed and tested independently of step-up. Existing
Python micro-services keep their constructor contract unless they explicitly
request the attribute map. MDQ-backed SAML flows regain metadata-scope owner
selection without exposing metadata objects to Python; statically pinned IdPs
need `idp_scopes` only when scope-based selection is required.

Deployments must provide an eduID-compatible Python package and its MongoDB
(and optionally Neo4j) dependencies in the configured virtual environment.
The adapter intentionally performs synchronous database calls in
Tunnelbana's bounded blocking-call pool.

## References

- `../eduid-backend/src/eduid/satosa/scimapi/scim_attributes.py`
- `python/tunnelbana_scimapi/scim_attributes.py`
- `crates/tunnelbana-python/tests/scim_attributes.rs`
- `docs/src/scim-attributes.md`
