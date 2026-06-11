# ADR 0022 - `primary_identifier` micro-service

- **Status:** Accepted
- **Date:** 2026-06-10
- **Component:** `tunnelbana-plugins` - `microservices/primary_identifier.rs`
  (`PrimaryIdentifier`, config type `primary_identifier`).
- **Related:** [ADR 0013 - framework decorations (`KEY_ERROR_REDIRECT`)](0013-microservice-framework-decorations.md).

## Context

Federation deployments rarely get one uniform identifier from every upstream
IdP: some assert `eduPersonUniqueId`, others only `eduPersonPrincipalName`,
others a persistent NameID. SATOSA's `PrimaryIdentifier` walks an **ordered
candidate list** - each candidate a set of attribute names (with the special
name `name_id` for the SAML subject) - takes the first candidate whose values
are all present, concatenates them (optionally appending a scope), and
asserts the result as a configured attribute, optionally replacing
`subject_id`. On failure it can redirect the browser to an external error
service.

tunnelbana covered a sliver of this via `user_id_from_attrs` (fixed
attribute concatenation into `subject_id` at the backend) - no fallback
ordering, no `name_id` candidate, no error redirect. The redirect needs the
`KEY_ERROR_REDIRECT` mechanism from ADR 0013.

## Decision

Port `PrimaryIdentifier` as a response-path service with a typed config:

- `ordered_identifier_candidates` (required, non-empty): each candidate has
  `attribute_names` (first values are concatenated; any missing one skips the
  candidate), optional `name_id_format`, optional `add_scope` (literal, or
  `issuer_entityid` for the asserting IdP's entity id, appended last).
- The `name_id` pseudo-attribute contributes `subject_id` only when the
  candidate's `name_id_format` matches `InternalData.subject_type`; the
  format may be a SAML URN or a short name (`persistent`, `transient`,
  `public`, `pairwise`), since tunnelbana's internal subject types also stand
  in for OIDC. A subject value already asserted as an attribute value is not
  appended twice (SATOSA's workaround for IdPs that duplicate eppn into the
  NameID).
- Defaults: `primary_identifier = "uid"`, `clear_input_attributes = false`,
  `replace_subject_id = false`.
- **Per-entity overrides** live under an explicit `override."<entity-id>"`
  table - *not* mixed into the top level as in SATOSA's YAML, which cannot be
  typed-parsed and makes typos indistinguishable from settings. Overrides are
  keyed by SP (requester) or IdP (issuer); both are applied IdP-first so an
  SP override wins on conflict (SATOSA's precedence). `ignore = true` skips
  the service for that entity.
- **`on_error`**: when no candidate succeeds and `on_error` is set, the
  service writes `<on_error>?sp=…&idp=…` (URL-encoded) to
  `KEY_ERROR_REDIRECT` and returns an authentication error - the proxy then
  302s the browser to the error service. Without `on_error`, the response
  passes through unchanged (SATOSA parity), leaving downstream policy (e.g.
  `attribute_authorization` on the identifier) to decide.

## Security boundaries

| Threat | Control | Residual risk |
|--------|---------|---------------|
| Identifier built from a NameID of the wrong durability (transient as stable id) | `name_id` contributes only when `name_id_format` matches the response's subject type | - |
| Cross-IdP identifier collisions | `add_scope = "issuer_entityid"` namespaces the identifier by the asserting IdP | Only if the candidate uses it; unscoped candidates are the operator's informed choice |
| Flow continuing without any identifier | `on_error` turns the failure into an explicit redirect; otherwise pair with a `force_attributes_presence_on_allow` rule on the identifier (ADR 0012) to hard-fail | Pass-through-on-failure is SATOSA parity and documented |
| Open redirect via `on_error` | Operator config only; query parameters are URL-encoded values of requester/issuer | - |

## Consequences

**Positive**

- Heterogeneous-federation identifier policy in config, with per-SP/per-IdP
  exceptions, replacing ad-hoc `user_id_from_attrs` chains for the complex
  cases (the simple backend-level mechanism remains).
- The typed `override` table catches config mistakes SATOSA's free-form YAML
  cannot.

**Negative / accepted trade-offs**

- SATOSA configs need a mechanical reshape (entity ids move under
  `override`); field names and semantics are otherwise identical.
- The identifier is asserted as a normal attribute, so chain order matters -
  it must run before filters/authorization that act on it.

## References

- `crates/tunnelbana-plugins/src/microservices/primary_identifier.rs` -
  implementation + `falls_through_candidates_in_order`,
  `name_id_candidate_requires_matching_subject_type`,
  `on_error_sets_redirect_decoration_and_fails`,
  `per_entity_overrides_and_ignore` tests
- `../SATOSA/src/satosa/micro_services/primary_identifier.py` - ported
  behavior
