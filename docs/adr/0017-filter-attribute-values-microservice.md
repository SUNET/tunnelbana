# ADR 0017 - `filter_attribute_values` micro-service

- **Status:** Accepted
- **Date:** 2026-06-10
- **Component:** `tunnelbana-plugins` - `microservices/values.rs`
  (`FilterAttributeValues`, config type `filter_attribute_values`).
- **Related:** [ADR 0014 - `filter_attributes` policy](0014-filter-attributes-policy.md),
  [ADR 0012 - `attribute_authorization`](0012-attribute-authorization-microservice.md).

## Context

`filter_attributes` drops whole attributes and `attribute_authorization`
rejects whole flows; neither can trim individual **values** out of a
multi-valued attribute. SATOSA's `FilterAttributeValues` does exactly that -
the canonical federation case is scope-filtering: keep only
`eduPersonPrincipalName` values in the home organization's domain, dropping
values an upstream IdP asserted outside its authority.

SATOSA's config nests `provider (issuer) → requester → attribute → filter`,
where `""` keys are defaults applied **in addition to** (before) the specific
entries - cumulative, unlike the selected-not-merged rules of
`attribute_authorization`. Filters come in two notations (bare regex string
or `{regexp: …}`) plus two `shibmdscope_match_*` types that check values
against the `<shibmd:Scope>` elements of the asserting IdP's metadata,
fetched through a metadata-store context decoration.

## Decision

Port the regex core faithfully; reject the metadata-dependent filter types:

- Same nesting and the same **cumulative** application order: default
  provider (`""`) then specific provider; within each, default requester then
  specific requester. An attribute key of `""` applies the filter to every
  attribute. Only `""` is the wildcard here - *not* `"default"` - matching
  SATOSA, which uses plain `.get("")` in this module.
- Both filter notations are accepted (`untagged` deserialization); values are
  kept when the regex **search** matches (`Regex::is_match`, like
  `re.search`).
- `shibmdscope_match_scope` / `shibmdscope_match_value` are a **build-time
  config error**: tunnelbana has no metadata-store decoration for
  micro-services yet, and silently treating them as keep-all or drop-all
  would be a policy surprise in either direction. The error message names the
  unsupported type.
- All regexes compile at startup; a value list can end up empty (the
  attribute then remains, with zero values - same as SATOSA's
  `list(filter(...))`).

## Security boundaries

| Threat | Control | Residual risk |
|--------|---------|---------------|
| Scope injection: an IdP asserting values for a domain it does not own | Per-provider value filters pin acceptable value shapes per issuer | Static config approximates what `shibmdscope_*` derives from signed metadata - it must be maintained by hand |
| Config porting silently dropping a SATOSA shibmd filter | Unsupported filter types abort startup instead of degrading | Operators must rewrite such filters as explicit regexes |
| Pattern matching too loosely (substring match) | Same `re.search` semantics as SATOSA - anchors are the operator's job; documented with anchored examples | Unanchored patterns over-match; examples in the book all anchor |

## Consequences

**Positive**

- SATOSA `FilterAttributeValues` regex configs port 1:1, both notations.
- Closes the per-value gap in the filtering trio (attribute-level,
  value-level, flow-level).

**Negative / accepted trade-offs**

- No metadata-driven scope filtering until a metadata-store decoration
  exists; tracked as the natural follow-up if SUNET needs it.

## References

- `crates/tunnelbana-plugins/src/microservices/values.rs` - implementation +
  `requester_and_provider_specific_filters_stack_on_defaults` test
- `../SATOSA/src/satosa/micro_services/attribute_modifications.py` - ported
  behavior
