# ADR 0019 - `attribute_generation` micro-service (Tera templates)

- **Status:** Accepted
- **Date:** 2026-06-10
- **Component:** `tunnelbana-plugins` - `microservices/generation.rs`
  (`AttributeGeneration`, config type `attribute_generation`).
- **Related:** [ADR 0011 - `attribute_processor`](0011-attribute-processor-microservice.md),
  [ADR 0012 - `attribute_authorization`](0012-attribute-authorization-microservice.md).

## Context

SATOSA's `AddSyntheticAttributes` synthesizes attributes from **Mustache**
templates evaluated over the response's attribute set - the canonical case is
deriving `schacHomeOrganization` from the scope of `eduPersonPrincipalName`.
Recipes nest `requester → provider → attribute → template` with
`""`/`"default"` wildcards (`get_dict_defaults`), rendered output is split on
`;`/newlines into values, and each attribute is exposed to the template with
`.value`, `.first`, `.scope` and an iterable `.values` sub-context.

tunnelbana had no synthesis capability at all: `static_attributes` injects
constants and `attribute_processor` only rewrites existing values in place.

## Decision

Port the recipe structure exactly; render with **Tera** instead of Mustache:

- Tera (`tera` crate) is already a workspace dependency - pulling in a
  Mustache implementation would add a dependency solely for syntax
  compatibility - and Tera has native iteration and conditionals, so the
  `{{#attr.values}}…{{/attr.values}}` Mustache section hack becomes an
  ordinary `{% for v in attr.values %}` loop.
- Identical recipe nesting and wildcard lookup via the shared `level()`
  helper; identical post-processing (split on `;`/newline, trim, drop
  empties); synthetic attributes **override** existing ones (SATOSA parity).
- Each attribute appears in the template context as an object with `value`
  (values joined with `;`), `first`, `scope` (substring after `@` of the
  first scoped value) and `values` - the same accessors SATOSA's
  `MustachAttrValue` exposes, minus Mustache-specific shims.
- Templates are compiled into a `Tera` instance at **build time**; a syntax
  error aborts startup. Rendering failures at runtime (e.g. referencing an
  absent attribute strictly) surface as internal errors rather than emitting
  partial values.

## Security boundaries

| Threat | Control | Residual risk |
|--------|---------|---------------|
| Template injection via attribute values | Values enter only as Tera context *data*; templates come exclusively from operator config compiled at startup | - |
| Synthesized attribute spoofing a verified one | Override-on-collision is SATOSA parity and operator-authored; authorization rules (ADR 0012) run on the post-synthesis view if listed after | Recipe order vs. authorization order is config responsibility, documented |
| Cross-requester recipe leakage | Recipes are selected per requester/provider (never merged), so a specific block fully replaces `default` | An operator expecting merge semantics may under-synthesize - same caveat as ADR 0012, documented |

## Consequences

**Positive**

- Scope-derived and composed attributes (`schacHomeOrganization`,
  display-name composition, entitlement stamping) without custom plugins.
- Tera gives loops/conditionals/filters beyond Mustache's logic-less model.

**Negative / accepted trade-offs**

- **SATOSA configs need template translation** - recipe structure ports 1:1,
  but `{{attr}}` Mustache bodies must be rewritten in Tera syntax (usually
  `{{ attr.value }}` or `{{ attr.scope }}`). This is the one service in the
  parity batch whose config is not drop-in; flagged in the parity table.

## References

- `crates/tunnelbana-plugins/src/microservices/generation.rs` -
  implementation + `synthesizes_static_and_scope_derived_attributes`,
  `iterates_values_and_scopes_rules_per_requester` tests
- `../SATOSA/src/satosa/micro_services/attribute_generation.py` - ported
  behavior
