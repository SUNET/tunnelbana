# ADR 0018 - `rename_attributes` micro-service

- **Status:** Accepted
- **Date:** 2026-06-10
- **Component:** `tunnelbana-plugins` - `microservices/values.rs`
  (`RenameAttributes`, config type `rename_attributes`).
- **Related:** [ADR 0008 - attribute map](0008-attribute-map-oids-and-passthrough.md).

## Context

The attribute map (`attributes.toml`) renames attributes at the protocol
edges - wire name ↔ internal name. What it cannot express is an
*internal-to-internal* rename mid-pipeline: e.g. an upstream OP that delivers
a bespoke claim which, after `passthrough_unmapped_attributes`, lands under
its lowercased raw name and must be folded onto the canonical internal
attribute every downstream rule already targets. SATOSA deployments cover
this with a `RenameAttributes` micro-service (a contrib module in SUNET-land,
listed in `satosa_parity.md` §4); chaining `regex_sub` processors cannot do
it either, since `attribute_processor` never adds or removes attributes.

## Decision

A minimal response-path rename service:

- Config is one flat `rename` table, `old internal name → new internal name`,
  applied in deterministic (sorted) order.
- Renaming onto an existing attribute **merges** the values (appended after
  the existing ones) rather than overwriting - dropping asserted values
  silently would be the worse surprise, and a deployment that wants
  replacement can `filter_attributes` the old name away first.
- A missing source attribute is a no-op.
- No per-requester/per-provider scoping: renames are namespace hygiene, not
  release policy. Scoped shaping belongs to the policy/authorization services
  (ADRs 0012/0014/0017); keeping this one global avoids a second
  subtly-different wildcard scheme.

## Security boundaries

| Threat | Control | Residual risk |
|--------|---------|---------------|
| Rename laundering an untrusted passthrough attribute into a trusted name | Renames are explicit operator config; nothing renames by pattern | The operator is asserting the equivalence - renaming `unverified_email` onto `mail` is a policy statement, reviewed like one |
| Value smuggling via merge-on-collision | Merge order is stable (existing values first); authorization rules still run after and see the merged list | Rules matching only the first value of an attribute see the pre-existing one - documented; match all values instead |

## Consequences

**Positive**

- Internal-name normalization without touching the shared attribute map or
  recompiling profiles; SATOSA contrib `RenameAttributes` configs port as the
  `rename` table.

**Negative / accepted trade-offs**

- Merge semantics (vs SATOSA contrib's overwrite) is a deliberate divergence;
  noted in the book.
- No conditional renames; combine with `filter_attributes` ordering when a
  replacement effect is needed.

## References

- `crates/tunnelbana-plugins/src/microservices/values.rs` - implementation +
  `renames_and_merges_attributes` test
- `satosa_parity.md` §4 - the SATOSA contrib module this stands in for
