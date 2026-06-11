# ADR 0014 - `filter_attributes` per-requester policy (`AttributePolicy`)

- **Status:** Accepted
- **Date:** 2026-06-10
- **Component:** `tunnelbana-plugins` - `microservices/policy.rs`
  (`FilterAttributes`, config type `filter_attributes`).
- **Related:** [ADR 0013 - framework decorations](0013-microservice-framework-decorations.md),
  [ADR 0012 - `attribute_authorization`](0012-attribute-authorization-microservice.md).

## Context

SATOSA's `AttributePolicy` micro-service keeps a per-requester allowlist:

```yaml
attribute_policy:
  https://sp.example.org:
    allowed:
      - mail
```

tunnelbana's `filter_attributes` only had one global `allowed` list applied to
every requester, so a deployment could not release a broader set to one SP
than to another at the cross-protocol layer. (The SAML frontend's
`[policy]` table covers SAML SPs only; this micro-service is the
protocol-agnostic layer.)

A wrinkle in the existing behavior: `allowed` defaulted to an **empty list**,
and an empty list drops *everything* - so a `filter_attributes` block without
an `allowed` key silently stripped all attributes.

## Decision

Extend `filter_attributes` rather than adding a separate type:

- New optional `policy` table keyed by requester, each entry carrying its own
  `allowed` list. Lookup follows the shared `level()` helper: exact requester
  → `""` → `"default"` (SATOSA's `get_dict_defaults`, consistent with
  `attribute_authorization`). SATOSA's own `AttributePolicy` has *no* wildcard
  fallback; supporting one here is a deliberate, strictly-more-expressive
  extension.
- A matching policy entry **replaces** the global `allowed` list (selected,
  not merged - same rule-selection philosophy as ADR 0012).
- The global `allowed` becomes `Option`: **absent** means pass-through (no
  filtering) unless a policy entry matches, matching SATOSA's "no policy for
  this requester → untouched". An explicitly **empty** `allowed = []` still
  means "drop everything", preserving the deliberate use of the old behavior.

## Security boundaries

| Threat | Control | Residual risk |
|--------|---------|---------------|
| Over-release to a specific SP | Per-requester `policy` entry narrows the release for exactly that requester | Entries are selected, not merged: an entry must list *everything* the SP may see |
| Accidental full release after upgrade | Only the no-`allowed`-key case changes to pass-through; any configured list behaves as before | A config that *relied* on the empty-default-drops-all quirk now releases attributes - called out in the CHANGELOG |
| Filtering bypassed for an unlisted requester | `""`/`"default"` wildcard entry, or the global `allowed`, catches requesters without a specific entry | With neither configured, unlisted requesters get everything - that is the documented pass-through default |

## Consequences

**Positive**

- SATOSA `AttributePolicy` configs port directly (requester → `allowed`).
- One micro-service covers both the global and per-requester filtering modes.

**Negative / accepted trade-offs**

- The empty-vs-absent `allowed` distinction is subtle; documented in the book
  and the config reference.

## References

- `crates/tunnelbana-plugins/src/microservices/policy.rs` - implementation +
  `per_requester_policy_overrides_global`, `no_config_passes_through` tests
- `../SATOSA/src/satosa/micro_services/attribute_policy.py` - ported behavior
