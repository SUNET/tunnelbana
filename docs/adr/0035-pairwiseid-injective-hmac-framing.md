# ADR 0035 - Injective framing for `pairwiseid` HMAC input

- **Status:** Accepted
- **Date:** 2026-08-05
- **Component:** `tunnelbana-plugins` micro-services (`pairwiseid`).
- **Supersedes in part:** ADR 0030.

The listed ADR remains an immutable historical record. Where this record
conflicts with it, the earlier statement is invalid as a description of
current behavior and this record is authoritative.

## Context

`pairwiseid` derived the per-SP identifier as
`HMAC-SHA256(salt, "{requester}-{subject-id}")`. Plain concatenation with a
separator that can also appear inside either component is not injective:
distinct `(requester, subject-id)` pairs such as `("a-b", "c")` and
`("a", "b-c")` produced the identical HMAC input and therefore the same
pairwise identifier, collapsing the unlinkability boundary between two
different requesters.

## Decision

- A new `framing` config option selects the HMAC input framing:
  - `legacy` (**default**): the original `{requester}-{subject-id}`
    concatenation, byte-compatible with earlier releases, so existing
    account links survive upgrades without migration.
  - `v1`: versioned, length-prefixed framing, matching the approach
    ADR 0033 adopted for `primary_identifier`:
    `tbpwid-v1:{requester_len}:{requester}:{subject-id}`. The requester
    length makes the requester/subject boundary unambiguous, and the
    version tag reserves room for future format changes.
- Any other `framing` value is a startup configuration error.
- The output shape is unchanged: lowercase hex digest with the user's scope
  re-appended.

## Security boundaries

| Threat | Control | Residual risk |
|--------|---------|---------------|
| Cross-requester identifier collision | `framing = "v1"` is injective across `(requester, subject-id)` pairs | The default `legacy` framing remains non-injective; operators who need the injective guarantee must opt in and migrate account links |

## Consequences

**Positive**

- Operators can obtain injective framing without waiting for an account-link
  migration window, by setting `framing = "v1"`.
- Upgrades are non-breaking by default: existing pairwise identifiers are
  unchanged unless `v1` is explicitly enabled.

**Negative / migration requirements**

- The non-injective legacy framing remains the default, so the collision
  weakness persists until operators opt in.
- Enabling `v1` changes every pairwise identifier; stored account links
  keyed on the old values must be migrated before enabling it.

## References

- `crates/tunnelbana-plugins/src/microservices/pairwiseid.rs`
- `crates/tunnelbana-plugins/src/microservices/primary_identifier.rs`
  (framing precedent).
- ADR 0030 (eduID `scimapi` micro-services), ADR 0033 (fail-closed security
  boundaries).
