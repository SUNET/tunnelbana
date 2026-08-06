# ADR 0034 - `hasher` rejects an empty per-requester salt

- **Status:** Accepted
- **Date:** 2026-08-05
- **Component:** `tunnelbana-plugins` micro-services (`hasher`).
- **Supersedes in part:** ADR 0021, ADR 0033.

The listed ADRs remain immutable historical records. Where this record
conflicts with one of them, the earlier statement is invalid as a description
of current behavior and this record is authoritative.

## Context

ADR 0033 established that hash processors require a non-empty salt at
startup, and `hasher` enforced this only for the default (`""`) section. A
per-requester entry could still set `salt = ""`: an empty string passed the
`Option<String>` presence check and was used verbatim, silently producing
unsalted hashes for that requester — the exact failure mode the default-section
validation was meant to prevent.

## Decision

- A per-requester `salt` that is present but empty is a startup
  configuration error naming the offending requester, using the same
  non-empty filter as the default section.
- An absent per-requester `salt` continues to inherit the validated default
  salt.

## Security boundaries

| Threat | Control | Residual risk |
|--------|---------|---------------|
| Silently unsalted per-requester hashes | Reject empty per-requester salts at startup | A weak but non-empty salt remains an operator choice |

## Consequences

**Positive**

- The non-empty-salt invariant now holds uniformly for every hasher entry,
  not only the default.

**Negative / migration requirements**

- Configurations that relied on `salt = ""` to obtain unsalted hashes fail at
  startup and must set an explicit salt.

## References

- `crates/tunnelbana-plugins/src/microservices/hasher.rs`
- ADR 0021 (`hasher` micro-service), ADR 0033 (fail-closed security
  boundaries).
