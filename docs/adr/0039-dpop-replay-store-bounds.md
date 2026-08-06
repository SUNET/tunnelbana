# ADR 0039 - DPoP replay store rejects zero max age and over-long `jti`

- **Status:** Accepted
- **Date:** 2026-08-05
- **Component:** `tunnelbana-plugins` (`dpop`).
- **Supersedes in part:** ADR 0033.

The listed ADRs remain immutable historical records. Where this record
conflicts with one of them, the earlier statement is invalid as a description
of current behavior and this record is authoritative.

## Context

Two bounds around the DPoP replay store were missing. First,
`dpop.proof_max_age_secs = 0` was accepted silently: it is both the maximum
proof age and the TTL for recorded `jti`s, so a zero value recorded every
`jti` with an already-elapsed TTL and replay detection became a no-op while
the operator believed it was active. Second, the attacker-controlled `jti`
claim was used verbatim as a cache key, so arbitrarily long `jti`s were
retained in the replay cache for the full window — unbounded
attacker-influenced memory per entry.

## Decision

- `proof_max_age_secs <= 0` with DPoP enabled is a startup configuration
  error; there is no supported mode in which the freshness window is zero.
- A `jti` longer than 256 bytes is rejected as a replay (fail-closed)
  without being retained, bounding the memory any single proof can occupy in
  the cache.

## Security boundaries

| Threat | Control | Residual risk |
|--------|---------|---------------|
| Replay protection silently disabled by configuration | Reject non-positive `proof_max_age_secs` at startup | The replay store remains process-local (ADR 0033) |
| Memory growth via attacker-sized `jti` keys | 256-byte cap, over-long ids rejected and never stored | Aggregate growth across many distinct valid `jti`s is still bounded only by the window and the cache's opportunistic prune |

## Consequences

**Positive**

- A misconfigured freshness window fails loudly at startup instead of
  silently disabling replay detection.
- Per-entry memory in the replay cache has a fixed upper bound.

**Negative / migration requirements**

- Configurations setting `proof_max_age_secs = 0` (previously a silent
  no-op) fail at startup and must set a positive value or disable DPoP.

## References

- `crates/tunnelbana-plugins/src/dpop.rs`
- ADR 0033 (fail-closed security boundaries; process-local replay stores).
