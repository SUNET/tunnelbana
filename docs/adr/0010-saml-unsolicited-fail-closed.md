# ADR 0010 — Fail-closed InResponseTo handling and `allow_unsolicited`

- **Status:** Accepted
- **Date:** 2026-06-09
- **Component:** `tunnelbana-plugins` — `saml2_backend.rs`
  (`allow_unsolicited`, the `expected_id` gate in `process_acs`).
- **Related:** [ADR 0001 — encrypted state cookie](0001-state-cookie-encryption.md).

## Context

SATOSA's `SAMLBackend` exposes `allow_unsolicited` for IdP-initiated SSO.
tunnelbana is stateless-by-cookie: a truly unsolicited Response arrives with
**no state cookie**, so there is no originating frontend to resume — the proxy
hard-fails before the backend is even consulted. Full IdP-initiated SSO
(reconstructing a requester out of thin air) is therefore out of scope; the
flag can only meaningfully relax the `InResponseTo` requirement *within an
existing flow*.

Reviewing the ACS also surfaced a **silent fail-open**: the stored AuthnRequest
id was passed to the validator as an `Option`, and when it was missing (cookie
replayed onto a different module name, state cleared, hand-crafted request)
the validator simply skipped the InResponseTo check.

## Decision

In `process_acs`, after parsing:

- a stored `authn_id` is **required** by default; if it is missing the
  response is rejected with "unsolicited responses are disabled" — never
  validated with the check skipped;
- with `allow_unsolicited = true` (default false), a response carrying **no**
  `InResponseTo` may proceed with `expected_request_id: None`;
- a response that *does* carry `InResponseTo` while nothing is in flight is
  rejected even with the flag (a dangling `InResponseTo` is either a replay or
  a confusion attack, never a legitimate unsolicited response).

Frontend reconstruction for cookie-less IdP-initiated SSO is deliberately
**not built**; if SUNET turns out to exercise IdP-initiated SSO through the
proxy, that needs its own design (and likely a configured default frontend +
requester), not a relaxation here.

## Security boundaries

| Threat | Control | Residual risk |
|--------|---------|---------------|
| Replay of a captured Response onto a fresh session | Default: no stored id ⇒ rejected. With the flag: only InResponseTo-less responses pass, and assertion freshness/conditions still apply | Within the assertion validity window an unsolicited response is replayable by design — that is what the flag opts into |
| Silent InResponseTo skip (previous behavior) | Removed: missing state is now an explicit rejection | — |
| Cross-flow response splicing (dangling InResponseTo) | Rejected even with `allow_unsolicited` | — |

## Consequences

**Positive**

- The ACS fails closed; the validator's InResponseTo check can no longer be
  skipped by losing state.
- SATOSA config parity for the common case (the flag exists, defaults safe).

**Negative / accepted trade-offs**

- True IdP-initiated SSO (no cookie at all) remains unsupported; SATOSA's
  `allow_unsolicited: true` in the SUNET config is likely cargo-culted, and
  this implements the safe subset.

## References

- `crates/tunnelbana-plugins/src/saml2_backend.rs` — the `expected_id` match
- `crates/tunnelbana-plugins/tests/saml_roundtrip.rs` — default rejection,
  flag acceptance, dangling-InResponseTo rejection
