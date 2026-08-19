# ADR 0042 - Federation trust-resolution hardening: https endpoints and negative caching

- **Status:** Accepted
- **Date:** 2026-08-05
- **Component:** `tunnelbana-plugins` (`federation_frontend`,
  `federation_backend`, `url_check`).
- **Supersedes in part:** ADR 0024, ADR 0033.

The listed ADRs remain immutable historical records. Where this record
conflicts with one of them, the earlier statement is invalid as a description
of current behavior and this record is authoritative.

## Context

Two gaps existed around trust-anchor resolution results. In the federation
backend, OP endpoint URLs recovered from a resolve response
(`authorization_endpoint`, `token_endpoint`, `userinfo_endpoint`, `jwks_uri`)
were redirected to or fetched with credentials attached without any scheme
check, so a compromised or malicious resolution path could downgrade the flow
to plaintext. In the federation frontend, an unknown `client_id` triggered a
fresh trust-anchor resolution on every request — no negative-result caching —
so a spray of unknown ids fanned out to trust-anchor fetches unboundedly.

## Decision

- TA-resolved OP endpoints must be https before use; plain http is accepted
  only for loopback hosts (`localhost`, `127.0.0.0/8`, `::1`) so tests and
  local development keep working. The check uses the shared `url_check`
  helper and fails the flow as an authentication error.
- A failed RP resolution is negatively cached for 60 seconds
  (`TtlCache`), keyed by `client_id`; within that window the request is
  rejected with `invalid_request` without consulting the trust anchors.
  Successful resolutions continue to be cached under the existing,
  trust-expiry-bounded RP cache.

## Security boundaries

| Threat | Control | Residual risk |
|--------|---------|---------------|
| Downgrade to plaintext via resolved metadata | https required for all resolved endpoints, loopback-only http exception | A TA vouching for a malicious but https OP remains a trust-anchor compromise |
| Resolve fan-out from unknown `client_id` spray | 60-second negative cache per id | Each *distinct* unknown id still costs one resolution per window |

## Consequences

**Positive**

- Resolved endpoints cannot steer the proxy into plaintext redirects or
  credential-bearing fetches.
- Repeated failing resolutions cost one trust-anchor round trip per minute
  instead of one per request.

**Negative / migration requirements**

- Federations resolving non-loopback http endpoints (not standards-compliant
  in production) must move to https.
- A client_id that fails resolution once is rejected from cache for up to 60
  seconds even if the underlying cause is fixed sooner.

## References

- `crates/tunnelbana-plugins/src/{federation_frontend,federation_backend,url_check}.rs`
- ADR 0024 (OpenID Federation backend), ADR 0033 (fail-closed security
  boundaries).
