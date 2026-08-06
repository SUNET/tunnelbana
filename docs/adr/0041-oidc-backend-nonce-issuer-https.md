# ADR 0041 - OIDC backend: mandatory nonce check, explicit issuer, https endpoints

- **Status:** Accepted
- **Date:** 2026-08-05
- **Component:** `tunnelbana-plugins` (`oidc_backend`, `federation_backend`,
  `url_check`).
- **Supersedes in part:** ADR 0033.

The listed ADRs remain immutable historical records. Where this record
conflicts with one of them, the earlier statement is invalid as a description
of current behavior and this record is authoritative.

## Context

Three fail-open edges existed on the RP side. A missing stored `oidc_nonce`
in the callback state was passed to id_token verification as `None`, which
skipped the nonce check entirely — unlike a missing stored state, which is an
error. When explicit endpoints were configured without `issuer`, the
authorization endpoint URL doubled as the expected `iss`, accepting id_tokens
from an issuer nobody configured. And statically configured endpoint/issuer
URLs accepted any scheme, including plain http.

## Decision

- A missing stored `oidc_nonce` at callback time is an authentication error,
  exactly like a missing stored state; the id_token nonce check always runs.
  This applies to both the OIDC and the federation backend.
- Statically configured endpoints (`authorization_endpoint` /
  `token_endpoint`) require an explicit `issuer`; the
  authorization-endpoint-as-issuer fallback is removed.
- Configured `issuer` and endpoint URLs must be https at config load; plain
  http is accepted only for loopback hosts (`localhost`, `127.0.0.0/8`,
  `::1`) for local development. The scheme check lives in the shared
  `url_check` helper.

## Security boundaries

| Threat | Control | Residual risk |
|--------|---------|---------------|
| Lost/tampered nonce state disabling the replay check | Missing stored nonce fails closed | State-cookie integrity still roots in the state secret |
| id_token accepted from an unconfigured issuer | Explicit `issuer` required with static endpoints | Discovery-resolved metadata still trusts the discovery document |
| Token/credential fetch over plaintext | https required for configured endpoints, loopback-only http exception | The loopback exception trusts the local host |

## Consequences

**Positive**

- The nonce check can no longer be skipped by missing state.
- The expected issuer is always an explicitly configured value when
  endpoints are static.
- Plaintext upstream endpoints fail at startup instead of leaking
  credentials at runtime.

**Negative / migration requirements**

- Configurations with static endpoints but no `issuer` must add it.
- Non-loopback http endpoints must move to https (or run on loopback for
  local development).

## References

- `crates/tunnelbana-plugins/src/{oidc_backend,federation_backend,url_check}.rs`
- ADR 0033 (fail-closed security boundaries).
