# ADR 0038 - Per-frontend token sealing and DPoP nonce keys

- **Status:** Accepted
- **Date:** 2026-08-05
- **Component:** `tunnelbana-plugins` (`oidc_frontend`, `federation_frontend`,
  `dpop`).
- **Supersedes in part:** ADR 0002, ADR 0033.

The listed ADRs remain immutable historical records. Where this record
conflicts with one of them, the earlier statement is invalid as a description
of current behavior and this record is authoritative.

## Context

Every OIDC and federation frontend derived its token-sealing key from the
same master secret (`TokenCodec::new(&bx.secret)`), and the DPoP nonce HMAC
key was derived from that secret with a fixed domain-separation label. Two
frontends sharing the deployment secret therefore shared identical keys: an
authorization code or access token sealed by one frontend could be opened by
another, and a DPoP nonce issued by one was accepted by another. The frontend
instance name is part of every token's routing and audience context, so a
token that escapes its own frontend is outside its intended trust boundary.

## Decision

- The master secret is scoped to the frontend instance before key derivation:
  the sealing key is derived from `<secret>:<frontend-name>` (via the
  `scoped_secret` helper), for both the current secret and every
  `previous_secrets` entry used during rotation.
- The DPoP nonce HMAC key is derived with the frontend instance name mixed
  into the domain-separation label
  (`tunnelbana-dpop-nonce-v1:<frontend-name>`).
- Tokens sealed before this change do not open after upgrade; in-flight
  login flows spanning the upgrade must be restarted.

## Security boundaries

| Threat | Control | Residual risk |
|--------|---------|---------------|
| Cross-frontend token replay | Per-instance sealing key mixed with the frontend name | All frontends still share the master secret; its compromise covers every instance |
| Cross-frontend DPoP nonce acceptance | Per-instance nonce HMAC key | Same master-secret residual as above |

## Consequences

**Positive**

- A token or nonce that leaves its own frontend is cryptographically
  unusable in any other frontend of the same deployment.

**Negative / migration requirements**

- The sealing key change invalidates outstanding codes/tokens at upgrade;
  users restart their login flow.

## References

- `crates/tunnelbana-plugins/src/{keyload,oidc_frontend,federation_frontend,dpop}.rs`
- ADR 0002 (OIDC token codec), ADR 0033 (fail-closed security boundaries).
