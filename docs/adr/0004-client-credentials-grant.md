# ADR 0004 — `client_credentials` grant

- **Status:** Accepted
- **Date:** 2026-06-09
- **Component:** `tunnelbana-oidc` — `provider.rs`
  (`handle_token_request` dispatch, `handle_client_credentials`),
  `metadata.rs` (`grant_types_supported`).
- **Related:** [ADR 0002 — OIDC token codec](0002-oidc-token-codec.md),
  [ADR 0003 — DPoP](0003-dpop-sender-constrained-tokens.md)

## Context

The OP previously served only the `authorization_code` grant — every token presupposed
an end user who logged in. Service-to-service callers (a backend job, a federation
peer's service account) need a token with **no user** behind it: the OAuth 2.0
`client_credentials` grant (RFC 6749 §4.4). Adding it must not disturb the stateless
token design (ADR 0002) and must compose with DPoP (ADR 0003).

The grant is security-sensitive in one specific way: it authenticates **only the
client**, so the client authentication itself is the entire trust gate. RFC 6749 §4.4
restricts it to *confidential* clients — a public client has no secret to prove, so
admitting one would let anyone who knows the `client_id` mint tokens.

## Decision

Dispatch `grant_type=client_credentials` in `handle_token_request` to a dedicated
`handle_client_credentials` that reuses the existing client-authentication and
token-sealing machinery:

- **Confidential clients only.** After `authenticate_client`, a client whose
  `token_endpoint_auth_method` is `none` (public) is rejected with `invalid_client`,
  **independently of** its registered `grant_types`. This is the primary security
  decision of this ADR (differential-review finding DR-03): the check does not rely on
  registration hygiene.
- **Grant must be registered.** The client's `grant_types` must include
  `client_credentials`, else `invalid_grant`.
- **Scope = requested ∩ allowed.** The requested `scope` is intersected with the
  client's registered scope set (absent `scope` ⇒ the full registered set). An empty
  intersection is `invalid_scope`. A client can never obtain a scope it was not
  registered for — no escalation.
- **Subject is the client.** The sealed `AccessTokenPayload` sets both `sub` and
  `client_id` to the client; `claims` is empty. **No `id_token`** is issued — there is
  no end user and OIDC authentication semantics do not apply.
- **Token is sealed exactly as ADR 0002**, and **DPoP binding applies** (ADR 0003): a
  validated proof sets `cnf.jkt` and `token_type: DPoP`; otherwise `Bearer`.

Discovery advertises `client_credentials` in `grant_types_supported`.

## Security boundaries

| Threat | Control | Residual risk |
|--------|---------|---------------|
| Public client mints tokens with only a `client_id` | `token_endpoint_auth_method = none` rejected (`invalid_client`) | None |
| Client requests scopes beyond its grant | requested ∩ registered; empty ⇒ `invalid_scope` | None |
| Client forging / escalating the issued token | AEAD seal under server key (ADR 0002) | None without the key |
| Token theft / replay | bearer by default; opt-in DPoP sender-constraint (ADR 0003) | Standard bearer until DPoP enabled |
| Treating a service token as a user login | no `id_token`; `sub == client_id` | Consumer must not assume an end user |

**Out of scope (assumed elsewhere):** client-secret custody and strength; TLS for
transport; authorization decisions the resource server makes from the granted scopes.

## Consequences

**Positive**

- Service-to-service tokens with no user, fully stateless and horizontally scalable,
  reusing the ADR 0002 codec and ADR 0003 DPoP path unchanged.
- Confidential-client enforcement is structural, not dependent on careful registration.
- Scope intersection prevents privilege escalation by construction.

**Negative / accepted trade-offs**

- Inherits the bearer-token and no-instant-revocation boundaries of ADR 0002 (mitigated
  by short TTLs, and by DPoP when enabled).
- No per-client rate limiting on issuance in the protocol layer; an authenticated client
  may request tokens freely (deployment concern).

## References

- `crates/tunnelbana-oidc/src/provider.rs` — `handle_client_credentials`, dispatch,
  confidential-client check, scope intersection
- `crates/tunnelbana-oidc/src/metadata.rs` — `grant_types_supported`
- `crates/tunnelbana-oidc/tests/op_flow.rs` — `client_credentials_*` tests
- RFC 6749 §4.4 (client credentials grant), §2.1 (client types)
