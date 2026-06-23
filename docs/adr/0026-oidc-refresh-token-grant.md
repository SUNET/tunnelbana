# ADR 0026 - OIDC `refresh_token` grant (stateless, rotated)

- **Status:** Accepted
- **Date:** 2026-06-23
- **Component:** `grindvakt` - `provider.rs` (token endpoint), `tokens.rs`
  (`RefreshTokenPayload`, `TokenCodec`); surfaced by the `oidc` and
  `oidc_federation` frontends in `tunnelbana-plugins`.
- **Related:** the OIDC OP token model (stateless codes/access tokens as JWE);
  [ADR 0024 - OpenID Federation backend](0024-openid-federation-backend.md).

## Context

The OP previously supported only the `authorization_code` and
`client_credentials` grants. Long-lived RP sessions need an OAuth2
`refresh_token` (RFC 6749 §6) so a client can obtain a fresh access token (and
id_token) without bouncing the user through the authorization endpoint again.

The OP is **stateless by design**: authorization codes and access tokens are
self-contained JWE tokens sealed under a key derived from the OP secret, and
neither the token nor the userinfo endpoint consults a server-side store. A
refresh token has to fit that model - which rules out the usual server-side
refresh-token store (and therefore server-side revocation and reuse detection).

## Decision

Add a `refresh_token` grant carried by a new stateless token type:

- **`RefreshTokenPayload`** is a JWE sealed by `TokenCodec`, exactly like codes
  and access tokens. It carries `client_id`, `sub`, granted `scope`, released
  `claims`, and the original `auth_time`/`nonce`/`acr`, plus its own `exp`.
- **Issuance**: the authorization-code exchange returns a refresh token **only**
  when the client is registered with `refresh_token` in `grant_types`
  (opt-in per client). The token endpoint also handles
  `grant_type=refresh_token`.
- **Refresh**: authenticate the client, open the refresh token, require it was
  issued to that same client, allow the requested `scope` to be **narrowed**
  (subset of the original grant) but never widened, then mint a new access token
  and id_token. The refreshed id_token replays the original `auth_time`,
  `nonce` and `acr` so it stays faithful to the initial authentication
  (`build_id_token` now takes `auth_time` rather than stamping "now").
- **Rotation**: every refresh returns a new refresh token with a fresh `exp`
  (sliding window of `refresh_token_ttl`, default 30 days).
- **Token-type tagging**: each sealed token now carries a type discriminator
  (`code`/`at`/`rt`) verified on open, so a token of one kind cannot be replayed
  as another (e.g. a refresh token or code presented as an access token at
  userinfo). This also closes the pre-existing latent gap where an
  authorization code would deserialize as an access-token payload.
- DPoP binding applies to the access token minted on refresh, as for the code
  grant.

## Security boundaries

| Threat | Control | Residual risk |
|--------|---------|---------------|
| Refresh token replay as an access token (or vice versa) | Per-type tag sealed in and verified on open | - |
| Scope escalation on refresh | Requested scope intersected with the original grant; empty intersection is rejected | - |
| Refresh token used by the wrong client | `client_id` sealed in and matched against the authenticated client | A public client authenticates only by `client_id`; a leaked refresh token for a public client is usable until expiry |
| Stolen refresh token used indefinitely | Bounded `refresh_token_ttl`; rotation slides the window per use | **No server-side revocation or reuse detection** (stateless design): a leaked token stays valid until its `exp`; rotation does not detect a stolen-then-replayed token |
| Forged refresh for a client without the grant | `grant_type=refresh_token` rejected unless the client registers `refresh_token` | - |

## Consequences

**Positive**

- RPs get standards-compliant refresh without the OP holding session state; the
  OP stays horizontally scalable with no shared store.
- The type-tag hardening benefits all token kinds, not just refresh tokens.

**Negative / accepted trade-offs**

- No revocation before expiry and no reuse detection - inherent to statelessness.
  Operators who need hard revocation should keep `refresh_token_ttl` short or
  rotate the OP secret (which invalidates all outstanding tokens).
- **Token format change**: tokens sealed by grindvakt ≤ 0.3.x do not open under
  0.4.0 because of the type tag; codes/access tokens are short-lived, so only
  in-flight tokens across an upgrade are affected.

## References

The refresh-grant engine lives in the external [`grindvakt`](https://crates.io/crates/grindvakt)
crate (a crates.io dependency, not vendored in this repo):

- `grindvakt`, `src/provider.rs` - `handle_refresh_token`, refresh issuance in
  `handle_authorization_code`, `client_allows_refresh`
- `grindvakt`, `src/tokens.rs` - `RefreshTokenPayload`, type-tagged
  `seal`/`open`, `token_types_are_not_interchangeable` test
- `grindvakt`, `tests/op_flow.rs` - `refresh_token_grant_flow`,
  `refresh_token_denied_when_grant_not_registered`

In this repository:

- `crates/tunnelbana-plugins/tests/proxy_oidc_op.rs` -
  `oidc_op_refresh_token_flow_through_proxy`
- RFC 6749 §6 (Refreshing an Access Token)
