# ADR 0002 — Stateless OIDC token codec (authorization codes & access tokens)

- **Status:** Accepted
- **Date:** 2026-06-08
- **Component:** `tunnelbana-oidc` — `tokens.rs` (`TokenCodec`, `AuthCodePayload`,
  `AccessTokenPayload`); wiring via `tunnelbana-core` `BuildContext` and the
  `oidc` / `oidc_federation` frontends.
- **Related:** [ADR 0001 — State cookie](0001-state-cookie-encryption.md),
  [ADR 0003 — DPoP](0003-dpop-sender-constrained-tokens.md),
  [ADR 0004 — client_credentials grant](0004-client-credentials-grant.md)

## Context

When tunnelbana acts as an **OpenID Provider** (the `oidc` and `oidc_federation`
frontends), it issues two artefacts to relying parties:

- an **authorization code** at the end of the authn flow, redeemed at the token
  endpoint, and
- an **access token**, presented as a bearer credential at the userinfo endpoint.

Per the project's stateless invariant (`CLAUDE.md`: "OIDC tokens are stateless …
the token/userinfo endpoints must not do server lookups"), these cannot reference a
server-side record. They must be **self-contained**: carry their own subject, client
binding, released claims, and expiry, so any worker can validate them with no shared
store.

These artefacts cross a trust boundary in the opposite direction from the state cookie:
they are handed to a **relying party / client**, which must be able to *present* them
but must not be able to *read or forge* them. An authorization code in particular
travels through the user agent (a front-channel redirect) and must stay confidential
and unforgeable end-to-end.

## Decision

Seal both artefacts with the same AEAD discipline as the state cookie, via a dedicated
`TokenCodec`, with a key **cryptographically separated** from the cookie key.

### Cryptographic construction

- **JWE compact, `dir` + `A256GCM`** — identical primitive and rationale as ADR 0001
  (AEAD confidentiality + integrity, fresh random nonce per seal).
- **Key derivation via HKDF-SHA256 with distinct salt/info:**
  `HKDF(salt = "tunnelbana-oidc-token-v1", ikm = secret, info = "…oidc token seal…")`.
  The salt/info differ from the cookie's, so although the same configured
  `state_encryption_key` is the input keying material, the **derived token key is
  independent** of the cookie key. A break or analysis of one does not yield the other.
- The 32-byte minimum on `state_encryption_key` (enforced in `config.rs`, see ADR 0001)
  protects this key too.

### Freshness

- Freshness lives **in the payload**, not in an envelope: `AuthCodePayload` and
  `AccessTokenPayload` both carry `exp`. `open_code` / `open_access_token` reject an
  expired artefact after decryption.
- Lifetimes are configured per deployment via `TokenLifetimes` (codes are
  short-lived; access tokens longer). Keeping the code lifetime short is the primary
  mitigation for the replay boundary noted below.

### Substitution and rotation

- **Algorithm pinning:** `open` uses `decrypt_with_options([dir], [A256GCM])`, rejecting
  any other `alg`/`enc` before key use.
- **Key rotation:** like the sealer, `TokenCodec` holds an ordered key list — seals with
  the primary, tries all on open. Previous secrets are supplied through
  `TokenCodec::with_previous_secrets`, fed from `BuildContext.previous_secrets`, which
  carries `previous_state_encryption_keys`. Rotating the secret therefore does **not**
  invalidate codes/tokens already in flight.

### Failure handling

- `open` returns a typed error (`Error::Authn` / `Error::Crypto`) that propagates up to
  the OAuth endpoint and is surfaced as a protocol error — failures are **not** silently
  turned into an "empty" credential (contrast the cookie, where an empty session is the
  safe default). A credential either authenticates as exactly what was sealed, or it is
  rejected.

## Security boundaries

**Trust model.** The server-held, token-specific key is the root of trust. The RP/client
is given an **opaque** artefact: it can transport and present it but cannot read its
claims or mint a new one. The userinfo and token endpoints re-establish all trust by
AEAD-decrypting under the server key — no database, no introspection lookup.

| Threat | Control | Residual risk |
|--------|---------|---------------|
| Client forging a code/token (e.g. escalating `scope`, swapping `sub`) | AEAD under a server-only key | None without the key |
| Client/RP reading released claims out of a code | Encryption (codes are confidential, not just signed) | None without the key |
| Use after expiry | `exp` in payload, checked on open | — |
| Algorithm substitution | `alg`/`enc` pinned to `dir`+`A256GCM` | — |
| Code injection / cross-client code use | `client_id` + `redirect_uri` + **PKCE** (`code_challenge`) sealed into the code and verified at redemption | Relies on the client correctly using PKCE |
| Offline brute-force of the secret | HKDF-SHA256 + 32-byte minimum, key domain-separated from the cookie | Operator's secret-entropy responsibility |
| Mass invalidation on key change | Multi-key rotation via `previous_state_encryption_keys` | — |
| Cross-key confusion (cookie key ↔ token key) | Distinct HKDF salt/info derive independent keys | — |

**Inherent boundaries of the stateless design (documented, accepted):**

- **Bearer semantics for access tokens.** Anyone in possession of the token string can
  use it until `exp`. This is standard OAuth bearer behaviour; confidentiality in
  transit is TLS's job.
- **No server-side single-use enforcement for authorization codes.** A stateless code
  has no "already redeemed" marker, so within its (short) lifetime a code could be
  presented more than once. This is mitigated by (a) a deliberately short code TTL and
  (b) PKCE binding the code to the client that started the flow — but true one-time-use
  would require a server-side seen-code cache, which the stateless design forgoes.
  Operators needing strict single-use must add that store.
- **No instant revocation.** As with the cookie, statelessness trades away per-credential
  revocation; expiry (and key rotation for a blanket reset) are the only levers.

**Out of scope (assumed elsewhere):** TLS for transport; key custody for
`state_encryption_key`; client-side compromise of the RP.

## Consequences

**Positive**

- Token and userinfo endpoints need no shared store — fully horizontally scalable.
- Codes are confidential *and* unforgeable; claims never leak to the client.
- Token key is independent of the cookie key despite a single configured secret.
- Algorithm pinning and zero-downtime key rotation, consistent with ADR 0001.

**Negative / accepted trade-offs**

- No server-side single-use codes or revocation without reintroducing state; safety
  rests on short lifetimes + PKCE.
- Sharing one configured secret across cookie and token keys is convenient but means a
  single secret to protect; mitigated by HKDF domain separation.

## References

- `crates/tunnelbana-oidc/src/tokens.rs` — `TokenCodec`, `derive_key`, payloads
- `crates/tunnelbana-core/src/plugin.rs` — `BuildContext.previous_secrets`
- `crates/tunnelbana-plugins/src/{oidc_frontend,federation_frontend}.rs` — codec wiring
- RFC 7516 (JWE), RFC 5869 (HKDF), RFC 6749 §4.1 (authorization code), RFC 7636 (PKCE)
