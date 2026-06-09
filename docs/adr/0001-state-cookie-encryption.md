# ADR 0001 — Stateless encrypted state cookie

- **Status:** Accepted
- **Date:** 2026-06-08
- **Component:** `tunnelbana-core` — `state.rs` (`StateSealer`, `State`), `config.rs`
- **Related:** [ADR 0002 — OIDC token codec](0002-oidc-token-codec.md),
  `DIFFERENTIAL_REVIEW_STATE_COOKIE.md`

## Context

Tunnelbana is a SATOSA-style identity proxy. A single login handshake spans several
HTTP requests (frontend authn request → backend upstream login → backend response →
frontend response) and must carry per-flow state across them: the originating
`requester`, the target frontend/backend, SAML `relay_state` / `request_id`, and —
critically — the OIDC `state`, `nonce`, and PKCE `code_verifier` that the proxy holds
as an RP toward the upstream IdP.

We require this state to be **stateless**: no server-side session store, so any worker
can serve any request and the proxy scales horizontally with no shared backend. The
only place to keep the state is therefore the client, in a cookie. That cookie is
**attacker-reachable data** — the client can read its bytes, replay it, drop it, or
attempt to tamper with it. The SATOSA original used LZMA + AES-256-**CBC with no MAC**,
which is malleable and offers no integrity.

## Decision

Seal the per-flow state into a single encrypted cookie using an **AEAD** scheme, with
explicit freshness, key-rotation, and transport hardening. Concretely:

### Cryptographic construction

- **JWE compact, `dir` + `A256GCM`.** Direct 256-bit AES-GCM provides confidentiality
  **and** integrity/authenticity in one primitive. A fresh random 96-bit nonce is
  generated per seal (handled in `jose-rs`), so there is no nonce-reuse exposure in
  practice.
- **Key derivation via HKDF-SHA256**, not a bare hash:
  `HKDF(salt = "tunnelbana-state-cookie-v1", ikm = secret, info = "…dir+A256GCM")`
  → 32-byte key. The salt/info are fixed public constants that domain-separate this
  key from every other use of the same secret (see ADR 0002).
- **Minimum secret strength enforced at config load:** `state_encryption_key` must be
  ≥ 32 bytes (`config.rs::validate`). HKDF does not stretch a weak passphrase, so the
  floor is what defends against offline brute-force.

### Freshness (bounded validity)

- The sealed payload is an **envelope** `{ v, iat, data }`, not the bare map. `v` is a
  format version; `iat` is the issue time in Unix seconds.
- On `unseal`, state older than `state_cookie_max_age` (default **1800 s / 30 min**,
  `0` disables) is rejected and treated as a fresh session. The same value is emitted
  as the cookie `Max-Age`, so client and server agree on the lifetime.
- This bounds the replay window on the single-use flow secrets (`state`, `nonce`,
  `code_verifier`) that the cookie carries.

### Robustness against substitution and rotation

- **Algorithm pinning:** `unseal` uses `decrypt_with_options([dir], [A256GCM])`,
  rejecting any other `alg`/`enc` in the header *before* touching key material — a
  standing defence against algorithm-substitution attacks.
- **Key rotation:** `StateSealer` holds an ordered key list. It seals with the primary
  (`keys[0]`) and tries **every** key on `unseal`. Operators move the old secret into
  `previous_state_encryption_keys` when rotating, enabling zero-downtime rotation; the
  old key is dropped once all in-flight cookies have expired.

### Transport / cookie hardening

- `HttpOnly` (no script access), `Secure` (default on), `Path=/`, and `SameSite`
  (configurable; default `None` for cross-site SSO POST-back).
- When `Secure`, the cookie name carries the **`__Host-` prefix**, so the browser
  itself enforces `Secure` + `Path=/` + no `Domain`.
- **Size guard:** if the `name=value` pair would exceed 4096 bytes (the browser's
  per-cookie limit) `seal` returns an error rather than letting the client silently
  drop an oversized cookie.

### Fail-closed behaviour and observability

- Any failure — missing cookie, decryption failure under all keys, bad envelope,
  wrong version, or expiry — yields an **empty, unauthenticated** `State`, never a
  partially-trusted one.
- Failures are logged: `warn` when a present cookie decrypts under no key (a genuine
  anomaly: tampering, a foreign cookie, or a rotation gap); `debug` for benign expiry
  / bad-envelope. Plaintext is never logged.

## Security boundaries

**Trust model.** The server-held key is the single root of trust. The cookie itself is
untrusted, attacker-reachable ciphertext. Everything the proxy trusts about a session
is re-derived by successfully AEAD-decrypting the cookie under a key only the server
holds.

| Threat | Control | Residual risk |
|--------|---------|---------------|
| Tampering / forging session state | AEAD (`A256GCM`) under a server-only key | None without the key |
| Reading flow secrets (PKCE verifier, `state`, `nonce`) | Encryption | None without the key |
| Unbounded replay of a captured cookie | `iat` + TTL freshness check + `Max-Age` | A **valid, unexpired** cookie is replayable within the TTL — stateless by design means no server-side revocation |
| Offline brute-force of a weak secret | HKDF-SHA256 + 32-byte minimum | A truly low-entropy 32-byte secret is still the operator's responsibility |
| Algorithm substitution | `alg`/`enc` allow-list pinned to `dir`+`A256GCM` | None for this construction |
| Cross-site / script exfiltration | `HttpOnly`, `Secure`, `__Host-`, `SameSite` | `SameSite=None` (needed for SSO) means CSRF protection rests on the per-flow `state`/`nonce`, not the cookie |
| Silent oversize-cookie loss | 4096-byte `name=value` guard → hard error | — |
| Mass session loss on key change | Multi-key rotation via `previous_state_encryption_keys` | — |

**Explicitly out of scope (assumed handled elsewhere):**

- **Transport confidentiality/integrity** is provided by TLS. The cookie scheme does
  not defend a plaintext-HTTP deployment (and `Secure`/`__Host-` will not be sent over
  http anyway).
- **A compromised client** (malware, a fully XSS-controlled origin) is out of scope;
  `HttpOnly` raises the bar but cannot defeat code running as the user.
- **Key custody.** Compromise of `state_encryption_key` is total compromise (decrypt
  and forge all state). It is mitigated by the strength floor and rotation support, but
  storing the secret (env var / secret manager) is an operational responsibility.

## Consequences

**Positive**

- No server-side session store; horizontally scalable with no shared state.
- Integrity + confidentiality + bounded freshness for all per-flow secrets.
- Zero-downtime key rotation and a clean algorithm-agility story.
- Strong, hard-to-misconfigure defaults (`Secure` + `__Host-` + 30-min TTL + 32-byte
  key floor).

**Negative / accepted trade-offs**

- No per-session server-side revocation (inherent to statelessness); the TTL is the
  only revocation lever short of rotating the key.
- All flow state must fit in ~4 KB; plugins must keep what they stash small.
- `SameSite=None` is the default to support cross-site SSO, so CSRF defence is pushed
  to the per-flow `state`/`nonce` parameters.

## References

- `crates/tunnelbana-core/src/state.rs` — `StateSealer`, `Envelope`, `derive_key`
- `crates/tunnelbana-core/src/config.rs` — `state_encryption_key`,
  `previous_state_encryption_keys`, `cookie_*`, `state_cookie_max_age`, `validate`
- RFC 7516 (JWE), RFC 5869 (HKDF), RFC 6265bis (`__Host-`, `SameSite`)
