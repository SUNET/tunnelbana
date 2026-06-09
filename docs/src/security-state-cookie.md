# Security: the state cookie

A single login handshake spans several HTTP requests — the downstream authn
request, the upstream login, the upstream response, and the downstream response.
The proxy must carry per-flow state across them: the originating `requester`, the
target frontend/backend, SAML `relay_state` / `request_id`, and — most
sensitively — the OIDC `state`, `nonce`, and PKCE `code_verifier` that tunnelbana
holds as a relying party toward the upstream IdP.

tunnelbana keeps **no server-side session store**. All of that state lives in a
single cookie, so any worker can serve any request and the proxy scales
horizontally with nothing shared. That makes the cookie **attacker-reachable
data**: the client can read its bytes, replay it, drop it, or try to tamper with
it. Everything below is how the cookie is hardened against that.

> The design rationale and threat table are recorded in
> [ADR 0001 — Stateless encrypted state cookie](https://github.com/kushaldas/tunnelbana/blob/main/docs/adr/0001-state-cookie-encryption.md).
> This page is the operator-facing summary.

## Cryptographic construction

- **JWE compact, `dir` + `A256GCM`.** Direct 256-bit AES-GCM gives
  confidentiality **and** integrity/authenticity in one primitive. A fresh random
  96-bit nonce is generated per seal, so there is no nonce-reuse exposure in
  practice. The SATOSA original used LZMA + AES-256-**CBC with no MAC**, which is
  malleable and offers no integrity — tunnelbana replaces it with an AEAD scheme.
- **Key derivation via HKDF-SHA256**, not a bare hash:
  `HKDF(salt = "tunnelbana-state-cookie-v1", ikm = state_encryption_key,
  info = "…dir+A256GCM")` → a 32-byte key. The salt/info are fixed public
  constants that domain-separate this key from every other use of the same secret
  (e.g. the OIDC token codec).
- **Minimum secret strength enforced at config load.** `state_encryption_key`
  must be ≥ 32 bytes or the proxy refuses to start. HKDF does **not** stretch a
  weak passphrase, so this floor is what defends against offline brute-force —
  use 32+ bytes of high-entropy material.

## Freshness (bounded validity)

The sealed payload is an envelope `{ v, iat, data }`, not the bare state map. `v`
is a format version; `iat` is the issue time in Unix seconds.

On every unseal, state older than `state_cookie_max_age` (default **1800 s /
30 min**; `0` disables the check) is rejected and treated as a fresh, empty
session. The same value is emitted as the cookie `Max-Age`, so client and server
agree on the lifetime. This bounds the replay window on the single-use flow
secrets (`state`, `nonce`, `code_verifier`) the cookie carries.

## Algorithm pinning and key rotation

- **Algorithm pinning.** Unseal decrypts with an explicit allow-list
  (`[dir]` / `[A256GCM]`), rejecting any other `alg`/`enc` in the JWE header
  *before* touching key material — a standing defence against
  algorithm-substitution attacks.
- **Zero-downtime key rotation.** The sealer holds an ordered key list. It seals
  with the primary key and tries **every** key on unseal. To rotate, move the old
  secret into `previous_state_encryption_keys` and set the new one as
  `state_encryption_key`; cookies sealed under the old key keep decrypting until
  they expire, after which the old secret can be dropped.

```toml
# During a rotation window:
state_encryption_key           = "${TUNNELBANA_STATE_KEY_NEW}"
previous_state_encryption_keys = ["${TUNNELBANA_STATE_KEY_OLD}"]
```

## Transport / cookie hardening

- **`HttpOnly`** — no script access to the cookie.
- **`Secure`** (default on) — sent only over HTTPS.
- **`__Host-` prefix** — when `Secure` is on, the effective cookie name is given
  the `__Host-` prefix, so the **browser itself** enforces `Secure` + `Path=/` +
  no `Domain`. The prefix is dropped automatically when `cookie_secure = false`
  (local plain-HTTP testing), since the prefix requires `Secure`.
- **`SameSite`** — configurable via `cookie_same_site`; defaults to `None` so the
  cross-site SSO POST-back works. See the CSRF note below.
- **Size guard.** If the `name=value` pair would exceed 4096 bytes (the browser's
  per-cookie limit), `seal` returns a hard error instead of letting the client
  silently drop an oversized cookie. Plugins must keep what they stash in the
  flow small.

## Fail-closed behaviour and observability

Any failure — a missing cookie, decryption failing under all keys, a bad
envelope, an unrecognised version, or expiry — yields an **empty, unauthenticated**
state, never a partially-trusted one. Plaintext is never logged. Failures are
surfaced at two levels:

- `warn` when a present cookie decrypts under no key — a genuine anomaly:
  tampering, a foreign cookie, or a key-rotation gap.
- `debug` for benign expiry or a bad envelope.

## Trust model and residual risks

The server-held `state_encryption_key` is the **single root of trust**. The
cookie itself is untrusted, attacker-reachable ciphertext; everything the proxy
trusts about a session is re-derived by successfully AEAD-decrypting the cookie
under a key only the server holds.

| Threat | Control | Residual risk |
|--------|---------|---------------|
| Tampering / forging session state | AEAD (`A256GCM`) under a server-only key | None without the key |
| Reading flow secrets (PKCE verifier, `state`, `nonce`) | Encryption | None without the key |
| Unbounded replay of a captured cookie | `iat` + TTL + `Max-Age` | A **valid, unexpired** cookie is replayable within the TTL — stateless by design means no server-side revocation |
| Offline brute-force of a weak secret | HKDF-SHA256 + 32-byte minimum | A truly low-entropy 32-byte secret is still the operator's responsibility |
| Algorithm substitution | `alg`/`enc` allow-list pinned to `dir`+`A256GCM` | None for this construction |
| Cross-site / script exfiltration | `HttpOnly`, `Secure`, `__Host-`, `SameSite` | `SameSite=None` (needed for SSO) means CSRF protection rests on the per-flow `state`/`nonce`, not the cookie |
| Silent oversize-cookie loss | 4096-byte `name=value` guard → hard error | — |
| Mass session loss on key change | Multi-key rotation via `previous_state_encryption_keys` | — |

### Out of scope (handled elsewhere)

- **Transport security** is TLS's job. The cookie scheme does not defend a
  plaintext-HTTP deployment — and `Secure`/`__Host-` will not be sent over http
  anyway.
- **A compromised client** (malware, a fully XSS-controlled origin) is out of
  scope; `HttpOnly` raises the bar but cannot defeat code running as the user.
- **Key custody.** Compromise of `state_encryption_key` is total compromise
  (decrypt and forge all state). The strength floor and rotation support mitigate
  it, but storing the secret (env var / secret manager) is an operational
  responsibility — keep it out of the config file with `${ENV}` interpolation.

## Operator checklist

- Generate `state_encryption_key` from a CSPRNG with **≥ 32 bytes** of entropy
  and inject it via `${ENV}`, never inline in `proxy.toml`.
- Leave `cookie_secure = true` in production; only set `false` for local
  plain-HTTP testing.
- Terminate TLS in front of the proxy; the cookie hardening assumes HTTPS.
- Keep `state_cookie_max_age` as short as your flows tolerate — it is the only
  replay/revocation lever short of rotating the key.
- Rotate the key periodically using `previous_state_encryption_keys`, and remove
  the old secret once `state_cookie_max_age` has elapsed since the switch.
