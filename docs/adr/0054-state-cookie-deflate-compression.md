# ADR 0054 - Deflate compression inside the sealed state cookie

- **Status:** Accepted
- **Date:** 2026-09-01
- **Component:** `tunnelbana-core` - `state.rs` (`StateSealer::seal` /
  `unseal`, plaintext format tag).
- **Related:** [ADR 0001 - state cookie encryption](0001-state-cookie-encryption.md),
  [ADR 0033 - security audit hardening](0033-security-audit-hardening.md),
  [ADR 0053 - disco_to_target_issuer and flow-resuming endpoints](0053-disco-to-target-issuer-flow-resume.md).

## Context

All per-flow state rides one encrypted cookie, hard-capped at 4096 bytes by
the browser's per-cookie limit (`seal` fails loudly beyond it, per ADR 0033).
The budget is real: `disco_to_target_issuer` (ADR 0053) snapshots a whole
in-flight request into the cookie and had to cap the snapshot at 2 KB, and an
OIDC authorization request plus SAML relay state plus a discovery snapshot
approach the limit together. The state JSON is highly redundant - repeated
namespace keys and long, similar URLs - so it compresses well: representative
payloads shrink 40-60% under deflate. SATOSA's original state cookie was
LZMA-compressed before encryption; tunnelbana's replacement scheme (JWE `dir`
+ `A256GCM`, ADR 0001) dropped compression along with the unauthenticated
AES-CBC construction.

The obvious mechanism - the JWE `zip: DEF` header - is unavailable by design:
grindvakt rejects JWEs carrying `zip` (0.3.0 hardening), because for tokens
crossing trust boundaries an attacker-supplied compressed payload is a
decompression-bomb and oracle vector. That rejection is correct and stays.

## Decision

Compress **inside** the seal, invisible to the JWE layer and to all callers:

- `seal` serializes the envelope `{v, iat, data}` to JSON, deflates it
  (`flate2`, default level), and prefixes one format-tag byte (`0x02`) before
  encrypting. The JWE construction, key derivation, freshness envelope, and
  4096-byte `name=value` guard are unchanged - the guard simply now measures
  the compressed token.
- `unseal` dispatches on the first decrypted plaintext byte: `{` is a legacy
  bare-JSON envelope (cookies sealed before this change keep unsealing across
  a deploy with no flag day); `0x02` is inflated then parsed; anything else is
  treated like a bad envelope - an empty, unauthenticated state.
- Inflation is capped at **64 KB**. This is defense in depth, not a
  load-bearing control: A256GCM authenticates the ciphertext *before*
  decompression, so only bytes this proxy sealed itself ever reach the
  decompressor, and the cookie transport already caps the compressed input at
  ~4 KB. An over-cap inflation is dropped as a bad envelope, never buffered
  without bound.
- The `disco_to_target_issuer` 2 KB snapshot cap still measures the
  *uncompressed* snapshot JSON. It becomes conservative rather than wrong,
  and stays a simple, deterministic pre-redirect check (its purpose is
  failing *before* the browser leaves for the discovery page, not accounting
  for the exact sealed size).

## Security boundaries

| Threat | Control | Residual risk |
|--------|---------|---------------|
| Decompression bomb / malformed compressed data | AEAD authentication runs before inflation, so the decompressor only ever sees self-sealed plaintext; a 64 KB inflation cap and fail-closed handling (empty state) cover corruption and the proxy's own oversized seals | - |
| Ciphertext length leaking plaintext structure (CRIME/BREACH class) | Compression happens before encryption, so ciphertext length now reflects plaintext redundancy. The cookie holds a single user's own flow data; the party that can observe its length (the user's client) is the data subject, and cross-user secrets are never co-resident with attacker-chosen input in one cookie | A network observer can distinguish "bigger vs smaller state" across requests; accepted - the same observer already sees request sizes, and SATOSA has shipped compressed state cookies with this property since inception |
| Downgrade to the uncompressed legacy format | The format tag is inside the AEAD plaintext; an attacker cannot flip it without the key. Legacy `{` parsing accepts only what old proxies genuinely sealed | Legacy parsing can be removed once no pre-0.4.0 cookie can be alive (one `state_cookie_max_age` after deploy) |
| Algorithm-substitution via JWE `zip` | Unchanged: grindvakt rejects `zip` in JWE headers; compression is invisible to the JWE layer | - |

## Consequences

**Positive**

- 40-60% smaller sealed cookies on representative state; the effective
  headroom under the 4096-byte browser cap roughly doubles. Flows that
  previously tripped the seal guard (stacked snapshots, attribute-heavy
  authorization requests) now fit.
- No API, config, or wire-visible change: same JWE `dir`+`A256GCM` token,
  same cookie attributes, zero-downtime rollout (old cookies unseal via the
  legacy path until they expire).

**Negative / accepted trade-offs**

- `tunnelbana-core` gains a `flate2` dependency (already in the workspace via
  `tunnelbana-plugins`).
- Sealed size is no longer a linear function of state size, so "will it fit"
  is less predictable for operators; the seal-failure error (ADR 0053's
  fail-the-request behavior) remains the safety net.
- The CRIME-class length side channel documented above.

## References

- `crates/tunnelbana-core/src/state.rs` - implementation +
  legacy/round-trip/inflation-cap tests
- `docs/src/security-state-cookie.md` - operator-facing summary
- grindvakt 0.7 changelog - JWE `zip` rejection this deliberately routes
  around
- `../SATOSA/src/satosa/state.py` - the LZMA-compressed original
