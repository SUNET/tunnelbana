# ADR 0003 — DPoP sender-constrained tokens (RFC 9449)

- **Status:** Accepted
- **Date:** 2026-06-09
- **Component:** `tunnelbana-oidc` — `dpop.rs` (`validate_proof`,
  `validate_resource_proof`, `ReplayStore`, stateless nonces), `provider.rs`
  (`cnf.jkt` binding + userinfo enforcement), `tokens.rs` (`AccessTokenPayload.cnf_jkt`);
  `tunnelbana-core` — `mac.rs` (HMAC/SHA-256/CT-eq), `cache.rs` (`put_if_absent`);
  `tunnelbana-plugins` — `dpop.rs` (`CacheReplayStore`, `DpopRuntime`, `DpopSettings`),
  `oidc_frontend.rs` (header validation, nonce challenge, scheme handling).
- **Related:** [ADR 0002 — OIDC token codec](0002-oidc-token-codec.md),
  [ADR 0004 — client_credentials grant](0004-client-credentials-grant.md)

## Context

ADR 0002 issues access tokens as opaque **bearer** credentials: anyone holding the
token string can use it at the userinfo endpoint until `exp`. That is standard OAuth,
but it makes a leaked token (via logs, a referrer header, browser history, an
intermediary proxy, or an XSS exfil) directly replayable. For deployments that want
theft-resistance without a server-side session store, RFC 9449 (**DPoP**) binds a
token to a key the client proves possession of on every request: the client signs a
short-lived **proof JWT** with a private key, the AS records the key's thumbprint as
the token's `cnf.jkt`, and the RS only honours the token when accompanied by a fresh
proof from the matching key.

Adopting DPoP here has to respect two standing invariants:

- **The `tunnelbana-oidc` crate is stateless and runtime-agnostic** (`CLAUDE.md`):
  no server lookups at token/userinfo, no actix, outbound HTTP injected. DPoP's one
  unavoidably stateful element — remembering proof `jti`s to stop replay — cannot live
  in the protocol crate.
- **The token/userinfo endpoints must not do server lookups.** The sender-constraint
  therefore has to travel *inside* the sealed token (`cnf.jkt`), readable back without
  a database, exactly as ADR 0002 does for `sub`/`scope`/`exp`.

DPoP is also a feature most deployments will not use, so it must be **off by default**
and add no surface (no discovery advertisement, no header parsing) until enabled.

## Decision

Implement DPoP as an **opt-in** capability whose protocol logic stays in the stateless
`tunnelbana-oidc` crate, with the single stateful concern (replay) pushed behind an
injected trait supplied by the deployment.

### Proof validation (token endpoint)

`validate_proof(store, config, proof, htm, htu)` performs, in order:

1. **Header shape** — `typ` MUST be `dpop+jwt`; `alg` MUST be `ES256`. Pinning `ES256`
   rejects `alg: none` and every symmetric (`HS*`) algorithm outright.
2. **Embedded key** — the protected header MUST carry the verifying public key as a
   `jwk`; a `jwk` containing private material (`d`/`oth`) is refused so a leaked private
   JWK cannot be smuggled in.
3. **Signature** — verified against that embedded key via
   `jose_rs::jws::compact::verify_with_jwk`, which re-derives the algorithm from the
   header, re-rejects `none`, and fails if the key type does not match the algorithm
   (algorithm-confusion safe — see the J-01/J-03 regressions in `jose-rs`).
4. **Request binding** — `htm` matched case-insensitively against the live request
  method; `htu` matched after stripping query/fragment only. A trailing slash
  remains significant, so a proof for `/token/` does not validate for `/token`.
5. **Freshness** — `iat` must be no more than `proof_max_age_secs` old and no more than
   a small skew (30 s) in the future.
6. **Nonce** — when `require_nonce` is set, a valid `DPoP-Nonce` must be present
   (below); otherwise the proof is challenged with `NonceRequired`.

The token's `cnf.jkt` is the RFC 7638 SHA-256 thumbprint of the embedded **public**
key, sealed into `AccessTokenPayload.cnf_jkt` by the codec from ADR 0002 and surfaced
to the client as `token_type: DPoP`.

### Resource binding (userinfo endpoint)

`validate_resource_proof(…, access_token)` does everything above **plus** the `ath`
binding (RFC 9449 §4.3): the proof must carry `base64url(SHA-256(access_token))`, so a
proof minted for one token cannot be presented with another. `Provider::userinfo` then
enforces the constraint (RFC 9449 §7.1):

- token carries `cnf.jkt` + proof key thumbprint **matches** → allowed;
- token carries `cnf.jkt` + thumbprint **mismatch** → `invalid_dpop_proof`;
- token carries `cnf.jkt` + **no proof** (plain `Bearer`) → `invalid_dpop_proof`.

The web layer accepts the token under either the `Bearer` or `DPoP` authorization
scheme; the scheme keyword is **not** load-bearing — possession is proven by the
signature + `ath` + `cnf.jkt` match, not by which keyword was used.

### Replay protection — injected, not in the stateless core

The `jti` seen-set is the only stateful element and is abstracted behind the
`ReplayStore` trait (`async fn record(jti, ttl) -> Result<bool>`). Recording **is** the
check: a `false` return (already present) is a replay. The protocol crate ships only
`NoReplayStore` (every `jti` fresh); the `tunnelbana` deployment supplies
`CacheReplayStore`, backed by the core `TtlCache` via a new **atomic
`put_if_absent`** (check-and-set under one write lock). The replay TTL equals
`proof_max_age_secs`, so the window a `jti` is remembered exactly covers the window a
proof is accepted — no replay gap.

`TtlCache` gained an amortised prune (a watermark-driven `retain` in `put_if_absent`)
because the replay key space is append-only random `jti`s that are never re-inserted;
without eviction the map would grow unbounded.

### Stateless DPoP nonces

`DPoP-Nonce` (RFC 9449 §8) is supported without a nonce store: a nonce is
`base64url( ts_be(8) || HMAC-SHA256(nonce_secret, ts)[..16] )`, validated by recomputing
the MAC (in constant time) and checking the embedded timestamp against
`nonce_lifetime_secs`. The `nonce_secret` is **domain-separated** —
`HMAC(deployment_secret, "tunnelbana-dpop-nonce-v1")` — never the token-signing or
sealing key, consistent with the key-separation discipline of ADR 0001/0002.

### Configuration

Off by default. Enabled per OIDC frontend under `[frontend.config.dpop]`
(`enabled`, `proof_max_age_secs`, `require_nonce`, `nonce_lifetime_secs`). Only when
enabled does discovery advertise `dpop_signing_alg_values_supported: ["ES256"]` and
does the token/userinfo path read the `DPoP` header.

## Security boundaries

**Trust model.** The client's proof key is the root of possession; the server-held
token key (ADR 0002) remains the root of token integrity. The AS binds the two by
sealing the proof key's thumbprint into the token. The RS re-establishes both with no
lookup: AEAD-decrypt the token for `cnf.jkt`, verify the proof against its embedded key,
match the two, and check `ath`.

| Threat | Control | Residual risk |
|--------|---------|---------------|
| Replay of a stolen **bound** token at userinfo as plain Bearer | `cnf.jkt` present ⇒ a matching proof is mandatory; bearer presentation rejected | None at this endpoint |
| Attacker captures token **and** a single proof together | Proof bound to `htm`/`htu`/`ath` and single-use via `jti` replay store | One use only, within `proof_max_age_secs`, on the same store (see below) |
| `alg: none` / algorithm confusion in the proof | `ES256` pinned + `jose-rs` header/alg/key-type binding | — |
| Private-key JWK smuggled in the header | `d`/private material rejected | — |
| Proof reused for a different token | `ath` = hash of the presented access token, checked at the RS | — |
| Proof minted for a different endpoint/method | `htm`/`htu` bound to the live request | — |
| Forged DPoP-Nonce | HMAC over timestamp, constant-time compare, domain-separated key | None without the nonce secret |
| Replay-store memory exhaustion | Amortised TTL prune in `TtlCache` | — |
| Replay-store lock poisoning | `put_if_absent` fails **closed** (treats key as present ⇒ rejects) and logs | DoS of DPoP until restart (accepted) |

**Inherent boundaries of the stateless design (documented, accepted):**

- **Per-process replay store.** `CacheReplayStore` is single-process. Behind multiple
  replicas a proof replayed against a *different* node is not detected, and stateless
  nonces do not close this. A horizontally-scaled DPoP deployment MUST front
  `ReplayStore` with a shared backend (e.g. Redis) or pin to a single instance; the
  runtime logs this caveat at startup.
- **`NoReplayStore` is not replay-safe on its own.** With `require_nonce = false` it
  permits replay within `proof_max_age_secs`. It exists only for embedders that supply
  their own freshness; the in-tree frontends always use `CacheReplayStore`.
- **Non-bound tokens are unchanged.** When DPoP is disabled (or no proof is sent), tokens
  remain bearer per ADR 0002 — DPoP adds constraint, it never weakens the baseline.

**Out of scope (assumed elsewhere):** TLS for transport; key custody for the deployment
secret; client-side compromise of the proof private key; `dpop_jkt` binding at the
authorization endpoint (RFC 9449 §10 code-injection hardening) — not implemented, the
token-endpoint proof is the only DPoP binding today.

## Consequences

**Positive**

- A leaked bound access token is useless without the proof key — the core DPoP
  guarantee — while the token/userinfo endpoints still do **no** server lookup.
- Protocol logic stays in the stateless, runtime-agnostic crate; the one stateful
  concern is injected, so the crate's invariants hold.
- Nonces and the sender-constraint are stateless (HMAC nonce; `cnf.jkt` in-token),
  preserving horizontal scalability for everything except the optional `jti` store.
- Off by default with zero added surface until enabled; key material domain-separated
  from cookie/token keys.

**Negative / accepted trade-offs**

- Cross-node replay protection requires a shared `ReplayStore` not shipped in-tree;
  single-instance or operator-supplied store until then.
- `ES256`-only (the wallet algorithm); other DPoP algorithms are a future extension.
- No `dpop_jkt` authorization-endpoint binding yet; the auth-code path is bound only at
  the token endpoint.

## References

- `crates/tunnelbana-oidc/src/dpop.rs` — proof + resource validation, nonces, `ReplayStore`
- `crates/tunnelbana-oidc/src/provider.rs` — `cnf.jkt` binding, `userinfo` enforcement
- `crates/tunnelbana-oidc/src/tokens.rs` — `AccessTokenPayload.cnf_jkt`
- `crates/tunnelbana-core/src/{mac,cache}.rs` — HMAC/SHA-256/CT-eq, `put_if_absent` + prune
- `crates/tunnelbana-plugins/src/dpop.rs` — `CacheReplayStore`, `DpopRuntime`, `DpopSettings`
- `crates/tunnelbana-plugins/src/oidc_frontend.rs` — header validation, nonce challenge
- RFC 9449 (DPoP), RFC 7638 (JWK thumbprint), RFC 7517 (JWK), RFC 5869 (HKDF)
