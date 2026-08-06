# ADR 0037 - Configuration, state-cookie, and HTTP-client hardening

- **Status:** Accepted
- **Date:** 2026-08-05
- **Component:** `tunnelbana-core` (configuration, proxy error handling, TTL
  cache, state cookie) and the `tunnelbana` binary (outbound HTTP client).
- **Supersedes in part:** ADR 0033.

The listed ADR remains an immutable historical record. Where this record
conflicts with it, the earlier statement is invalid as a description of
current behavior and this record is authoritative.

## Context

A follow-up audit pass over the core crate and the binary found a second
group of confirmed weaknesses that ADR 0033 did not cover:

- `${ENV}` interpolation silently replaced an unset variable with the empty
  string, so a missing environment variable could turn a configured secret
  (or any other value) into an empty string without any error.
- TOML parse errors echoed the post-interpolation source snippet — which can
  contain plaintext secrets — into the error message and from there into
  logs.
- A state-cookie seal failure was silently dropped, and the proxy returned
  the full internal error text to unauthenticated clients.
- TTL-cache expiry arithmetic (`now + ttl`) could overflow on a
  configuration-supplied TTL.
- A state-cookie `iat` in the future was clamped to age 0, so a forged
  timestamp could extend a cookie's effective lifetime indefinitely.
- `cookie_same_site` accepted any string, emitting an invalid `SameSite`
  attribute instead of failing at startup.
- The outbound reqwest client followed redirects without restriction, so a
  307/308 from a token endpoint would re-send the POST form body —
  `client_secret` and authorization code included — to a cross-origin
  target.

## Decision

- `interpolate_env` returns `Result`. An unset referenced variable aborts
  configuration loading with an error naming the variable. This applies to
  the main config file and to plugin `include` files.
- TOML parse errors keep the parser's message and line/column but never
  include the source snippet.
- A state-cookie seal failure is logged with `tracing::error!`; the response
  is still delivered without the cookie.
- Unhandled request errors return a generic `request failed` body to the
  client. The internal error text stays in the server log.
- TTL-cache expiry uses saturating arithmetic.
- A state cookie whose `iat` is more than 60 seconds ahead of the local
  clock is rejected (treated as a fresh session) instead of having its age
  clamped to zero.
- `cookie_same_site` is validated at configuration load against `None`,
  `Lax`, and `Strict` (case-insensitive); any other value is rejected.
- The reqwest client uses `redirect::Policy::none()`. A 3xx response
  surfaces to the caller as its status code, and the existing call sites
  already treat non-200 statuses as errors.

## Security boundaries

| Threat | Control | Residual risk |
|--------|---------|---------------|
| Missing environment variable silently empties a secret | Fail configuration load, naming the unset variable | None beyond the operator reading the error |
| Secret leakage through parse-error snippets | Snippet stripped; message and line/column retained | A secret that is itself the parse error's subject may appear in the parser's message fragment |
| Cross-origin credential replay via redirect | Redirects never followed; 3xx surfaces as an error status | Endpoints that legitimately redirect must be configured with their final URL |
| Cookie lifetime extension via forged `iat` | Future `iat` beyond a 60-second skew rejected | A skewed client clock within 60 seconds is accepted |
| Internal error detail disclosure to clients | Generic client body; details only in trusted logs | Log access remains a sensitive privilege |

## Consequences

**Positive**

- Configuration mistakes fail fast with actionable messages instead of
  degrading secrets or cookie attributes silently.
- Error paths no longer disclose source snippets or internal error text.
- The outbound HTTP client cannot be turned into a credential-relaying
  redirect follower.

**Negative / migration requirements**

- Configurations that previously relied on an unset `${VAR}` expanding to
  the empty string must now set the variable explicitly.
- An invalid `cookie_same_site` value now aborts startup instead of being
  passed through to the cookie header.

## References

- `CHANGELOG.md` - 0.3.0 operator-facing release summary.
- `crates/tunnelbana-core/src/{config,proxy,cache,state}.rs`
- `crates/tunnelbana/src/reqwest_client.rs`
