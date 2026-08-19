# ADR 0050 - Fail-closed `security` preset in the SAML2 backend

- **Status:** Accepted
- **Date:** 2026-08-05
- **Component:** `tunnelbana-plugins` SAML2 backend configuration.

## Context

The `security` config value selected the validation preset with
`strict = (security == Some("strict"))`: any unrecognized value — a typo
such as `"strick"` — silently selected the *permissive* preset, the weaker
of the two. Misconfiguration thereby downgraded SAML response validation
without any signal to the operator.

## Decision

The value is matched explicitly at build time: `"strict"` and
`"permissive"` (both case-insensitive, absent = permissive as before) are
accepted; anything else is an `Error::Config` and the backend refuses to
build.

## Security boundaries

| Threat | Control | Residual risk |
|--------|---------|---------------|
| Typo'd `security` value silently weakens validation | Fail closed at startup with a config error | None |

## Consequences

**Positive**

- Validation strength is always the one the operator named; mistakes
  surface at startup, not after an incident.

**Negative / migration requirements**

- A deployment running with an invalid `security` value (previously
  ignored) now fails to start until the value is corrected.

## References

- `crates/tunnelbana-plugins/src/saml2_backend.rs` (`Saml2Backend::build`).
- ADR 0033 (fail-closed security boundaries).
