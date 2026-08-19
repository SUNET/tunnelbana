# ADR 0051 - Sanitized rejection output in the SAML2 frontend

- **Status:** Accepted
- **Date:** 2026-08-05
- **Component:** `tunnelbana-plugins` SAML2 frontend.

## Context

Several rejection paths in `handle_sso` handled attacker-controlled strings
— the AuthnRequest issuer (SP entity id) and the requested NameID format —
unsafely:

- They were logged with plain `{}` formatting. An entity id containing
  newlines forges additional log lines, polluting audit trails and log
  alerts.
- The unknown-SP 403 body and the signature-rejection 403 body reflected
  request-derived content to an unauthenticated client.

## Decision

- Attacker-controlled values are logged debug-escaped (`{:?}`), so control
  characters cannot forge log lines.
- Client-facing 403 bodies are static text (`"unknown SP"`,
  `"AuthnRequest signature verification failed"`); the detailed reason
  stays in the (escaped) log. The SAML-level `InvalidNameIDPolicy` error
  posted to the *metadata-validated* ACS is unchanged — it is XML-escaped
  by the serializer and delivered only to the requesting SP itself.

## Security boundaries

| Threat | Control | Residual risk |
|--------|---------|---------------|
| Log forging via newline-laden entity ids / NameID formats | Debug-escaped log fields | None |
| Reflection of attacker input to unauthenticated clients | Static 403 bodies | None |

## Consequences

**Positive**

- Log integrity is preserved and unauthenticated clients receive no
  reflected input.

**Negative / migration requirements**

- Operators debugging unknown-SP rejections must read the SP entity id
  from the proxy log (quoted/escaped), not from the HTTP response body.

## References

- `crates/tunnelbana-plugins/src/saml2_frontend.rs` (`handle_sso`).
- ADR 0006 (registered SP metadata store), ADR 0033 (fail-closed security
  boundaries).
