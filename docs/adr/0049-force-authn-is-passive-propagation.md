# ADR 0049 - Propagating ForceAuthn/IsPassive through the proxy

- **Status:** Accepted
- **Date:** 2026-08-05
- **Component:** `tunnelbana-core` (`InternalData`), `tunnelbana-plugins`
  SAML2 frontend, SAML2 backend, OIDC backend, federation backend.

## Context

The SAML2 frontend parsed `ForceAuthn` and `IsPassive` from the inbound
AuthnRequest and then dropped them: the downstream SP's demand for fresh
authentication (or for no user interaction) never reached the upstream IdP.
Silently dropping an authentication constraint is a security-relevant
behavior change the requester cannot detect.

## Decision

- `InternalData` carries `force_authn` / `is_passive` booleans (request
  path only; both default to `false`).
- The SAML2 frontend populates them from the validated AuthnRequest.
- The SAML2 backend forwards them as `ForceAuthn`/`IsPassive` on the
  outgoing AuthnRequest. The flags ride the flow state so the
  discovery-service return leg forwards them too; when IdP discovery would
  require user interaction, an `IsPassive` request fails instead of
  silently dropping the constraint.
- The OIDC backend maps `force_authn` → `prompt=login` and `is_passive` →
  `prompt=none`. Both set is contradictory (`prompt` cannot be `login` and
  `none` at once) and is rejected with an error.
- The federation backend has no channel for the constraint (signed request
  object + discovery round-trip); it returns an error rather than ignoring
  the flags.

The rule: a backend that cannot honor the constraint must fail, never
silently drop it.

## Security boundaries

| Threat | Control | Residual risk |
|--------|---------|---------------|
| SP-mandated reauthentication silently weakened by the proxy | End-to-end forwarding, or fail-closed where forwarding is impossible | An upstream IdP/OP may itself ignore ForceAuthn/prompt; that is outside the proxy's control |

## Consequences

**Positive**

- `ForceAuthn`/`IsPassive` semantics survive the proxy hop; deployments
  relying on step-up authentication get the behavior the SP asked for.

**Negative / migration requirements**

- Flows pinned to the federation backend now fail when the SP sets
  `ForceAuthn`/`IsPassive` instead of proceeding without the constraint.

## References

- `crates/tunnelbana-core/src/internal.rs`
- `crates/tunnelbana-plugins/src/saml2_frontend.rs` (`handle_sso`)
- `crates/tunnelbana-plugins/src/saml2_backend.rs` (`start_auth`,
  `build_authn_redirect`)
- `crates/tunnelbana-plugins/src/oidc_backend.rs` (`start_auth`)
- `crates/tunnelbana-plugins/src/federation_backend.rs` (`start_auth`)
