# ADR 0048 - Issuer-scoped subject identifiers in MDQ federation mode

- **Status:** Accepted
- **Date:** 2026-08-05
- **Component:** `tunnelbana-plugins` SAML2 backend (MDQ / dynamic IdP selection).
- **Supersedes in part:** ADR 0005.

The listed ADR remains an immutable historical record. Where this record
conflicts with it, the earlier statement is invalid as a description of
current behavior and this record is authoritative.

## Context

In MDQ mode any federation IdP may authenticate the user. ADR 0005 scoped
the *persistent NameID fallback* by issuer (`{len}:{issuer}:{id}`), because
a raw NameID is only stable within the IdP that issued it. Two paths
escaped that scoping:

- `compose_subject_id` (subject built from `user_id_from_attrs`) was
  returned verbatim. An attribute-composed identifier is still
  IdP-asserted: a malicious federation IdP could assert attributes that
  compose to a victim's subject id at another IdP.
- A transient NameID fallback was returned unscoped for the same reason.

## Decision

Issuer scoping of **every** subject identifier derived from the assertion —
composed from attributes or a raw persistent/transient NameID — is available
in dynamic IdP-selection mode via the backend config option
`scope_subject_id_by_issuer = true`. Static (single-IdP) mode is unchanged:
the raw NameID is kept.

The default is `false`, which preserves SATOSA-compatible behavior: composed
identifiers are used unscoped (SATOSA's `base.py` composes
`user_id_from_attrs` without any issuer scoping) and only raw persistent
NameIDs remain issuer-scoped (ADR 0005). The scoping is opt-in because
SATOSA accepts the cross-IdP assertion risk federation-wide, and existing
SATOSA-migrated deployments hold account links keyed on unscoped values.

## Security boundaries

| Threat | Control | Residual risk |
|--------|---------|---------------|
| A federation IdP asserts a victim's subject id (composed or NameID) | `scope_subject_id_by_issuer = true` makes subjects from different IdPs distinct | With the SATOSA-compatible default (`false`), composed identifiers remain forgeable across federation IdPs; enabling the option changes subject values, so stored account links must be migrated first |

## Consequences

**Positive**

- Operators who key downstream accounts on `subject_id` can close cross-IdP
  subject impersonation for all subject-selection paths by opting in.
- Upgrades are non-breaking by default: existing MDQ deployments keep their
  current subject values.

**Negative / migration requirements**

- The cross-IdP impersonation gap remains open until the operator opts in.
- Enabling the option changes composed and transient subjects in MDQ mode
  (`{len}:{issuer}:{id}` framing). Stored account links keyed on the old
  values must be migrated before enabling it.

## References

- `crates/tunnelbana-plugins/src/saml2_backend.rs` (`select_subject_id`,
  `scope_subject_id`).
- ADR 0005 (MDQ-backed dynamic IdP metadata), ADR 0035 (framing precedent).
