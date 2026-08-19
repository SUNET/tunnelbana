# ADR 0047 - Passthrough attributes must never collide with internal names

- **Status:** Accepted
- **Date:** 2026-08-05
- **Component:** `tunnelbana-plugins` SAML2 backend (`passthrough_unmapped_attributes`).
- **Supersedes in part:** ADR 0008.

The listed ADR remains an immutable historical record. Where this record
conflicts with it, the earlier statement is invalid as a description of
current behavior and this record is authoritative.

## Context

With `passthrough_unmapped_attributes` enabled, the SAML2 backend keeps
attributes the map does not know about under a lowercased
FriendlyName-or-Name key (ADR 0008). Two gaps let an upstream IdP smuggle
values into authoritative internal attributes:

- The known-attribute check compared the inbound `Name`/`FriendlyName`
  case-sensitively against the map's external names. An IdP asserting an
  attribute named `MAIL` (a case-variant of the mapped `mail`) was treated
  as *unknown*, keyed as `mail`, and merged into the mapped internal `mail`
  values.
- Nothing stopped a passthrough key from equalling an internal attribute
  name defined only for *another* profile (e.g. an openid-only internal
  attribute), letting a SAML IdP fabricate internal attributes the proxy
  later treats as authoritative — including the attributes composing the
  subject id.

## Decision

- The known-attribute check is case-insensitive: external names, OIDs, and
  friendly names from the map are compared lowercased.
- Before a passthrough value is merged, the attribute is skipped when its
  lowercased key already exists in the mapped internal attributes **or**
  equals any internal attribute name in the mapper — for *any* profile, not
  just `saml`.
- Colliding attributes are dropped wholesale (never merged), so mapped
  internal values stay exactly what the mapped external names carried.

## Security boundaries

| Threat | Control | Residual risk |
|--------|---------|---------------|
| IdP injects values into a mapped internal attribute via a case-variant or colliding FriendlyName | Case-insensitive known check + drop-on-collision against all internal names | A deliberate same-name mapping in `attributes.toml` is still honored by configuration |

## Consequences

**Positive**

- Passthrough can no longer alter or fabricate mapped internal attributes,
  including the `user_id_from_attrs` subject-id sources.

**Negative / migration requirements**

- A deployment that (perhaps unknowingly) relied on case-variant merging
  loses those values; the fix is a correct `attributes.toml` entry.

## References

- `crates/tunnelbana-plugins/src/saml2_backend.rs`
  (`passthrough_unmapped_attributes` block in `handle_acs`).
- ADR 0008 (OID-aware attribute map and unknown-attribute passthrough).
