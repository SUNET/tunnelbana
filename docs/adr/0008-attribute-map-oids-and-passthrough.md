# ADR 0008 — OID-aware attribute map and unknown-attribute passthrough

- **Status:** Accepted
- **Date:** 2026-06-09
- **Component:** `tunnelbana-core` — `attributes.rs` (`ProfileAttribute`,
  `ProfileMapping`, `external_names`, `profile_attribute`);
  `tunnelbana-plugins` — `saml2_frontend.rs` (`attribute_name_format`),
  `saml2_backend.rs` (`passthrough_unmapped_attributes`).
- **Related:** `config/attributes.toml`.

## Context

The attribute map knew only plain external names per profile
(`saml = ["mail"]`). Real SAML federations (SWAMID) expect attributes under
the **`uri` name format** — OID names like `urn:oid:0.9.2342.19200300.100.1.3`
plus a `FriendlyName` — and the frontend hardcoded
`ATTRNAME_FORMAT_BASIC` with no FriendlyName. Separately, SATOSA's
`allow_unknown_attributes` keeps attributes the map doesn't know about;
tunnelbana silently dropped them.

## Decision

- **Polymorphic profile mapping (back-compatible).** A profile entry is either
  the legacy list or a detailed table, normalized once at construction:

  ```toml
  [attributes.givenname]
  saml = ["givenName"]                  # legacy form, still valid

  [attributes.mail]
  saml = { names = ["mail", "email"], oid = "urn:oid:0.9.2342.19200300.100.1.3", friendly_name = "mail" }
  ```

  `to_internal` additionally matches the `oid` and `friendly_name` as inbound
  keys; `from_internal` is unchanged (first of `names`). New accessors:
  `profile_attribute(profile, internal)` and `external_names(profile)` (every
  known name, OID and FriendlyName for a profile). `AttributeMapper::raw()` is
  gone; the discovery `claims_supported` path uses the normalized iterator.
- **Frontend `attribute_name_format = "basic" | "uri"`** (default `basic`).
  In `uri` mode each released attribute is emitted with `Name = oid`,
  `NameFormat = …:attrname-format:uri` and a `FriendlyName`; an attribute with
  no OID in the map falls back to its basic name with a warning. The backend
  needs no change — it already indexes inbound attributes by both Name and
  FriendlyName, and now by OID too.
- **Backend `passthrough_unmapped_attributes`** (default false). After
  mapping, attributes whose Name *and* FriendlyName are absent from
  `external_names("saml")` are kept under a normalized key: lowercased
  FriendlyName, else lowercased Name. The structured attribute list is
  iterated (not the Name+FriendlyName-flattened map), so each attribute is
  considered exactly once; mapped values are never clobbered; collisions merge
  with order-preserving dedupe.

## Security boundaries

| Threat | Control | Residual risk |
|--------|---------|---------------|
| Passthrough leaking attributes to downstream RPs/SPs | Frontends emit via `from_internal`, which only emits internal names present in the map — passthrough keys are dropped at the boundary | A future frontend-side passthrough opt-in must preserve this asymmetry deliberately |
| Attribute smuggling under a colliding passthrough key | Mapped internal values are never overwritten; passthrough merges only into unmapped or same-named passthrough keys | Two *unknown* attributes normalizing to one key merge values (documented) |
| OID spoofing (same value under Name and OID) | Inbound matching dedupes values per internal attribute, order-preserving | — |

## Consequences

**Positive**

- SWAMID-style `uri`/OID interop on the IdP side with no change on the SP side.
- Legacy `attributes.toml` files parse unchanged (`serde(untagged)`).
- `external_names` gives micro-services and plugins a single source of truth
  for "is this attribute known".

**Negative / accepted trade-offs**

- Passthrough keys are lowercased raw names, not curated internal names —
  deployments filtering on them must use the normalized form.
- `name` config in `uri` mode requires OIDs in the map to be effective; the
  warning-and-fallback keeps flows working rather than failing closed (these
  are attribute *names*, not security decisions).

## References

- `crates/tunnelbana-core/src/attributes.rs`
- `crates/tunnelbana-plugins/tests/saml_roundtrip.rs` — uri-mode roundtrip,
  passthrough on/off, FriendlyName/Name keying
- `config/attributes.toml` — standard OIDs (mail, givenName, sn, displayName,
  eduPersonPrincipalName)
