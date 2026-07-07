# ADR 0032 - Legacy identifier compatibility modes

- **Status:** Accepted
- **Date:** 2026-07-06
- **Component:** `tunnelbana-plugins` - `microservices/{hasher,processor,legacy_eptid}.rs`,
  `saml2_frontend.rs`
- **Related:** [ADR 0020 - `attribute_processor` processor pack](0020-attribute-processor-pack.md),
  [ADR 0021 - `hasher`](0021-hasher-microservice.md),
  [ADR 0030 - eduID `scimapi` micro-services](0030-eduid-scimapi-microservices.md)

## Context

ADR 0020 and ADR 0021 rejected MD5 in SATOSA-compatible hashing. That is the
right default for new identifiers, but it leaves one migration gap: some
existing SATOSA/PySAML2 deployments have already released MD5-derived
pseudonyms to SPs, and those SPs may store the released value as the account
key. Replacing the value with SHA-256 creates a new external identity.

PySAML2 also has a stock `saml2.eptid.Eptid` helper whose wire value is:

```text
idp_entity_id + "!" + sp_entity_id + "!" + md5(user_id || sp_entity_id || secret)
```

Operators need a way to preserve those values during migration without making
MD5 a silent or attractive default.

## Decision

Add explicit compatibility modes:

- `hasher`: accept `alg = "md5"` only when the effective requester entry also
  sets `allow_legacy_md5 = true`.
- `attribute_processor`: accept `hash_algo = "md5"` only when that processor
  sets `allow_legacy_md5 = true`.
- `legacy_eptid`: add a response-path micro-service that generates the stock
  PySAML2 MD5 EPTID value. It requires `allow_legacy_md5 = true`, a non-empty
  `idp_entity_id`, and a non-empty `secret`. It can be limited to specific
  requester entityIDs, and can release the value as an internal
  `edupersontargetedid` attribute, set it as `subject_id`, or both.
- `saml2_frontend`: when an outbound internal attribute maps to
  `eduPersonTargetedID`, serialize its values as NameID-valued SAML attribute
  values rather than plain strings.

No default changes: SHA-256/SHA-512 remain the normal hash choices, and
`pairwiseid` + `nameid` remain the preferred new persistent subject profile.

## Security Boundaries

| Threat | Control | Residual risk |
|--------|---------|---------------|
| Accidental weak digest use | MD5 requires `allow_legacy_md5 = true`; otherwise startup fails | Operators can still enable it globally by leaving `requesters` empty; documentation says to scope per SP |
| New SPs inheriting legacy IDs | `legacy_eptid` is a separate service, not folded into `pairwiseid`/`nameid`, and supports a `requesters` allowlist | Review micro-service order and release policy |
| Account takeover via identifier mismatch | Exact PySAML2 formula preserves legacy account keys when inputs and secret match | If the old deployment had stored overrides or different input normalization, recomputation may not match; import old mappings instead |
| Correlation across SPs | PySAML2 EPTID includes SP entityID in the hash input | MD5 remains weak against chosen-input attacks; compatibility mode should be retired after SP migration |

## Consequences

**Positive**

- Operators can replace SATOSA/PySAML2 without forcing account relinking for
  SPs that already store MD5-derived identifiers.
- MD5 use is auditable in config and logs.
- `eduPersonTargetedID` output now matches PySAML2's NameID-valued attribute
  shape.

**Negative / accepted trade-offs**

- The codebase carries MD5 support for migration. The guard and separate
  service keep it out of the normal path.
- Recomputed PySAML2 EPTID compatibility only works when old inputs and secret
  are known exactly. Importing old mappings is still the safer path.

## References

- `crates/tunnelbana-plugins/src/microservices/legacy_eptid.rs`
- `crates/tunnelbana-plugins/src/microservices/hasher.rs`
- `crates/tunnelbana-plugins/src/microservices/processor.rs`
- `crates/tunnelbana-plugins/src/saml2_frontend.rs`
- `../pysaml2/src/saml2/eptid.py`
