# Legacy Identifier Compatibility

Identifier migration is account migration. A SAML SP usually stores one released
value as its account key, so changing that value can create a second account for
the same person even when authentication still succeeds.

Use this chapter when replacing a SATOSA/PySAML2 deployment and you need to
decide whether tunnelbana should preserve old identifiers or issue new ones.

## What To Check First

Start with a real SAML response from the old proxy to the SP. The decisive
fields are:

- `<saml:NameID Format="...">...`
- `eduPersonTargetedID`
- `subject-id`
- `pairwise-id`
- `mail`, `eduPersonPrincipalName`, or any other attribute the SP may use as
  its local account key

SATOSA configuration tells you how SATOSA builds and releases values, but only
the SP can prove which value it stores. If the old response had a transient
NameID and only released `mail`, preserve that behavior unless the SP is ready
to migrate to a stronger stable identifier.

## SATOSA-Style Transient NameID

For flows like a SATOSA frontend that passes a transient upstream NameID and
releases only display/mail attributes, configure the SAML frontend to answer
with transient NameIDs and do not run `pairwiseid`, `nameid`, `legacy_eptid`, or
`hasher` for that SP:

```toml
[[frontend]]
type = "saml2"
name = "Saml2IDP"
  [frontend.config]
  name_id_formats = ["urn:oasis:names:tc:SAML:2.0:nameid-format:transient"]
```

tunnelbana mints a fresh transient value per response. That is correct SAML
behavior even if the old SATOSA proxy copied the upstream transient value
through byte-for-byte. The SP must not use a transient NameID as a durable
account key.

Use `filter_attributes` to keep the downstream release identical:

```toml
[[microservice]]
type = "filter_attributes"
name = "release"
  [microservice.config]
  allowed = ["displayname", "givenname", "surname", "mail"]
```

## Current Pairwise Persistent Mode

For new or intentionally migrated SAML persistent identifiers, prefer the
existing `pairwiseid` + `nameid` pair:

```toml
[[microservice]]
type = "pairwiseid"
name = "pairwise"
  [microservice.config]
  pairwise_salt = "${TUNNELBANA_PAIRWISE_SALT}"

[[microservice]]
type = "nameid"
name = "nameid"
```

`pairwiseid` computes:

```text
pairwise-id = hex(HMAC-SHA256(pairwise_salt, "{requester}-{subject-id}")) + "@" + scope
```

When the SAML frontend has negotiated persistent NameID, `nameid` uses the hash
part before `@` as the SAML subject value. This is not byte-compatible with old
PySAML2 MD5 EPTID values; it is a deliberate new identifier profile.

## SATOSA Hasher Compatibility

The `hasher` service reproduces SATOSA's `util.hash_data`:

```text
hex(hash(value || salt))
```

By default only `sha256` and `sha512` are accepted. If an old deployment really
used MD5 for released pseudonyms, enable it explicitly:

```toml
[[microservice]]
type = "hasher"
name = "legacy-md5-hasher"
  [microservice.config.""]
  salt = "${LEGACY_SATOSA_HASH_SALT}"
  alg = "md5"
  allow_legacy_md5 = true
  subject_id = true
  attributes = ["edupersontargetedid"]
```

The guard is required. `alg = "md5"` without `allow_legacy_md5 = true` is a
startup error. Scope this per requester whenever possible:

```toml
[microservice.config."https://new-sp.example.org"]
alg = "sha256"
subject_id = true
attributes = []
```

Use this only when you have confirmed the SP already stores the MD5-derived
value. For new SPs, keep SHA-256/SHA-512 or use pairwise identifiers.

## Attribute Processor MD5

The `attribute_processor` `hash` processor has the same guard:

```toml
[[microservice]]
type = "attribute_processor"
name = "legacy-attribute-hash"
  [[microservice.config.process]]
  attribute = "uid"
    [[microservice.config.process.processors]]
    name = "hash"
    hash_algo = "md5"
    allow_legacy_md5 = true
    salt = "${LEGACY_ATTRIBUTE_SALT}"
```

Without the guard, `hash_algo = "md5"` fails at startup. This processor hashes
attributes only; use `hasher` when the old deployment hashed `subject_id`.

## PySAML2 EPTID Compatibility

PySAML2's stock `saml2.eptid.Eptid` computes:

```text
idp_entity_id + "!" + sp_entity_id + "!" + md5(user_id || sp_entity_id || secret)
```

Use `legacy_eptid` only for SPs that already store that value as
`eduPersonTargetedID` or persistent NameID:

```toml
[[microservice]]
type = "legacy_eptid"
name = "legacy-eptid"
  [microservice.config]
  idp_entity_id = "https://old-idp.example.org/idp.xml"
  secret = "${LEGACY_PYSAML2_EPTID_SECRET}"
  allow_legacy_md5 = true

  # Default: use the first value of the internal "subject-id" attribute as the
  # PySAML2 user_id argument.
  source_attribute = "subject-id"

  # Default: release the value as internal "edupersontargetedid".
  target_attribute = "edupersontargetedid"
  release_attribute = true
  set_subject_id = false

  # Optional: run only for audited legacy SPs.
  requesters = ["https://legacy-sp.example.org/metadata"]
```

The SAML frontend emits `edupersontargetedid` as a NameID-valued
`eduPersonTargetedID` attribute when the attribute map marks it as
`eduPersonTargetedID` / OID `urn:oid:1.3.6.1.4.1.5923.1.1.1.10`.

For an SP whose persistent NameID itself was the legacy EPTID:

```toml
[[microservice]]
type = "legacy_eptid"
name = "legacy-eptid-nameid"
  [microservice.config]
  idp_entity_id = "https://old-idp.example.org/idp.xml"
  secret = "${LEGACY_PYSAML2_EPTID_SECRET}"
  allow_legacy_md5 = true
  source_attribute = "subject-id"
  requesters = ["https://legacy-sp.example.org/metadata"]
  release_attribute = false
  set_subject_id = true
```

The SAML frontend must also negotiate persistent NameID for that SP:

```toml
[frontend.config]
name_id_formats = ["urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"]
```

If the old PySAML2 EPTID store contains hand-edited or imported values, import
those exact mappings instead of recomputing. Recomputing only works when the old
secret, SP entityID, user identifier, and input normalization are all identical.

## Operational Rules

- Enable MD5 only with `allow_legacy_md5 = true`; this is a migration switch,
  not a default.
- Prefer per-SP/requester scoping. Do not enable legacy identifiers globally
  unless every SP has been audited.
- Keep legacy secrets in environment variables, not committed config.
- Verify with a decoded SAML response before cutover. Compare the old and new
  `NameID`, `eduPersonTargetedID`, `subject-id`, and `mail` values for the same
  test user and SP.
- Plan a retirement path: once SP-side account mappings are migrated, remove
  MD5 compatibility and switch to `pairwiseid`/`nameid` or a non-legacy
  attribute.
