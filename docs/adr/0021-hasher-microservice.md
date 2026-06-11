# ADR 0021 - `hasher` micro-service

- **Status:** Accepted
- **Date:** 2026-06-10
- **Component:** `tunnelbana-plugins` - `microservices/hasher.rs`
  (`Hasher`, config type `hasher`).
- **Related:** [ADR 0020 - processor pack (`hash` processor)](0020-attribute-processor-pack.md).

## Context

SATOSA's `Hasher` pseudonymizes the **subject id** and selected attributes
per requester: config is a map keyed by requester whose `""` entry provides
required defaults (`salt`, plus `alg`=sha512, `subject_id`=yes,
`attributes`=[]), each requester entry overriding fields individually. Hashing
is `satosa.util.hash_data`: `hex(hash(value ‖ salt))`.

This overlaps with - but is distinct from - the `hash` *processor*
(ADR 0020): the processor transforms one named attribute inside a chain,
while `Hasher` is the per-requester pseudonymization policy and the only one
that can hash `subject_id`, which is not an attribute.

## Decision

Port `Hasher` with field-level default merging:

- Config deserializes as a requester-keyed map. The `""` entry is **required**
  and must carry a non-empty `salt` - there is no usable zero-config mode for
  a pseudonymization service. Defaults: `alg = "sha512"`,
  `subject_id = true`, `attributes = []`.
- Every requester entry is materialized at build time as defaults overlaid
  with its explicitly-set fields (SATOSA's `defs.update(conf)`), so lookup at
  runtime is exact-requester else `""` - no `"default"` synonym here,
  matching SATOSA's `config.get(requester, config[""])`.
- `hash_data` reproduces `hex(hash(value ‖ salt))` exactly, so a tunnelbana
  proxy can take over a SATOSA deployment **without changing released
  pseudonyms** (same salt, same alg → same values).
- Algorithms: `sha256`/`sha512` only; others are build-time errors (SATOSA
  accepts anything in hashlib, md5 included - deliberately not ported).
- All values of each listed attribute are hashed; a `subject_id = true` entry
  with no subject id present is a no-op.

## Security boundaries

| Threat | Control | Residual risk |
|--------|---------|---------------|
| Releasing correlatable identifiers to an SP | Per-requester salt/alg yields per-deployment (and optionally per-SP) pseudonyms | Same salt across SPs keeps pseudonyms correlatable across them - use per-requester salts when unlinkability is the goal |
| Dictionary attacks on hashed low-entropy values | Salt is mandatory and checked non-empty at startup | No minimum salt length/entropy enforced (SATOSA parity); plain hashing is not a KDF - documented |
| Weak algorithm via config | md5/sha1 rejected at build time | - |
| Silent half-configuration | Missing `""` section or missing salt aborts startup | - |

## Consequences

**Positive**

- SATOSA `Hasher` configs port verbatim and produce identical pseudonyms,
  enabling drop-in migration.
- Field-level override merging means requester entries stay minimal.

**Negative / accepted trade-offs**

- Narrower algorithm set than hashlib; a config using e.g. `blake2b` must
  move to sha256/sha512 (and accept changed pseudonyms) at migration time.

## References

- `crates/tunnelbana-plugins/src/microservices/hasher.rs` - implementation +
  `hashes_subject_id_and_listed_attributes_with_defaults`,
  `per_requester_entry_overrides_alg_and_subject_id` tests
- `../SATOSA/src/satosa/micro_services/hasher.py`,
  `../SATOSA/src/satosa/util.py` (`hash_data`) - ported behavior
