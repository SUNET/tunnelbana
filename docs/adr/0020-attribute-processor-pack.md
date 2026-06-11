# ADR 0020 - `attribute_processor` processor pack (hash, scope, gender)

- **Status:** Accepted
- **Date:** 2026-06-10
- **Component:** `tunnelbana-plugins` - `microservices/processor.rs`
  (`AttributeProcessor`, config type `attribute_processor`).
- **Related:** [ADR 0011 - `attribute_processor` (`regex_sub`)](0011-attribute-processor-microservice.md),
  [ADR 0021 - `hasher`](0021-hasher-microservice.md).

## Context

ADR 0011 landed the `attribute_processor` chain with a single processor kind,
`regex_sub`. SATOSA ships five more under `micro_services/processors/`:
`HashProcessor`, `ScopeProcessor` (append `@scope`), `ScopeExtractorProcessor`
(copy the scope into another attribute), `ScopeRemoverProcessor` (strip the
scope) and `GenderToSchacProcessor` (text → ISO 5218 / schacGender code).

Two upstream quirks needed a porting decision:

- SATOSA's `HashProcessor` reads its **salt from the `hash_algo` config key**
  (a copy-paste bug - the salt key is dead config) and hashes only the
  *first* value of the attribute.
- Missing/unsuitable attributes raise `AttributeProcessorWarning`, which the
  SATOSA driver catches and logs - i.e. they are skips, not failures -
  while genuine config errors raise and abort.

## Decision

Add five processor kinds to the existing chain, keyed by short snake names:

- **`hash`** - `hex(hash(value‖salt))` per value. Reads `salt` from the
  `salt` key (the upstream bug is *not* reproduced) and hashes **all** values
  of the attribute, not just the first - half-pseudonymized multi-valued
  attributes are never the intent. `hash_algo` is `sha256` (default) or
  `sha512`; anything else (md5, sha1, …) is a build-time error rather than
  inheriting hashlib's full menu.
- **`scope`** - appends `@<scope>` to every value; `scope` required.
- **`scope_extractor`** - writes the domain part of the first scoped value
  into `mapped_attribute` (required), overwriting it; skips when no value is
  scoped.
- **`scope_remover`** - strips `@domain` from every value.
- **`gender`** - maps values to ISO 5218 codes (`male`→1, `female`→2,
  `not specified`→9, unknown→0), case-insensitive, applied to all values.
- The internal `Processor::apply` signature changed from per-value
  `&str → String` to operating on the attribute map, since `scope_extractor`
  writes a *different* attribute. SATOSA's warning-vs-error split maps to:
  missing/unsuitable attribute → silent skip (consistent with `regex_sub`
  since ADR 0011); bad config → build-time error.

## Security boundaries

| Threat | Control | Residual risk |
|--------|---------|---------------|
| Weak digests for pseudonymization | Only sha256/sha512 accepted; rejected algorithms fail at startup | Unsalted or short-salt hashes of low-entropy values (emails) remain enumerable - salt quality is operator responsibility (same as ADR 0021) |
| Partial hashing of multi-valued attributes | All values hashed (deliberate divergence from SATOSA) | - |
| SATOSA config porting with the upstream salt bug | tunnelbana reads `salt` correctly; a ported config that *relied* on the bug (salt silently empty) now actually salts | Hashes change vs. the buggy SATOSA output - flagged in the book for migrations that persist hashed values |
| Scope forgery via `scope_extractor` on multi-scoped input | First scoped value wins, deterministically | If upstream can assert mixed scopes, filter values first (ADR 0017) |

## Consequences

**Positive**

- The full SATOSA processor set is available in one chain; configs port by
  renaming the processor (`ScopeProcessor` → `scope`, etc.).
- Correct salt handling and whole-list hashing close two upstream sharp
  edges.

**Negative / accepted trade-offs**

- Hash outputs differ from a buggy-salted SATOSA deployment by design.
- `gender` keeps SATOSA's lossy unknown→`NOT_KNOWN` mapping for parity.

## References

- `crates/tunnelbana-plugins/src/microservices/processor.rs` -
  implementation + `hash_processor_salted_sha256`,
  `scope_processors_roundtrip`, `gender_processor_maps_to_schac_codes` tests
- `../SATOSA/src/satosa/micro_services/processors/*.py` - ported behavior
  (and the `hash_processor.py` salt bug)
