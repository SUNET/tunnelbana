# ADR 0011 — `attribute_processor` micro-service (regex value transforms)

- **Status:** Accepted
- **Date:** 2026-06-10
- **Component:** `tunnelbana-plugins` — `microservices.rs`
  (`AttributeProcessor`, config type `attribute_processor`).
- **Related:** [ADR 0008 — OID-aware attribute map](0008-attribute-map-oids-and-passthrough.md),
  [ADR 0012 — `attribute_authorization`](0012-attribute-authorization-microservice.md).

## Context

The production SATOSA instances at SUNET run an `AttributeProcessor`
micro-service with a `RegexSubProcessor` that rewrites the scoped SAML
`subject-id` into a local identifier:

```yaml
process:
- attribute: subject-id
  processors:
  - name: RegexSubProcessor
    regex_sub_match_pattern: "@([^.]+)\\.(.+)"
    regex_sub_replace_pattern: _\1
```

i.e. `user@scope.tld` → `user_scope`. This matters because the SWAMID
registrations assert the REFEDS **Personalized Access** entity category, under
which IdPs release `subject-id` (`urn:oasis:names:tc:SAML:attribute:subject-id`)
rather than eduPersonPrincipalName; downstream services consume the rewritten
local form. tunnelbana had no attribute-transform micro-service, so SATOSA
configs using this could not be ported.

## Decision

Add an `attribute_processor` micro-service mirroring SATOSA's semantics on the
**response path**: a `process` list of `{attribute, processors}` rules, where
each named internal attribute's values run through the rule's processor chain
in order, every value transformed in place.

The first (and currently only) processor is `regex_sub`:

- `match_pattern` and `replace_pattern` are both required and must be non-empty;
  `match_pattern` is compiled with the `regex` crate at **build time** and any
  missing, empty, or invalid value fails plugin construction, not the request
  path;
- replacement uses `Regex::replace_all` (all matches, like Python's
  `re.sub`);
- replacement strings accept the regex crate's `$1`/`${1}` group references
  **and** Python-style `\1` backreferences, which are converted at build time
  (`convert_backrefs`) so SATOSA configs paste over unchanged.

Processor kinds are an enum keyed by `name`; SATOSA's remaining processors
(hash, scope add/extract/remove, gender) can be added as further variants
without config-shape changes.

Like SATOSA, the transform applies to the attribute **after** the backend has
composed the subject id (`user_id_from_attrs`), so the rewritten value is what
gets released downstream as an attribute while NameID handling is untouched.

## Security boundaries

| Threat | Control | Residual risk |
|--------|---------|---------------|
| Regex injection / DoS via config | Patterns come from operator config only, compiled once at startup; the `regex` crate has no backtracking (linear-time matching) | A pathological pattern can still be slow to compile — config-load time, not request time |
| Unknown processor silently ignored | Unknown `name` rejects the config at build time | — |
| Transform widening attribute release | The processor only rewrites values of attributes already present; it cannot add attributes or bypass `filter_attributes`/policy | Ordering matters: place it before any authorization micro-service that matches on the transformed form |

## Consequences

**Positive**

- Production SATOSA `AttributeProcessor`/`RegexSubProcessor` configs port 1:1
  (`\1` backrefs included).
- Build-time regex compilation keeps the hot path allocation-light and makes
  config errors fail fast.

**Negative / accepted trade-offs**

- Only `regex_sub` is implemented; SATOSA's hash/scope/gender processors
  remain unported until a deployment needs them.
- Python and Rust regex syntaxes are close but not identical (no lookaround
  in the `regex` crate); exotic patterns may need adjusting.

## References

- `crates/tunnelbana-plugins/src/microservices.rs` — `AttributeProcessor`,
  `convert_backrefs`
- `crates/tunnelbana-plugins/src/microservices.rs` tests —
  `attribute_processor_regex_sub_satosa_subject_id` (the production pattern),
  `attribute_processor_dollar_backrefs_and_chaining`
- `../SATOSA/src/satosa/micro_services/attribute_processor.py`,
  `processors/regex_sub_processor.py` — ported behavior
