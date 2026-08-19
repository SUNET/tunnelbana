# ADR 0040 - Inline `clients` reject unknown fields like `clients_file`

- **Status:** Accepted
- **Date:** 2026-08-05
- **Component:** `tunnelbana-plugins` (`client_loader`, `oidc_frontend`,
  `federation_frontend`).
- **Supersedes in part:** ADR 0028.

The listed ADRs remain immutable historical records. Where this record
conflicts with one of them, the earlier statement is invalid as a description
of current behavior and this record is authoritative.

## Context

ADR 0028 made unknown fields in `clients_file` JSON entries a hard error so a
typo'd key (e.g. `redirect_uri` for `redirect_uris`) cannot silently produce
a half-configured client. Inline `clients` in the frontend TOML did not get
the same strictness: serde dropped unknown fields, and a misspelled key
quietly yielded a client with empty `redirect_uris` — a client that fails
only later, at protocol time, with no hint about the real cause.

## Decision

- Inline `clients` entries are carried through config parsing as raw values
  and deserialized in `client_loader` with the same `serde_ignored`
  unknown-field detection as file entries; an unknown field names the
  offending entry (`inline clients[<index>]`) and fails the build.
- The duplicate-`client_id` check continues to apply across the merged set.

## Security boundaries

| Threat | Control | Residual risk |
|--------|---------|---------------|
| Typo'd client key silently weakening registration | Unknown-field rejection on inline entries, same as `clients_file` | A correctly spelled but wrong-valued field remains an operator error |

## Consequences

**Positive**

- Both client-roster sources fail fast on misspelled keys, at startup, with
  the offending field and index named.

**Negative / migration requirements**

- Configurations carrying previously ignored extra keys in inline `clients`
  fail at startup and must remove or correct them.

## References

- `crates/tunnelbana-plugins/src/client_loader.rs`
- ADR 0028 (`clients_file` external client roster).
