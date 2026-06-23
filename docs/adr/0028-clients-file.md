# ADR 0028 - External client roster file (`clients_file`)

- **Status:** Accepted
- **Date:** 2026-06-23
- **Component:** `tunnelbana-plugins` - `client_loader.rs`, `oidc_frontend.rs`,
  `federation_frontend.rs` (frontend `config.clients_file`).
- **Related:** [ADR 0006 - SAML SP metadata store](0006-saml-frontend-sp-metadata-store.md),
  [ADR 0027 - frontend backend pin](0027-frontend-backend-pin.md).

## Context

The `oidc` and `oidc_federation` frontends register their relying parties inline
in the proxy TOML as `[[frontend.config.clients]]` tables, deserialized into
`Vec<Client>` and handed to `InMemoryClientStore::with_clients`
(`oidc_frontend.rs`, `federation_frontend.rs`). For a deployment whose client
roster is large, churns often, or is machine-generated (a registration portal
emitting the list), keeping that roster inline in the main config is awkward:
every roster change edits the main file, and the existing `include` directive can
only externalize the **whole** plugin config, not just the clients.

The SAML side already solved the analogous problem differently: downstream SPs
are loaded from a *list* of external metadata XML files via
`[frontend.config.metadata].local` (ADR 0006) plus optional MDQ. The OIDC side
had no file-based option for *just* the client list.

## Decision

Add an optional `clients_file: Option<String>` to both OIDC frontends, handled by
a shared `client_loader::load_clients(inline, clients_file)`:

- The file is a **bare JSON array** of `Client` objects (the same fields as an
  inline client table). JSON only - it is the format the user asked for and the
  one a generator most naturally emits; the existing `include` covers the TOML
  whole-config case.
- The file's clients are **merged** with the inline `clients` (inline first,
  then file), so keys/TTLs/etc. stay inline while the roster lives in its own
  file.
- An **unknown field** in a file entry is rejected at boot (via `serde_ignored`,
  which keeps the check in sync with `Client` as it evolves, rather than
  `#[serde(deny_unknown_fields)]` on the `grindvakt` type). A misspelled key
  like `redirect_uri` for `redirect_uris` would otherwise be silently dropped,
  leaving a client that fails closed for a non-obvious reason.
- A **duplicate `client_id`** anywhere in the merged set is a fail-fast
  `Error::Config` at boot. `with_clients` keys a `HashMap` by `client_id` and
  silently keeps the last entry, which would shadow a client's secret/redirect
  URIs; the loader rejects it instead. This check runs even with no
  `clients_file`, so it also catches accidental duplicates among purely-inline
  clients.
- The path is read **as-given** (relative to the process working directory, like
  the sibling `signing_key_path` and SAML `metadata.local`), so no
  `config_dir` plumbing is added to `BuildContext`. `${ENV}` interpolation
  already runs over the config upstream, so it applies to the path.
- A **single** path, read **once at boot** (fail-fast on missing/malformed). No
  hot-reload - consistent with keys, inline clients, and SAML metadata, none of
  which reload today.
- An empty final set stays valid (a frontend with no registered clients is
  already legal).

The **SAML2 frontend is intentionally excluded**: SP registration is already
file-based and list-shaped (`metadata.local` + MDQ, ADR 0006), and SP identity is
standard signed metadata XML, not a JSON list of our own `Client` structs. There
is no inline-only-roster gap to close there.

## Security boundaries

| Threat | Control | Residual risk |
|--------|---------|---------------|
| `client_secret` exposed in plaintext in an external file | Same exposure as inline secrets today, now in a separate artifact; operators must apply file permissions/secret management to the roster file | A world-readable roster file leaks every client secret - it is as sensitive as the main config |
| A duplicate `client_id` silently shadowing another client's secret/redirect URIs | `load_clients` rejects any duplicate across the merged set with a boot error naming the id | - |
| Request-time file access / path injection | The path comes only from operator config and is read once at `build()`; no request data touches it, no per-request reads | - |
| Malformed or missing file booting a half-configured proxy | Read+parse failures abort startup with `Error::Config` (fail-fast), the server never starts | - |

## Consequences

**Positive**

- A churning or generated roster lives in its own JSON file, regenerated
  independently of the main config, while keys/TTLs stay inline.
- One shared helper (`client_loader.rs`, modeled on `keyload.rs`) serves both
  OIDC frontends; the federation frontend's runtime auto-registration is
  untouched and coexists with the seeded static clients.
- The duplicate-id guard hardens inline configs too, turning a previously silent
  last-wins shadow into a boot error.

**Negative / accepted trade-offs**

- The path is working-directory-relative, not config-file-relative, so it
  behaves differently from `include`. This keeps it consistent with the
  `signing_key_path` next to it (the more common reference point) at the cost of
  one more place where "relative to what?" must be known.
- JSON only; no TOML or multi-file roster. Multi-file/sharded rosters and TOML
  remain the job of `include` or a future extension.
- Static load: a roster change needs a proxy restart.

## References

- `crates/tunnelbana-plugins/src/client_loader.rs` - `load_clients` + unit tests
  (merge, duplicate-id error, missing/malformed file)
- `crates/tunnelbana-plugins/src/oidc_frontend.rs`,
  `federation_frontend.rs` - `config.clients_file` wiring
- `crates/tunnelbana-plugins/tests/proxy_oidc_op.rs` -
  `client_loaded_from_clients_file_can_authorize`
- [Configuration: client roster from a file](../src/built-in-plugins.md#client-roster-from-a-file)
