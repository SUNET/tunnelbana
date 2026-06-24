# ADR 0031 - Configurable index page (`index_html`)

- **Status:** Accepted
- **Date:** 2026-06-24
- **Component:** `tunnelbana` binary - `main.rs` (`index`, `load_index_page`,
  `resolve_sibling`); `tunnelbana-core` - `config.rs` (`ProxyConfig.index_html`).
- **Related:** [ADR 0029 - O(1) router dispatch](0029-router-exact-match-dispatch.md).

## Context

The binary serves a landing page at `/` and the project logo at
`/assets/tunnelbana.png`. Both were hard-coded in `main.rs`: the HTML as a string
literal, the PNG embedded with `include_bytes!`. That is fine for the demo
deployment but unhelpful for operators who run tunnelbana under their own brand -
they have no way to replace the page short of forking and rebuilding the binary.

We want operators to point at their own landing page from config, while keeping
the zero-config default working (the demo, local dev, and a fresh install all
still get a sensible page with no extra files). The change should not add a
templating engine, a static-file server, or a new dependency, and it must follow
the project's fail-fast config convention: a bad path aborts boot rather than
surfacing as a runtime 404 or a silent fall-back.

## Decision

Add an optional `index_html` top-level config key (`Option<String>`,
`#[serde(default)]`) holding a path to an HTML file. The binary resolves the page
**once at boot**:

- `load_index_page(cfg, config_path)` returns the bytes to serve at `/`.
  - `Some(path)` - read the file (resolved by `resolve_sibling`: relative paths
    are joined to the **config file's directory**, the same rule plugin
    `include` paths use in `ProxyConfig::resolve_includes`; absolute paths are
    used as-is). An I/O error propagates out of `main` and exits the process
    (fail-fast). The bytes are wrapped in `web::Bytes::from(String)`.
  - `None` - serve the built-in `DEFAULT_INDEX_HTML` via
    `web::Bytes::from_static` (no allocation, no copy).
- The resolved page is stored as `web::Data<web::Bytes>` and injected into the
  `index` handler. `web::Bytes` is reference-counted, so each request clones a
  cheap handle rather than re-reading the file or copying the body.
- The logo route (`/assets/tunnelbana.png`, still `include_bytes!`-embedded) is
  left untouched and always available; a custom page may reference it or ignore
  it. A custom page is otherwise responsible for its own assets - we deliberately
  did **not** add a general static-file mount.

Reading once at boot (rather than per request) keeps the hot path allocation-free
and makes a missing/unreadable file a startup error instead of an intermittent
runtime failure. The trade-off - edits to the file require a restart - is
acceptable for a landing page and consistent with how the rest of the config is
loaded.

## Security boundaries

| Threat | Control | Residual risk |
|--------|---------|---------------|
| Operator points `index_html` at a path traversal / unintended file | The path comes only from the operator-controlled config file, never from a request; it is read once at boot, not derived from any inbound parameter | Operator-controlled, not attacker-controlled - identical trust level to every other config path (`attributes`, `cache_dir`, plugin `include`) |
| Untrusted request influences which file is served | `/` ignores all request input; the served bytes are fixed at boot | None - no request data reaches the filesystem |
| Malicious/oversized HTML served to users | The file is operator-supplied and served verbatim with `text/html; charset=utf-8`; the operator owns its content (and any script it embeds) | Operator-controlled; same boundary as any site the operator deploys |
| Silent failure hides a misconfiguration | A configured-but-unreadable path aborts startup with an error rather than falling back to the default or returning a runtime 404 | None - failure is loud and at boot |

## Consequences

**Positive**

- Operators can rebrand the landing page with a single config key and no rebuild.
- Zero-config default is preserved: absent `index_html`, the built-in page (logo,
  tagline, project link) is served exactly as before.
- No new dependency, no templating engine, no static-file server. The hot path
  serves a pre-resolved `web::Bytes` clone per request (no I/O, no allocation of
  the body).
- Fail-fast: a bad path is caught at boot, matching the project convention that
  config errors abort startup.

**Negative / accepted trade-offs**

- The custom page is read once; editing it requires a restart. Acceptable for a
  landing page and consistent with the rest of config loading.
- Only the single `/` document is configurable. A custom page must supply its own
  CSS/JS/images (the built-in logo route is the one exception); we did not add a
  general asset directory, to keep the surface small. A future ADR can revisit a
  static-file mount if demand appears.

## References

- `crates/tunnelbana-core/src/config.rs` - `ProxyConfig.index_html`.
- `crates/tunnelbana/src/main.rs` - `load_index_page`, `resolve_sibling`,
  `index` handler, `DEFAULT_INDEX_HTML`; unit tests (`index_serves_builtin_landing_page`,
  `index_serves_custom_page`, `load_index_page_defaults_to_builtin_when_unset`,
  `load_index_page_reads_custom_file_relative_to_config`,
  `load_index_page_errors_on_missing_file`).
- `docs/src/configuration.md` - "The index page" section.
