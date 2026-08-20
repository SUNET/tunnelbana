# ADR 0052 - Embedded CPython micro-services

- **Status:** Accepted
- **Date:** 2026-08-19
- **Components:** `tunnelbana-python`, `tunnelbana`, and the generic
  micro-service registry in `tunnelbana-core`.

## Context

Tunnelbana's micro-service pipeline currently accepts only Rust
implementations. Operators also need to migrate small, synchronous policy and
attribute transformations from Python without introducing a network sidecar or
making PyO3 a dependency of the protocol-neutral core and built-in plugins.

Embedding trusted code creates two distinct risks: a broad Rust/Python data
boundary could expose credentials or mutable proxy internals, and synchronous
Python can block an async worker indefinitely. CPython also cannot safely
cancel a running call when an application-level timeout expires.

## Decision

- Add a dedicated `tunnelbana-python` workspace crate using exactly PyO3 0.29.2
  and pythonize 0.29.0. Link dynamically to the system CPython 3.13 library.
  Core and built-in plugins do not depend on either crate.
- Initialize CPython explicitly at binary startup using CPython's isolated
  configuration: interpreter environment variables (`PYTHONPATH`,
  `PYTHONHOME`, ...) are ignored, the user site directory is excluded, and
  bytecode caches are never written. Add only the configured module directory
  and import only explicit module/class pairs. Reuse one class instance per
  configured micro-service. An optional configured virtual environment is
  adopted by pointing `PyConfig.executable` at its interpreter, so CPython's
  own path machinery applies `pyvenv.cfg` and venv site-packages; this stays
  file-based configuration, never environment-based activation.
- Support synchronous `process_request` and `process_response` methods only.
  Require at least one callable method and treat a missing direction as
  identity. Reject coroutine functions and runtime awaitables.
- Expose complete `InternalData`, but only a restricted context snapshot. Allow
  changes to `target_backend`, `decorations`, and returned `InternalData`.
  Strictly validate all output and read-only fields before an atomic commit.
  Reserved first-writer-wins decorations (`target_entity_id`,
  `target_authn_context_class_ref`, `target_accr_comparison`) may be published
  when absent but never changed or removed once another component set them.
  The proxy core follows an `error_redirect` decoration only when it is an
  absolute http(s) URL free of control characters.
- Run each call in `spawn_blocking` behind one global Tokio semaphore. The
  deadline covers permit wait and execution. A timed-out blocking task is
  detached and retains its owned permit until Python returns.
- Sanitize client-facing errors. Logs contain fixed metadata and bounded stack
  locations, never Python configuration/data, HTTP credentials, bodies, or
  exception messages.
- Store only micro-service constructors as captured `Send + Sync` closures;
  retain source compatibility with existing function registrations.

Python code is trusted operator code, not sandboxed code. Python endpoints,
async Python, automatic discovery, `abi3`, extension modules, maturin, and
runtime package installation are outside this decision.

## Security boundaries

| Threat | Control | Residual risk |
|--------|---------|---------------|
| Python reads request credentials or persistent state | Restricted copied context omits URI, headers, cookies, body, state, secrets, clients, and Rust handles | Trusted code still has the process's OS permissions |
| Python corrupts routing/session values through partial mutation | Read-only comparison, strict complete conversion, atomic commit of the allowed fields | Valid but harmful allowed values remain operator-code responsibility |
| Python exception discloses data to a client or log | Fixed outward error; logs omit exception messages/source and bound escaped stack locations | Module, class, method phase, file/function location are operational metadata |
| Blocking work starves async runtime workers | `spawn_blocking` plus global semaphore | CPython/native code can consume blocking threads and process resources |
| Timeout creates unbounded detached calls | Permit remains owned until the timed-out call exits | Enough permanently hung calls can exhaust all Python capacity |
| Unexpected code is loaded | One explicit module path and configured imports; isolated interpreter configuration ignores `PYTHONPATH`/`PYTHONHOME` and the user site directory; no discovery or pip | Import statements inside trusted modules may load their own dependencies from system site-packages |
| Python steers routing or client redirects from request input | First-writer-wins enforcement for reserved routing decorations; proxy follows only absolute http(s) `error_redirect` URLs | Operator code that derives an allowed value (e.g. a fresh `target_entity_id` or an https `error_redirect`) from untrusted input remains its own responsibility |

## Consequences

**Positive**

- Existing synchronous Python transformations can run in-process with no
  protocol-side changes or serialization over a network boundary.
- PyO3 remains isolated and the existing Rust micro-service API is preserved.
- Invalid output cannot partially alter a request context.

**Negative / migration requirements**

- Build and runtime environments must carry matching CPython 3.13 development
  and shared-library packages.
- CPython is part of the server process: crashes, hangs, memory use, imports,
  and global/instance state in operator code affect the whole service.
- Operators must deploy dependencies ahead of startup and bound I/O inside
  Python code. A proxy deadline cannot cancel the underlying call.

## References

- `crates/tunnelbana-python`
- `docs/src/python-microservices.md`
- `docs/src/development/embedded-python-plan.md`
