# ADR 0036 - `custom_logging` opens audit logs with `O_NOFOLLOW`

- **Status:** Accepted
- **Date:** 2026-08-05
- **Component:** `tunnelbana-plugins` micro-services (`custom_logging`).
- **Supersedes in part:** ADR 0023, ADR 0033.

The listed ADRs remain immutable historical records. Where this record
conflicts with one of them, the earlier statement is invalid as a description
of current behavior and this record is authoritative.

## Context

ADR 0033 stated that audit-log targets are created or restricted to mode
`0600` before use. The implementation opened the log target following
symlinks and re-applied `chmod 0600` on every write. Following symlinks lets
a planted symlink redirect audit records (and the chmod) onto an unrelated
file the process can write, and re-chmodding a pre-existing target on each
record extends the process's authority over files it did not create.

## Decision

- On Unix, the log target is opened with `O_NOFOLLOW | O_NONBLOCK`
  (`OpenOptionsExt::custom_flags`): a symlinked target is refused at both
  startup and write time.
- Owner-only mode `0600` is applied only at creation via `OpenOptions::mode`;
  a pre-existing target keeps its own permissions.
- The opened file must be a regular file; other file types (FIFOs, devices)
  are rejected. `O_NONBLOCK` is what keeps a planted FIFO from hanging the
  caller, through two distinct paths: a write-only open of a FIFO with **no
  reader** fails immediately with `ENXIO` (no descriptor is created, so the
  regular-file check never runs and the target is refused by the failed open
  itself), while a FIFO **with a reader** attached opens without blocking and
  is then rejected by the regular-file check. Without the flag, the
  readerless open would block until a reader appeared (see the boundaries
  table). Once the descriptor is confirmed to be a regular file,
  `O_NONBLOCK` is cleared with `fcntl(F_SETFL)`, since it has no effect on
  regular-file I/O and the handle should behave like an ordinary append
  handle.
- An opt-out config flag `allow_insecure_log_target = true` restores the
  SATOSA-compatible open behavior (follow symlinks, accept non-regular
  targets) for deployments that log through a symlinked target such as
  `/dev/stdout` in a container, or a FIFO feeding a syslog reader. The
  hardened behavior remains the default.

## Security boundaries

| Threat | Control | Residual risk |
|--------|---------|---------------|
| Symlink redirection of audit writes and chmod | `O_NOFOLLOW` on every open (default) | A hard link is still followed, and a hard link can target any writable regular file on the same filesystem, not only one in the same directory tree; a symlinked *parent* directory component is also still followed, so `O_NOFOLLOW` on the leaf does not prove the resolved path is the intended one. Closing either needs `openat2(RESOLVE_NO_SYMLINKS)` or a directory-anchored open. `allow_insecure_log_target` re-enables symlink redirection by operator choice |
| Writes to non-regular targets (FIFOs, devices) | `O_NONBLOCK` on open, then a regular-file check on the descriptor (default) | Accepted deliberately when `allow_insecure_log_target` is set - note that in that mode a planted FIFO with no reader **will** block the caller |
| Planted FIFO stalls the proxy (boot hang, or one parked tokio worker per response, since `process_response` opens without `spawn_blocking`) | `O_NONBLOCK`: a readerless FIFO fails the open immediately with `ENXIO` (the regular-file check never runs), and a reader-attached FIFO opens without blocking and is rejected by the regular-file check | Only closed in the default mode; `allow_insecure_log_target` accepts the blocking open by design |
| Silent repair of permissive pre-existing logs | Permissions set only at creation | Operators must secure pre-existing log files themselves. **Note this is weaker than the pre-ADR-0033 code**, which called `set_permissions(0600)` on every open and therefore hard-failed at startup on a target owned by another user; an attacker-owned, world-readable pre-existing regular file is now accepted silently |
| Audit-write failure after startup | Failure is logged via `tracing::error!` | The flow still succeeds, so replacing the target with a symlink post-startup turns every subsequent write into `ELOOP` and authentication continues **unlogged** indefinitely. `O_NOFOLLOW` converts log *redirection* into silent total audit *loss*; operators should alert on the write-failure log line |

## Consequences

**Positive**

- Audit records and permission changes can no longer be redirected through a
  symlink, and the process no longer chmods files it did not create.
- A planted FIFO at the log target is rejected rather than hanging the proxy
  at boot or parking a tokio worker per authentication response.

**Negative / migration requirements**

- Deployments that deliberately symlink the audit log (for example the
  common container pattern of symlinking it to `/dev/stdout`, or a FIFO
  feeding a syslog reader) must either set `allow_insecure_log_target = true`
  or configure the real path instead.
- Pre-existing log files with permissive modes are no longer tightened
  automatically; operators must set `0600` themselves.

## References

- `crates/tunnelbana-plugins/src/microservices/logging.rs`
- ADR 0023 (`custom_logging` micro-service), ADR 0033 (fail-closed security
  boundaries).
