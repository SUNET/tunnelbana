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

- On Unix, the log target is opened with `O_NOFOLLOW`
  (`OpenOptionsExt::custom_flags(libc::O_NOFOLLOW)`): a symlinked target is
  refused at both startup and write time.
- Owner-only mode `0600` is applied only at creation via `OpenOptions::mode`;
  a pre-existing target keeps its own permissions.
- The opened file must be a regular file; other file types (FIFOs, devices)
  are rejected.
- An opt-out config flag `allow_insecure_log_target = true` restores the
  SATOSA-compatible open behavior (follow symlinks, accept non-regular
  targets) for deployments that log through a symlinked target such as
  `/dev/stdout` in a container, or a FIFO feeding a syslog reader. The
  hardened behavior remains the default.

## Security boundaries

| Threat | Control | Residual risk |
|--------|---------|---------------|
| Symlink redirection of audit writes and chmod | `O_NOFOLLOW` on every open (default) | A hard link to a writable regular file in the same directory tree is still followed; `allow_insecure_log_target` re-enables symlink redirection by operator choice |
| Writes to non-regular targets (FIFOs, devices) | Regular-file check on the opened descriptor (default) | Accepted deliberately when `allow_insecure_log_target` is set |
| Silent repair of permissive pre-existing logs | Permissions set only at creation | Operators must secure pre-existing log files themselves |

## Consequences

**Positive**

- Audit records and permission changes can no longer be redirected through a
  symlink, and the process no longer chmods files it did not create.

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
