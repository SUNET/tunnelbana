# ADR 0023 - `custom_logging` micro-service (per-flow audit records)

- **Status:** Accepted
- **Date:** 2026-06-10
- **Component:** `tunnelbana-plugins` - `microservices/logging.rs`
  (`CustomLogging`, config type `custom_logging`).

## Context

Operations and federation compliance (e.g. SWAMID incident handling) want a
**per-authentication audit record** - who authenticated where, through which
SP, with which released identifier - in a machine-readable file that survives
log-level changes and is cheap to ship to SIEM tooling. tunnelbana only had
structured `tracing` output, which mixes audit events with operational noise
and changes shape with subscriber config. SATOSA covers this with
`CustomLoggingService`: JSON lines appended to a configured file, with a
configured attribute subset.

## Decision

Port it as a response-path service with deliberately boring semantics:

- Config: `log_target` (file path, required) and `attrs` (internal attribute
  names to include; default empty). One JSON object per completed
  authentication, one per line (JSONL):
  `timestamp` (the response's `auth_info.timestamp`, else now, RFC 3339),
  `sp` (requester), `idp` (issuer), `frontend`, `backend`, and `attr` - only
  the configured subset, only those present.
- **Unwritable `log_target` is a build-time error** (open-append is attempted
  at startup), surfacing path/permission mistakes at boot instead of as
  silently missing audit data.
- **Runtime write failures never fail the flow**: the record is dropped with
  a `tracing::error!`. Audit logging must not become an authentication
  denial-of-service when a disk fills (same trade-off SATOSA makes by
  swallowing exceptions).
- Synchronous append per response - no buffering, no rotation; rotation is
  logrotate-with-copytruncate territory, and the open-per-write keeps the
  service correct across rotations.

## Security boundaries

| Threat | Control | Residual risk |
|--------|---------|---------------|
| PII over-collection in audit logs | Only the explicitly configured `attrs` subset is recorded; nothing by default | Operators can still list sensitive attributes; data-protection review is theirs |
| Audit file tampering / disclosure | File creation uses the process umask; placement and permissions are deployment configuration | No built-in signing/forward-integrity - out of scope for a proxy-local file |
| Flow DoS via failing audit sink | Write failures log-and-continue | Records are *lost* in that window - monitor the error log; fail-closed auditing would need a different decision |
| Log injection via attribute values | Values are JSON-encoded by `serde_json`; newlines in values cannot break the JSONL framing | - |

## Consequences

**Positive**

- Stable, grep/jq-able audit trail per authentication, independent of
  `tracing` subscriber configuration; SATOSA `CustomLoggingService` configs
  port directly (`log_target`, `attrs`).
- Closes the "per-SP audit logging" item from the ops gap list.

**Negative / accepted trade-offs**

- Fail-open on write errors (availability over audit completeness),
  explicitly chosen and documented.
- No structured router/session fields from SATOSA's record (tunnelbana has
  no server-side session id by design - ADR 0001); `frontend`/`backend`
  names carry the routing context instead.

## References

- `crates/tunnelbana-plugins/src/microservices/logging.rs` - implementation +
  `writes_one_json_record_per_response`,
  `rejects_unwritable_target_at_build_time` tests
- `../SATOSA/src/satosa/micro_services/custom_logging.py` - ported behavior
