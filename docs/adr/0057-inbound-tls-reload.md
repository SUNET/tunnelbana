# ADR 0057 - Optional inbound TLS with SIGHUP renewal

- **Status:** Accepted
- **Date:** 2026-09-23
- **Components:** `tunnelbana-core::config`, the `tunnelbana` binary, container health check.

## Context

The binary served plain HTTP and relied on a fronting reverse proxy for TLS.
Operators also need to supply a certificate/key pair directly and renew it
without stopping the server or interrupting authentication flows.

## Decision

- Add optional strict `[tls]` configuration with required `cert_path` and
  `key_path`, resolved relative to the main config file. Absence preserves HTTP.
  The existing bind setting selects the address for either mode.
- Use Actix's rustls 0.23 integration and the ring provider already used by
  outbound reqwest. Explicitly enable Actix runtime signal support required by
  its existing shutdown handler when the TLS dependency selects newer runtimes.
- Load a leaf-first PEM certificate chain and exactly one unencrypted supported
  private key, parse every certificate, and verify the leaf/key match before
  accepting connections. Invalid startup material is fatal.
- Share one `RwLock<Arc<CertifiedKey>>` resolver across all workers. Handshakes
  only clone the current identity under the read lock. On Unix SIGHUP, one
  serial loop loads a complete candidate on the blocking pool, then replaces
  the identity under a short write lock. Failures preserve the previous value.
- Keep paths absolute but do not canonicalize symlinks, so each renewal follows
  their current targets. The main TOML and other application state are not
  reloaded. HTTP-mode HUP is a logged no-op; non-Unix renewal needs a restart.
- Keep Actix's shutdown handling. Bound the HUP loop's lifetime to the server
  future, and fail startup if HUP registration fails. Avoid logging PEM parser
  diagnostics because they can contain input lines.
- Make the container curl health URL configurable while preserving verification
  and the existing HTTP default. Document local DNS/`--resolve` and private-CA
  requirements for direct HTTPS probes.

## Alternatives

Restarting or rebinding the server for every renewal would interrupt connections
and complicate port ownership. A shared certificate resolver changes just the
identity while retaining the listener and application state. A filesystem
watcher could observe a partially published pair; explicit HUP lets a renewal
tool signal when publication is complete. Keeping the old identity on a bad
reload preserves service while operators repair the files.

## Consequences and validation

Established connections remain open. New full handshakes obtain the new identity;
ordinary session resumption is unchanged. This is certificate renewal, not
emergency session revocation. Certificate expiry, hostname and chain trust are
client checks; loading does not assert public trust or prevent an operator from
installing an expired certificate. TLS versions/ciphers use rustls defaults,
and Actix configures HTTP/1.1 and HTTP/2 ALPN. ACME, mTLS, per-SNI identities,
encrypted private keys and dual listeners remain outside this feature.

Unit tests cover configuration, PEM/key checks, atomic replacement, failure
retention and symlink rotation. Process tests send real HUP signals, inspect
peer certificates before/after renewal, reuse an established connection,
exercise invalid replacements and HTTP mode, and verify SIGTERM shutdown.
