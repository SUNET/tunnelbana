# Dependency security updates

Reviewed on 2026-09-23 using `cargo audit --deny warnings` and the resolved
dependency graph. This records targeted advisory remediation, not a general
upgrade of unrelated dependencies or RustCrypto trait generations.

| Dependency | Change | Result |
| --- | --- | --- |
| `rustls` | 0.23.43 -> 0.23.45; raise the manifest minimum | Fixes [RUSTSEC-2026-0285](https://rustsec.org/advisories/RUSTSEC-2026-0285.html) for inbound TLS and outbound requests |
| `rustls-webpki` | 0.103.13 -> 0.103.15 | Compatible update selected with rustls |
| `actix-web` | 4.14.0 -> 4.15.0; raise the manifest minimum | Includes the 4.14.1 graceful-shutdown fix; retains Rust 1.88 and existing HTTP/TLS features |
| `actix-server` | 2.6.0 -> 2.9.5 | Compatible update required by Actix Web's new `>=2.7, <3` constraint; removes the old socket2 0.5 dependency |
| `actix-http` | 3.13.1 -> 3.13.6 | Includes upstream WebSocket validation fixes; preserves HTTP/2 support |
| `chacha20` | 0.10.1 -> 0.10.2 | Removes the yanked version used through `rand` 0.10 |
| `rustls-pemfile` | Remove 2.2.0 | Replace the unmaintained wrapper with `rustls::pki_types::pem::PemObject`, as recommended by [RUSTSEC-2025-0134](https://rustsec.org/advisories/RUSTSEC-2025-0134.html) |
| `cryptoki` | Previously updated 0.12.0 -> 0.12.1 with Grindvakt integration | Fixes [RUSTSEC-2026-0286](https://rustsec.org/advisories/RUSTSEC-2026-0286.html) |

The PEM migration retains certificate-chain order, PKCS#1/PKCS#8/SEC1 key
support, exactly-one-key validation, certificate/key matching, sanitized errors,
and complete scanning for malformed trailing sections. Existing TLS config,
certificate files, SIGHUP renewal and HTTP/2 negotiation remain supported.

## Remaining advisories

- **[RUSTSEC-2026-0258](https://rustsec.org/advisories/RUSTSEC-2026-0258.html):**
  `tunnelbana -> actix-web 4.15.0 -> actix-http 3.13.6 -> h2 0.3.27`.
  Actix Web 4.15.0 requires `actix-http = "3.13.3"`; the resolved
  `actix-http` 3.13.6 still declares `h2 = "0.3.27"` and uses `http`
  0.2. The fixed h2 version is 0.4.16, outside that dependency constraint.
  An ordinary Cargo update cannot take it. Unblocking requires a patched h2 0.3
  release or an Actix release that adopts a fixed h2 line. Do not silently
  disable HTTP/2 or force incompatible dependency versions to hide the finding.
- **[RUSTSEC-2023-0071](https://rustsec.org/advisories/RUSTSEC-2023-0071.html):**
  `rsa` 0.9.10 is used directly and through the JOSE/XML cryptography stack.
  RustSec lists no patched release, including the 0.10 prerelease line.
  A major cryptographic dependency migration would not resolve this advisory.

The repository adds no advisory exceptions: the audit continues to fail on
these two findings and reports no unmaintained or yanked dependency warnings.
Recheck the constraints and advisory patch ranges when upstream releases land.

## Verification

- `cargo test --locked --workspace --all-features`: 419 passed, including TLS
  renewal process tests and the PEM parser compatibility regression.
- `cargo clippy --locked --workspace --all-targets --all-features -- -D warnings`:
  passed.
- `cargo fmt --all -- --check`, `git diff --check`, and the documentation book
  build: passed.
- `cargo audit --deny warnings`: fails only on the two advisories above; no
  dependency warnings or new advisory exceptions.
