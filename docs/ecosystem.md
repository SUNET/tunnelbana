# Dependency ecosystem status

Last reviewed: 2026-11-10. Scope: the Rust workspace, including development
dependencies and the resolved transitive graph. Versions were checked with
`cargo outdated --workspace --depth 1` and the crates.io release API; the API
check also covers exact pins and unused workspace dependency declarations.

## Updated stack

| Dependency | Previous | Updated |
| --- | --- | --- |
| grindvakt | 0.10.0 | 0.11.0 |
| jose-rs | 0.10.0 | 0.11.0 |
| gamlastan / gamlastan-mdq | 0.9.1 | 0.11.0 |
| bergshamra and its component crates | 0.9.2 | 0.12.0 |
| uppsala | 0.10.1 | 0.12.1 |
| kryptering | 0.6.0 and 0.7.0 | 0.7.1 |
| rsa | 0.9.10 and 0.10.0-rc.19 | 0.10.0 |
| crypto-bigint | 0.5.5 and 0.7.5 | 0.7.11 |
| actix-web / actix-http | 4.15.0 / 3.18.12 | 4.19.0 / 3.21.0 |
| toml | 1.1.6 | 1.2.1 |
| pyo3 (including build-config / ffi) | 0.29.2 | 0.30.1 |

`sfw cargo update` also refreshed compatible transitive releases, including
Tokio 1.54.1, serde_json 1.0.154, rustls-webpki 0.103.16, aws-lc-rs 1.19.0,
and their supporting crates. Rustls remains at the already-resolved 0.23.46;
its manifest minimum now reflects that version. Actix RT's manifest minimum
likewise reflects the already-resolved 2.15.0. Bergshamra and Uppsala are selected
through Gamlastan, without adding artificial direct dependencies.
The lockfile changes 146 crate-name/version sets and contains 494 package
entries, down from 499 before the refresh.

## RustCrypto migration

The workspace now uses SHA-2 0.11, MD5 0.11 and HKDF 0.13 together. The upgraded
JOSE/SAML consumers accept the corresponding digest/signature/RNG generation:

| Consumer | Verified dependency requirements |
| --- | --- |
| grindvakt 0.11.0 | sha2 0.11, hkdf 0.13, rsa 0.10, p256/p384 0.14 |
| jose-rs 0.11.0 | sha2 0.11, rsa 0.10, p256/p384 0.14, ed25519-dalek 3 |
| kryptering 0.7.1 | sha2 0.11, hkdf 0.13, rsa 0.10, signature 3 |
| gamlastan 0.11.0 | bergshamra 0.12.0, uppsala 0.12.1 |

Requirements were inspected in the published registry manifests before the
coordinated bump. No local crypto patch or path override is used. Some older crypto
traits remain transitively through Bergshamra's legacy key-format support;
they do not force the workspace's hashing/KDF code onto the older generation.

## Retained versions

| Dependency | Retained | Newer release | Reason / unblock condition |
| --- | --- | --- | --- |
| tera | 1.20.1 | 2.4.0 | Tera 2 removes syntax/filters supported by deployed templates. Upgrade requires an explicit template compatibility migration. |
| pythonize | =0.29.0, vendored | None | Published source with PyO3 requirements updated to 0.30.1; remove the patch when upstream supports PyO3 0.30. |
| libc | 0.2.191 | 1.0.0-alpha.5 | Stable release retained; no alpha adoption for this maintenance update. |

## PyO3 0.30.1

PyO3, pyo3-ffi and pyo3-build-config now resolve to 0.30.1. Pythonize's
published 0.29.0 release and upstream branch still require PyO3 0.29, so the
workspace selects the released Pythonize source from `vendor/pythonize` with
its normal and development PyO3 requirements changed to 0.30.1. The source,
upstream tests and MIT license are retained unchanged. The patch preserves
arbitrary-precision JSON handling and avoids linking two PyO3 FFI versions.
See [the compatibility patch notes](../vendor/pythonize/TUNNELBANA.md) for
provenance, test commands and removal instructions.

## Security audit

The update removes the versions affected by RUSTSEC-2026-0387 (crypto-bigint)
and RUSTSEC-2023-0071 (RSA). One existing advisory remains:

`tunnelbana -> actix-web 4.19.0 -> actix-http 3.21.0 -> h2 0.3.27`
is affected by RUSTSEC-2026-0258. Actix HTTP still requires h2 0.3.27;
the fixed h2 0.4.16+ line cannot satisfy that constraint. A fixed 0.3 release
or an upstream Actix migration is required. HTTP/2 has not been disabled and
no advisory exception has been added.

## Verification

The digest migration uses `hex::encode` instead of the removed digest-array
`LowerHex` implementation; existing identifier/hash outputs stay lowercase
hexadecimal. SAML request adapters populate Gamlastan's added policy fields,
and SAML responses supply the upstream issuer as an authenticating authority.

Validated on 2026-11-10:

- `cargo build --locked --workspace --all-features`: passed.
- `cargo test --locked --workspace --all-features`: 428 passed, none failed
  or ignored, including TLS renewal, OIDC/federation, post-quantum signing,
  SAML signatures/encryption and embedded Python integration.
- `cargo test --manifest-path vendor/pythonize/Cargo.toml --all-features --target-dir target`:
  95 upstream tests (including documentation) passed on PyO3 0.30.1.
- `cargo clippy --locked --workspace --all-targets --all-features -- -D warnings`:
  passed.
- `cargo +1.89.0 check --locked --workspace --all-targets --all-features`:
  passed with an isolated target directory; the declared minimum is retained.
- `cargo fmt --all -- --check` and `git diff --check`: passed.
- `cargo audit --no-fetch --deny warnings`: fails solely on the existing h2
  advisory above; no advisory exceptions were added.

`sfw` was used for Cargo dependency updates and downloads. An initial audit
refresh also encountered an SFW network timeout; the final audit used the
already-fetched advisory database (1,430 advisories). No package-policy
rejections were bypassed.
