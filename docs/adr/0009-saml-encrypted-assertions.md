# ADR 0009 — Encrypted assertions at the SAML2 backend (XML Encryption)

- **Status:** Accepted
- **Date:** 2026-06-09
- **Component:** `tunnelbana-plugins` — `saml2_backend.rs`
  (`encryption_keypairs`, `decrypt_with_any`, `unwrap_decrypted_wrapper`,
  the restructured `process_acs`, encryption `KeyDescriptor`s).
- **Related:** [ADR 0006 — SP metadata store](0006-saml-frontend-sp-metadata-store.md)
  (collects SP encryption certs for the future IdP-side counterpart, F6);
  gamlastan `SamlDecryptor` / bergshamra `xenc`.

## Context

Many federation IdPs deliver `<saml2:EncryptedAssertion>` (and some
`<saml2:EncryptedID>`). The backend died with "missing or unsupported NameID"
on such responses. gamlastan already ships the XML Encryption machinery
(`SamlDecryptor` over bergshamra-enc: RSA-OAEP / RSA-1.5 key transport,
AES-CBC/GCM data decryption) and parses `EncryptedAssertion` blobs into
`response.encrypted_assertions` — the proxy never used them.

The hard part is the **signature acceptance rule**: the previous
"response or assertion signed" check ran `verify_enveloped` over the received
document, but an encrypted assertion's signature is *inside the ciphertext*
and can only be verified after decryption.

## Decision

- **Config.** `[[backend.config.encryption_keypairs]]` with `key_path` and
  optional `cert_path` (mirrors SATOSA). Multiple entries for rotation; every
  entry with a `cert_path` is published in SP metadata as a
  `use="encryption"` KeyDescriptor; omit `cert_path` for retired decrypt-only
  keys.
- **One decryptor per key.** bergshamra uses only the first RSA key of a
  `KeysManager`, so each keypair gets its own `SamlDecryptor`; decryption
  tries each in turn (`decrypt_with_any`).
- **Parse-then-verify restructure of `process_acs`:**
  1. parse the Response (nothing parsed is trusted yet);
  2. apply the signature rule (below);
  3. decrypt each `EncryptedAssertion` — error if any are present with no
     keypairs configured — and splice the assertions into the response;
  4. status check, the unchanged 32-check validation, extraction.
- **Signature rule spanning the encryption boundary** (supersedes the plain
  `want_assertions_or_response_signed` interpretation): accept iff
  - the Response envelope is signed and verifies on the received document
    (the envelope signature also covers the `EncryptedAssertion` ciphertext),
    **or**
  - *every* assertion — cleartext and decrypted alike — carries a signature
    that verifies on the XML it travelled in: the original document for
    cleartext assertions, the **decrypted plaintext** for encrypted ones.
- **In-place decryption unwrap.** The decryptor replaces `xenc:EncryptedData`
  inside the wrapper element, so the output's root is still
  `EncryptedAssertion`/`EncryptedID`; `unwrap_decrypted_wrapper` peels it off
  byte-verbatim, keeping the enveloped signature inside verifiable.
- **EncryptedID.** A `NameIdOrEncryptedId::EncryptedId` subject is decrypted
  with the same try-each path and parsed as a `NameID`.

## Security boundaries

| Threat | Control | Residual risk |
|--------|---------|---------------|
| Unsigned-content injection next to an encrypted assertion | Without a valid envelope signature, *every* assertion (cleartext and decrypted) must individually verify; one unsigned assertion rejects the response | — |
| Ciphertext tampering | AES-GCM authenticates; CBC modes lack integrity, but the signature rule still requires a verified signature over (or inside) the ciphertext | CBC + envelope-signature responses depend on the envelope signature, which covers the ciphertext — acceptable |
| Signature wrapping across the boundary | Decrypted assertion signatures are verified against the exact decrypted plaintext, not the outer document | bergshamra's dsig hardening (E91 ds:Object rejection etc.) applies per document |
| Key rotation downtime | try-each decryptors; old keys stay configured (decrypt-only, no published cert) until drained | — |
| Responses encrypted to a retired key after rotation window | Decryption fails with every key ⇒ rejected with a clear error | Operator-controlled rotation window |

**Known limitation (tracked):** an `EncryptedAssertionRef.raw` blob loses
namespace prefixes declared on *ancestor* elements of the original document
(same limitation as gamlastan's own swedenconnect `decrypt_response`). If a
real IdP's responses hit this, the fix belongs in gamlastan (re-serialize with
inherited namespace declarations).

## Consequences

**Positive**

- Encrypted assertions and EncryptedIDs work against federation IdPs, with
  key rotation and metadata publication handled.
- The signature rule is stricter than before for mixed responses: partially
  signed multi-assertion responses without an envelope signature are now
  rejected instead of sliding through on a single assertion's signature.

**Negative / accepted trade-offs**

- IdP-side assertion *encryption* (frontend, F6) is not built; the SP
  encryption certs collected per ADR 0006 are its prepared input.
- `verify_enveloped` is called per decrypted assertion — one extra dsig pass
  per assertion in the assertion-signed case.

## References

- `crates/tunnelbana-plugins/src/saml2_backend.rs`
- `crates/tunnelbana-plugins/tests/saml_encrypted.rs` — signed-envelope,
  signed-assertion, nothing-signed, no-keys, rotation, tampered ciphertext,
  EncryptedID, metadata KeyDescriptor
- xmlenc-core; SAML profiles 4.1.4.3
