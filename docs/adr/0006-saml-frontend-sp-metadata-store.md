# ADR 0006 — Registered SP metadata store + AuthnRequest validation in the SAML2 frontend

- **Status:** Accepted
- **Date:** 2026-06-09
- **Component:** `tunnelbana-plugins` — `saml2_frontend.rs` (`SpStore`, `SpEntry`,
  `load_local_metadata`, `RawQueryRequest`, `handle_sso`,
  `verify_authn_request_signature`), `saml_common.rs` (`MdqConfig`,
  `verifier_from_cert_ders`).
- **Related:** [ADR 0005 — MDQ dynamic IdP](0005-saml-mdq-dynamic-idp.md)
  (the backend-side counterpart and the shared MDQ client);
  gamlastan 0.3.0 `SpSsoDescriptor::signing_certificates_der()` /
  `encryption_certificates_der()`.

## Context

The SAML2 frontend (the proxy as an IdP to downstream SPs) called
`process_authn_request(&req, None)`: any unsigned AuthnRequest from **any**
issuer was accepted, and the **ACS URL was taken from the request itself**.
An attacker who knew the SSO URL could submit an AuthnRequest naming a victim
SP as `Issuer` and an attacker-controlled `AssertionConsumerServiceURL`, and
the proxy would deliver signed assertions for the victim's users to that URL.
SATOSA validates the requester and the ACS against registered SP metadata;
gamlastan's `process_authn_request` already does the same when given the SP's
`SpSsoDescriptor` — the proxy simply never passed one.

## Decision

The frontend **refuses to build** without a registered-SP metadata source.

- **Config.** `[frontend.config.metadata]` with `local = [files]` (each an
  `EntityDescriptor` or `EntitiesDescriptor`) and/or `[metadata.mdq]` (the
  shared `MdqConfig`, with `require_role` forced to `"sp"`). No `[metadata]`
  block and no escape hatch ⇒ **config error** naming the flag.
  `allow_unknown_sps = true` restores the legacy open behavior with a startup
  warning — explicitly insecure, testing only.
- **SP store.** `enum SpStore { AllowAll, Store { local, mdq } }`; local files
  are parsed and indexed at build time into `SpEntry { sp_sso,
  signing_certs_der, encryption_certs_der }`; entities not found locally are
  resolved via MDQ (`EntityNotFound` ⇒ unknown). An unknown SP gets a **403**,
  never an assertion.
- **ACS validation.** `process_authn_request(&req, Some(&entry.sp_sso))`
  activates gamlastan's existing endpoint resolution: a request URL not among
  the SP's registered `AssertionConsumerService`s is rejected
  (`AcsUrlMismatch`); index references and the metadata default are resolved
  from metadata.
- **Signature policy.** An AuthnRequest must be signed when the SP's metadata
  says `AuthnRequestsSigned="true"` **or** the frontend sets
  `want_authn_requests_signed = true` (also advertised in IdP metadata).
  Redirect binding: the SigAlg/Signature query parameters are verified over
  the **raw, still-percent-encoded** query string — a `RawQueryRequest`
  adapter feeds `gamlastan::bindings::redirect::redirect_decode` from
  `HttpRequestData.uri`, because the decoded query map would corrupt the
  signature input. POST binding: the enveloped XML signature is verified.
  Verifiers are built per SP from its metadata signing certs (each cert added
  as both verification key and trusted anchor).

## Security boundaries

| Threat | Control | Residual risk |
|--------|---------|---------------|
| Assertion exfiltration: attacker-chosen ACS URL | ACS resolved/validated against registered SP metadata; unknown SP ⇒ 403 | `allow_unknown_sps = true` reopens the hole (warned, testing only) |
| SP impersonation (forged `Issuer`) | Without a signature requirement an attacker can still *start* a flow as a known SP, but assertions only ever go to that SP's registered ACS | Phishing-style flows land at the real SP; enable signing requirements where the federation supports it |
| Forged signed requests | Signature verified against the SP's federation-registered certs (metadata signed/MDQ-verified per ADR 0005) | Compromised SP key — out of scope |
| Redirect-signature malleability via re-encoding | Signature input taken verbatim from the raw query string, never re-encoded | None known |
| Unparseable/missing KeyInfo in SP metadata | Empty cert list fails closed (`verifier_from_cert_ders` errors; request rejected when a signature is required) | — |

## Consequences

**Positive**

- The assertion-exfiltration hole is closed by default; deployments must
  explicitly opt into the open mode.
- Local metadata files and MDQ cover both small static deployments and
  federation-scale SP registration (SeamlessAccess-style).
- `SpEntry.encryption_certs_der` is already collected, giving the future
  IdP-side assertion-encryption feature (F6) its key source.

**Negative / accepted trade-offs**

- **Breaking config change:** existing frontends without `[metadata]` fail to
  start until configured (or explicitly opened). Deliberate — silent
  insecurity is worse.
- Local metadata files are read once at build; rotation requires a restart
  (SATOSA's `enable_metadata_reload` analog is future work). MDQ-sourced SPs
  rotate per the MDQ cache.

## References

- `crates/tunnelbana-plugins/src/saml2_frontend.rs`
- `crates/tunnelbana-plugins/tests/saml_roundtrip.rs` — unknown-SP 403, ACS
  mismatch, signed-redirect accept/tamper, unsigned-when-required, build matrix
- SAML profiles 4.1.4.1 (ACS verification); SATOSA `SAMLFrontend` metadata
  handling
