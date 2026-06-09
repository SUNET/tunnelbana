# ADR 0005 — MDQ-backed dynamic IdP metadata for the SAML2 backend

- **Status:** Accepted
- **Date:** 2026-06-09
- **Component:** `tunnelbana-plugins` — `saml2_backend.rs` (`IdpMetadata`,
  `build`, `start_auth`, `handle_acs`/`process_acs`, `build_mdq_client`,
  `idp_sso_redirect_url`, `idp_verifier_from_metadata`).
- **Related:** gamlastan
  [ADR 0002 — MDQ client](../../../saml/docs/adr/0002-mdq-metadata-query-client.md),
  [ADR 0003 — metadata accessors](../../../saml/docs/adr/0003-metadata-key-and-endpoint-accessors.md);
  [Writing a plugin](../src/writing-a-plugin.md)

## Context

The SAML2 backend (the proxy as an SP to an upstream IdP) pinned a **single**
IdP statically: `idp_entity_id` + `idp_sso_url` + `idp_cert_path` (a PEM file).
That is fine for a one-IdP deployment but does not fit a **federation**
(eduGAIN / SWAMID / …), where an SP talks to many IdPs and metadata rotates.
Federations publish per-entity metadata over the **Metadata Query Protocol
(MDQ)**, and `gamlastan-mdq` already implements a verifying, caching MDQ client.

Two things were needed to use it from the proxy: a config surface and the wiring
to resolve, **per request**, the IdP's SSO endpoint and signing certificate from
metadata instead of from static fields. A federation SP also rarely knows the
target IdP up front — the user picks it at a **discovery service** (e.g.
SeamlessAccess / thiss.io), which hands the chosen `entityID` back to the SP.

The generic metadata-extraction primitives this depends on (pull the
`<X509Certificate>` DER out of an opaque `KeyInfo`; find an SSO endpoint by
binding; collect signing certs) were added to **gamlastan**, not here — see its
ADR 0003. This crate only does the SP-side trust assembly and flow control.

## Decision

Introduce an `IdpMetadata` source the backend holds in place of the static
`idp_sso_url` + `verifier` fields:

```
enum IdpMetadata {
    Static { sso_url, verifier },   // pinned at build from idp_sso_url + idp_cert_path
    Mdq(MdqClient),                 // resolved per request, keyed by entityID
}
```

- **Config.** `idp_sso_url` and `idp_cert_path` become optional; an `[mdq]`
  sub-table selects MDQ mode: `url`, `signing_cert_path`, `transform`
  (`url_encoded` | `sha1`), `require_role` (default `idp`), `fallback_ttl_secs`,
  `allow_unverified`. Static mode still **requires** `idp_sso_url` +
  `idp_cert_path` and is otherwise unchanged.
- **MDQ trust is mandatory by default.** `build_mdq_client` requires a
  `signing_cert_path` (every fetched document is signature-verified by
  `gamlastan-mdq`) unless the operator explicitly sets `allow_unverified = true`
  (testing only). This mirrors gamlastan ADR 0002's "MDQ server is untrusted".
- **Per-request IdP selection.** In MDQ mode the target IdP is the request's
  `entityID` parameter (e.g. a discovery-service return), falling back to the
  configured `idp_entity_id` default. The chosen entityID is **persisted in flow
  state** (`set_str(name, "idp_entity_id", …)`) at `start_auth`.
- **Primary subject selection.** In MDQ mode the backend mirrors SATOSA's
  primary-identifier flow: if the operator configured `user_id_from_attrs`, that
  composed identifier is preferred as `subject_id`; otherwise a raw persistent
  SAML `NameID` fallback is **issuer-scoped** before it is exposed downstream.
  This avoids collisions when different IdPs mint the same persistent `NameID`.
- **AuthnRequest.** `start_auth` resolves the HTTP-Redirect SSO location for the
  selected IdP from its metadata (`idp_sso_redirect_url`) and sends there.
- **Response verification.** `handle_acs` reads the persisted entityID, fetches
  that IdP's metadata, builds a `SamlVerifier` from its signing certs
  (`idp_verifier_from_metadata` → `verifier_from_cert_ders`), and verifies the
  Response against it — **and** passes that entityID as the validator's
  `expected_idp_entity_id`.
- **Dependency wiring (interim).** `gamlastan` and the new `gamlastan-mdq` are
  consumed as **path deps** into `../saml/crates/*` during development so the
  ADR-0003 accessors are available before a release; to be bumped to published
  versions once gamlastan is re-released.

## Security boundaries

| Threat | Control | Residual risk |
|--------|---------|---------------|
| Untrusted MDQ server / CDN serves forged metadata | `gamlastan-mdq` verifies the federation signature against `signing_cert_path`; no cert ⇒ refuses unless `allow_unverified` | Operator opting into `allow_unverified` loses authenticity (testing only) |
| Attacker swaps the Response `Issuer` to an IdP it controls | Verifier is built for the **persisted, requested** entityID — not the Response's claimed issuer; validator's `expected_idp_entity_id` is that same value | None: a Response from an unexpected IdP fails verification/validation |
| Two IdPs issue the same persistent `NameID` | In MDQ mode the backend prefers a configured primary identifier from mapped attributes; if it must fall back to a raw persistent `NameID`, it scopes that value by the IdP issuer before exposing it downstream | Operators still need to choose a better user identifier when one is available (for example ePTID or a federation-specific stable identifier) |
| Discovery service returns an arbitrary `entityID` | The entityID is only ever resolved **through** the trusted, signature-verified MDQ source; an entity absent from the federation fails to resolve | Bounded by the federation's MDQ contents |
| Stale / rotated IdP keys | MDQ caches per `validUntil`/`cacheDuration` with `fallback_ttl_secs`; verification always uses freshly resolved metadata | Window bounded by cache TTL |

**Out of scope (assumed elsewhere):** TLS to the MDQ server (defence in depth,
not the authenticity anchor); the federation operator's signing-key custody;
SP key custody (unchanged from the static path).

## Consequences

**Positive**

- The SAML backend works in a federation: IdPs and their keys are resolved and
  rotated from MDQ with no redeploy, and discovery-driven `entityID` selection
  composes naturally.
- Generic SAML logic lives in gamlastan (ADR 0003); the proxy keeps only trust
  assembly and flow control. The static single-IdP path is unchanged.

**Negative / accepted trade-offs**

- An MDQ fetch happens on `start_auth` and on ACS (served from the client's
  cache after warm-up); a cold cache adds an outbound round-trip to the flow.
- MDQ uses `gamlastan-mdq`'s own reqwest transport, not the proxy's injected
  `HttpClient`. Accepted: MDQ is SAML-specific and its verifying/caching client
  is part of the SAML stack.
- **Full SP-initiated discovery is not yet built.** Today an `entityID` must
  *arrive on* the authorization request; redirecting the user *to* SeamlessAccess
  and handling the DS return on a dedicated backend endpoint
  (Identity Provider Discovery Service Protocol) is a follow-up that builds on
  the per-request entityID plumbing this ADR introduces.

## References

- `crates/tunnelbana-plugins/src/saml2_backend.rs` — `IdpMetadata`,
  `build_mdq_client`, `select_target_idp`, `idp_sso_redirect_url`,
  `idp_verifier_from_metadata`, `verifier_from_cert_ders`
- `config/proxy.toml` — SAML backend `(a) static` / `(b) MDQ` examples
- gamlastan ADR 0002 (MDQ client), ADR 0003 (metadata accessors)
- draft-young-md-query / -saml (MDQ); OASIS Identity Provider Discovery Service
  Protocol and Profile
