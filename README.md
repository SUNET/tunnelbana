# tunnelbana

A high-performance, SATOSA-like **identity proxy** in Rust. It translates between
identity protocols (OpenID Connect, OAuth 2.0, OpenID Federation, and — planned —
SAML 2.0) using a plugin architecture: a **frontend** speaks to downstream
relying parties / service providers, a **backend** speaks to upstream identity
/ OpenID providers, and the two are decoupled by a protocol-agnostic
`InternalData` model. Built on [`actix-web`](https://actix.rs), the local
[`jose-rs`](https://github.com/kushaldas/jose-rs) JOSE library, and (for SAML) the local
[`gamlastan`](https://github.com/kushaldas/gamlastan) library.

> tunnelbana = the Stockholm metro — it moves identities between lines.

## Why

[SATOSA](github.com/IdentityPython/SATOSA/) is a Python proxy that bridges
SAML2 ⇄ OIDC ⇄ OAuth2. This is a from-scratch Rust reimplementation aimed at
best performance, with TOML configuration, a **stateless** encrypted-cookie
session model (no shared store → trivial horizontal scaling), and first-class
**OpenID Federation 1.1** support so it can run the
[`satosa-federation`](https://github.com/SUNET/satosa-federation) deployment.

## The any-frontend × any-backend matrix

A frontend and a backend are independent plugins; the deployed behavior is chosen
purely by config + which plugins are loaded:

|                         | SAML2 frontend (IdP) | OIDC frontend (OP) |
| ----------------------- | -------------------- | ------------------ |
| **SAML2 backend (SP)**  | SAML → SAML          | OIDC → SAML        |
| **OIDC backend (RP)**   | SAML → OIDC          | OIDC → OIDC        |

…plus OpenID-Federation variants of the OIDC frontend/backend.

## Workspace

| Crate                | Role |
| -------------------- | ---- |
| `tunnelbana-core`    | Framework: `Context`, `InternalData`, encrypted state cookie, plugin traits + registry, router, proxy orchestrator, TOML config, attribute mapping, key loading (PEM **and** JWK), TTL/disk cache. |
| `tunnelbana-oidc`    | Reusable OAuth2 / OIDC / **OpenID Federation 1.0** protocol library on `jose-rs` — OP engine, RP flow, stateless tokens, PKCE, `private_key_jwt`, entity statements, trust-chain resolution, metadata policies. Independent of the proxy and of any web runtime. |
| `tunnelbana-plugins` | Concrete plugins: `oidc` frontend (OP), `oidc` backend (RP), `oidc_federation` frontend, `saml2` frontend (IdP) and backend (SP) via gamlastan, and micro-services (`static_attributes`, `filter_attributes`, `custom_routing`). |
| `tunnelbana`         | The actix-web binary: config loading, plugin instantiation, `reqwest`-backed HTTP client, request/response glue. |

## Design decisions

- **Stateless encrypted cookie** for flow state — sealed as a JWE (`dir` +
  `A256GCM`) under a key derived from `state_encryption_key`. No server-side
  session store.
- **Stateless OIDC tokens** — authorization codes and access tokens are
  confidential JWE tokens carrying their own state + expiry; id_tokens are signed
  JWTs. The token and userinfo endpoints do no server lookups.
- **Static compile-time plugin registry** — `Box<dyn Frontend/Backend/MicroService>`
  selected by a `type` string in config. No dynamic loading.
- **Async actix + `reqwest`**; synchronous JOSE/crypto called inline.
- **Keys** may be PEM/DER files **or** inline/file JWK(s); everything is
  normalized to a `jose_rs::Jwk` internally.

## What works today (not fully tested)

All four matrix cells are configurable (SAML↔SAML, SAML↔OIDC, OIDC↔SAML,
OIDC↔OIDC) plus the OpenID Federation OP — by config + plugin selection, no core
changes.

- OIDC **OP** (frontend): discovery, JWKS, authorization (code, with PKCE),
  token (`authorization_code`, `client_credentials`; `client_secret_basic`/`post`,
  `none`, **`private_key_jwt`**), userinfo, optional DPoP sender-constrained
  access tokens, stateless JWT tokens, attribute → claims mapping.
- OIDC **RP** (backend): discovery, auth request (state + nonce + PKCE), code
  exchange (incl. `private_key_jwt`), id_token verification, userinfo, claims →
  attribute mapping.
- **SAML2 SP** (backend): create + send AuthnRequest (HTTP-Redirect), static or
  MDQ-resolved IdP metadata, identity-provider **discovery service** flow
  (SeamlessAccess-style, `disco_srv`), ACS signature verification,
  **encrypted assertions / EncryptedID** (RSA-OAEP + AES-GCM/CBC, key
  rotation), gamlastan's 32-check `process_response` validation with
  configurable clock skew, fail-closed `InResponseTo` handling
  (`allow_unsolicited` opt-in), attribute mapping with optional
  unknown-attribute passthrough, SP metadata (organization/contact,
  encryption certs, DiscoveryResponse).
- **SAML2 IdP** (frontend): parse AuthnRequest (Redirect/POST), validate the
  requester + ACS against **registered SP metadata** (local files and/or MDQ;
  refuses to run open), redirect/POST **AuthnRequest signature verification**,
  NameIDPolicy honoring with per-response transient NameIDs and
  InvalidNameIDPolicy SAML errors, per-SP **attribute release policy**,
  OID/`uri` attribute name format, build a signed Assertion + Response, POST
  it back to the SP's ACS, IdP metadata (organization/contact, configured
  NameID formats, entity-id metadata endpoint).
- **OpenID Federation** frontend: serves its signed entity configuration,
  **auto-registers** unknown RPs by resolving them through a trust anchor's
  `federation_resolve_endpoint`, unpacks request objects (RFC 9101), accepts
  `private_key_jwt` (RFC 7523). Metadata-policy operators implemented.
- **Micro-services**: `static_attributes`, `filter_attributes` (response path),
  `custom_routing` (request path, backend selection by requester).
- The full proxy flow (route → state → dispatch → micro-services → state).

This project is being developed heavily. So, it will a few months to be tested
properly for all the paths.



Highlights: `tunnelbana-oidc/tests/op_flow.rs` (code+PKCE flow, id_token verify,
userinfo, `private_key_jwt` with audience checks);
`tunnelbana-plugins/tests/proxy_oidc_op.rs` (whole-proxy OIDC flow);
`federation_flow.rs` (entity config + auto-registration via a mocked trust
anchor + `private_key_jwt`); `saml_roundtrip.rs` (our IdP signs an assertion
with real RSA keys, our SP verifies + validates it, tampered Responses and
forged/unsigned AuthnRequests are rejected, NameID policies, release policies,
passthrough and clock skew); `saml_disco.rs` (whole-proxy SeamlessAccess-style
discovery flow with an in-test MDQ server); and `saml_encrypted.rs`
(encrypted assertions/EncryptedID, signature rules across the encryption
boundary, key rotation).


### Test coverage

```
cargo test            # workspace test suite, clippy clean
```
## Running

```bash
# Generate an EC P-256 signing key (SEC1 or PKCS#8 PEM both work):
mkdir -p keys
openssl ecparam -genkey -name prime256v1 -noout -out keys/op.key

# Edit config/proxy.toml (set base_url, state_encryption_key, client/backend).
TUNNELBANA_BIND=127.0.0.1:8080 cargo run -p tunnelbana -- config/proxy.toml
```

Then e.g. `GET http://127.0.0.1:8080/OIDC/.well-known/openid-configuration`.

## Configuration

A single `proxy.toml` with `[[frontend]]` / `[[backend]]` / `[[microservice]]`
tables, `${ENV}` interpolation, and an `include` directive per plugin. See
[`config/proxy.toml`](config/proxy.toml) and
[`config/attributes.toml`](config/attributes.toml).

## Roadmap

- HSM support
- **OpenID Federation backend** (RP): discovery page, trust-chain resolve of the
  upstream OP, signed request object, `private_key_jwt` token exchange (the OIDC
  RP backend already does the non-federation parts).
- More micro-services: consent (with UI), account linking, LDAP attribute store.
- Social OAuth2 backends (GitHub/Google/…).
- `tera`-rendered discovery/consent pages; disk-backed metadata cache with
  background refresh (the cache primitive exists in `tunnelbana-core::cache`).
