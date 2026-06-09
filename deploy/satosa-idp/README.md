# satosa-idp — tunnelbana deployment (SAML IdP → OpenID Federation OP)

A [tunnelbana](../../README.md) deployment that replaces the previous
SATOSA-based OP on the `realta.labb.sunet.se` lab. It is a federation-aware
**OpenID Provider** whose users are authenticated upstream against the SAML IdP
`samlidp.labb.sunet.se`.

Published at **https://satosa.labb.sunet.se** (entity_id is the bare host).

```
  Federation RP                tunnelbana OP (this)              SAML IdP
       │   OpenID Federation 1.1       ┌──────────────┐   SAML2 SP    │
       │   + OIDC ─────────────────────►│ oidc_federation│─────────────►│
       │   (trust-chain discovery,      │ frontend (OP)  │  (samlidp.   │
       │    private_key_jwt)            │ + saml2        │   labb...)   │
       │                                │ backend (SP)   │              │
```

* **Frontend** `oidc_federation` (name `OIDFed`): serves the entity
  configuration, auto-registers federation RPs by resolving them through the
  realta Trust Anchor, accepts request objects (RFC 9101) and `private_key_jwt`.
* **Backend** `saml2` (name `Saml2`): SAML SP to `samlidp.labb.sunet.se`; builds
  signed AuthnRequests (RSA-SHA256, HTTP-Redirect), ACS at `/Saml2/acs`.

## Live layout on realta.labb.sunet.se

| Thing | Value |
| ----- | ----- |
| Deploy dir | `~/tunnelbana-idp` (rsynced from this dir + vendored source) |
| Container | `tunnelbana-idp-tunnelbana-idp-1`, host `:8088` → container `:8080` |
| TLS / vhost | `/etc/caddy/conf.d/satosa.caddy` → `localhost:8088` |
| Entity config | `https://satosa.labb.sunet.se/.well-known/openid-federation` (Caddy rewrites to `/OIDFed/.well-known/openid-federation`) |
| OIDC endpoints | `https://satosa.labb.sunet.se/OIDFed/{authorization,token,userinfo,jwks}` |
| SP metadata | `https://satosa.labb.sunet.se/Saml2/metadata` (registered with samlidp via PUT `/services/satosa.labb.sunet.se`) |

### Keys (reused from the old SATOSA OP, in `keys/`)

* `federation_ec.key` — EC P-256, signs the entity configuration (`kid federation-key-1`).
  **This is the key the realta TA pins** in its subordinate statement for
  `https://satosa.labb.sunet.se`, so the entity_id had to stay the bare host.
* `oidc_signing.key` — RSA, signs id_tokens (RS256).
* `saml_backend.key` / `.crt` — SAML SP key/cert.
* `idp.crt` — samlidp signing cert (extracted from its metadata; verifies the SAML Response).

## Build & deploy (fast path — no Rust on the remote)

The binary is cross-built on the dev host inside a bookworm container so its
glibc matches `debian:bookworm-slim`; the remote only mounts it.

```bash
# 1. Build (cached target + host cargo registry):
./build.sh                        # -> .build-cache/target/release/tunnelbana

# 2. Ship the binary and restart (no rebuild):
rsync -a ../../.build-cache/target/release/tunnelbana \
      debian@realta.labb.sunet.se:~/tunnelbana-idp/bin/tunnelbana
ssh debian@realta.labb.sunet.se 'cd ~/tunnelbana-idp && docker compose restart'

# First-time / Dockerfile or config change:
ssh debian@realta.labb.sunet.se 'cd ~/tunnelbana-idp && docker compose up -d --build'
```

## Verified (non-interactive)

* Entity configuration served, ES256-signed, `iss`/`sub` = bare entity_id.
* realta TA lists `https://satosa.labb.sunet.se` as a subordinate and pins
  `federation-key-1`; `/resolve?sub=…&trust_anchor=…` returns our metadata with
  a 3-link trust chain (server-side chain validation passes).
* `GET /OIDFed/authorization` for federation RPs `satosarp` and `realrp`:
  auto-registers the RP via the TA, then **302 → `samlidp.labb.sunet.se/sso`**
  with a signed SAMLRequest.
