# Introduction

**tunnelbana** is a high-performance identity proxy written in Rust. Like
[SATOSA](https://github.com/IdentityPython/SATOSA), it sits between identity
protocols and translates between them: a **frontend** speaks to downstream
relying parties / service providers, a **backend** speaks to upstream identity
/ OpenID providers, and the two are decoupled by a protocol-agnostic
`InternalData` model.

> tunnelbana = the Stockholm metro — it moves identities between lines.

It is built on [`actix-web`](https://actix.rs), the
[`jose-rs`](https://github.com/kushaldas/jose-rs) JOSE library, and (for SAML)
the [`gamlastan`](https://github.com/kushaldas/gamlastan) library.

## The any-frontend × any-backend matrix

A frontend and a backend are independent plugins; the deployed behaviour is
chosen purely by configuration plus which plugins are loaded:

|                         | SAML2 frontend (IdP) | OIDC frontend (OP) |
| ----------------------- | -------------------- | ------------------ |
| **SAML2 backend (SP)**  | SAML → SAML          | OIDC → SAML        |
| **OIDC backend (RP)**   | SAML → OIDC          | OIDC → OIDC        |

…plus the **OpenID Federation** variant of the OIDC frontend (a federation OP).

## What this book covers

1. [**Architecture**](architecture.md) — the request flow, the plugin traits,
   and how state is kept.
2. [**Configuration**](configuration.md) — every key of `proxy.toml`, the
   attribute map, `${ENV}` interpolation, `include` files, and key loading —
   followed by a [reference](built-in-plugins.md) for each built-in plugin.
3. [**Writing a plugin**](writing-a-plugin.md) — the plugin traits in depth, and
   a guided tour of the OpenID Federation frontend as a worked example.

## A 30-second example

```bash
# Generate an EC P-256 signing key:
mkdir -p keys
openssl ecparam -genkey -name prime256v1 -noout -out keys/op.key

# Run with a config file:
TUNNELBANA_BIND=127.0.0.1:8080 cargo run -p tunnelbana -- config/proxy.toml
```

```toml
# config/proxy.toml — a minimal OIDC OP fronting an upstream OIDC RP.
base_url = "https://proxy.example.com"
state_encryption_key = "${TUNNELBANA_STATE_KEY}"
attributes = "config/attributes.toml"

[[frontend]]
type = "oidc"
name = "OIDC"
  [frontend.config]
  signing_key_path = "keys/op.key"
  signing_algorithm = "ES256"

[[backend]]
type = "oidc"
name = "Upstream"
  [backend.config]
  issuer = "https://accounts.upstream.example"
  client_id = "tunnelbana-rp"
  client_secret = "upstream-rp-secret"
  scope = "openid profile email"
```
