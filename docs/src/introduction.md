# Introduction

**tunnelbana** is a high-performance identity proxy written in Rust. Like
[SATOSA](https://github.com/IdentityPython/SATOSA), it sits between identity
protocols and translates between them: a **frontend** speaks to downstream
relying parties / service providers, a **backend** speaks to upstream identity
/ OpenID providers, and the two are decoupled by a protocol-agnostic
`InternalData` model.

> tunnelbana = like the Stockholm metro - it carries identities between providers, connecting them with performance and ease of use.

It is built on [`actix-web`](https://actix.rs), the
[`jose-rs`](https://github.com/kushaldas/jose-rs) JOSE library, the
[`grindvakt`](https://crates.io/crates/grindvakt) OAuth2 / OIDC / OpenID
Federation library, and (for SAML) the
[`gamlastan`](https://github.com/kushaldas/gamlastan) library.

## The any-frontend × any-backend matrix

A frontend and a backend are independent plugins; the deployed behaviour is
chosen purely by configuration plus which plugins are loaded:

|                         | SAML2 frontend (IdP) | OIDC frontend (OP) |
| ----------------------- | -------------------- | ------------------ |
| **SAML2 backend (SP)**  | SAML → SAML          | OIDC → SAML        |
| **OIDC backend (RP)**   | SAML → OIDC          | OIDC → OIDC        |

…plus the **OpenID Federation** variants: a federation OP (the `oidc_federation`
frontend) and a federation RP (the `oidc_federation` backend) that registers
automatically through a trust anchor.

## What this book covers

1. [**Architecture**](architecture.md) - the request flow, the plugin traits,
   and how state is kept.
2. [**Configuration**](configuration.md) - every key of `proxy.toml`,
   `${ENV}` interpolation, `include` files, and key loading - followed by a
   [reference](built-in-plugins.md) for each built-in plugin, grouped into
   frontends, backends, and micro-services.
3. [**Attributes and transforms**](attributes.md) - how attributes pivot
   through internal names, the attribute map, subject-id composition, and the
   response-path transform pipeline (including the `email_verified` case).
4. [**Micro-services**](micro-services.md) - the in-the-middle plugins that
   reshape a flow, where they run on the request/response paths, and how to
   scope them to specific SPs and IdPs.
5. [**Security: the state cookie**](security-state-cookie.md) - the AEAD
   construction, freshness, key rotation, and the threat model.
6. [**Writing a plugin**](writing-a-plugin.md) - the plugin traits in depth,
   with the OpenID Federation frontend as a worked example.

Two end-to-end **tutorials** then wire real federations together:
[SAML and OIDC over a SWAMID SP backend](tutorial-saml-mdq.md), and
[a SAML IdP over an OpenID Federation RP backend with discovery](tutorial-oidc-federation.md).

## A 30-second example

```bash
# Generate an EC P-256 signing key:
mkdir -p keys
openssl ecparam -genkey -name prime256v1 -noout -out keys/op.key

# Run with a config file:
TUNNELBANA_BIND=127.0.0.1:8080 cargo run -p tunnelbana -- config/proxy.toml
```

```toml
# config/proxy.toml - a minimal OIDC OP fronting an upstream OIDC RP.
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
