# Architecture Decision Records

Each ADR captures one significant decision: its context, the decision itself, the
security boundaries it establishes, and the consequences. ADRs are immutable once
accepted — supersede with a new record rather than editing history.

| # | Title | Status |
|---|-------|--------|
| [0001](0001-state-cookie-encryption.md) | Stateless encrypted state cookie | Superseded in part by [0033](0033-security-audit-hardening.md) |
| [0002](0002-oidc-token-codec.md) | Stateless OIDC token codec (authorization codes & access tokens) | Superseded in part by [0033](0033-security-audit-hardening.md), [0038](0038-per-frontend-token-sealing-keys.md) |
| [0003](0003-dpop-sender-constrained-tokens.md) | DPoP sender-constrained tokens (RFC 9449) | Accepted |
| [0004](0004-client-credentials-grant.md) | `client_credentials` grant | Accepted |
| [0005](0005-saml-mdq-dynamic-idp.md) | MDQ-backed dynamic IdP metadata for the SAML2 backend | Superseded in part by [0048](0048-saml-mdq-issuer-scoped-subject.md) |
| [0006](0006-saml-frontend-sp-metadata-store.md) | Registered SP metadata store + AuthnRequest validation in the SAML2 frontend | Superseded in part by [0033](0033-security-audit-hardening.md) |
| [0007](0007-saml-discovery-service.md) | Identity-provider discovery service flow in the SAML2 backend | Accepted |
| [0008](0008-attribute-map-oids-and-passthrough.md) | OID-aware attribute map and unknown-attribute passthrough | Superseded in part by [0047](0047-saml-passthrough-internal-name-collision.md) |
| [0009](0009-saml-encrypted-assertions.md) | Encrypted assertions at the SAML2 backend (XML Encryption) | Superseded in part by [0033](0033-security-audit-hardening.md) |
| [0010](0010-saml-unsolicited-fail-closed.md) | Fail-closed InResponseTo handling and `allow_unsolicited` | Accepted |
| [0011](0011-attribute-processor-microservice.md) | `attribute_processor` micro-service (regex value transforms) | Accepted |
| [0012](0012-attribute-authorization-microservice.md) | `attribute_authorization` micro-service (regex allow/deny) | Accepted |
| [0013](0013-microservice-framework-decorations.md) | Micro-service framework: target-entity and error-redirect decorations | Accepted |
| [0014](0014-filter-attributes-policy.md) | `filter_attributes` per-requester policy (`AttributePolicy`) | Superseded in part by [0033](0033-security-audit-hardening.md) |
| [0015](0015-custom-routing-target-issuer.md) | `custom_routing` by target issuer (`DecideBackendByTargetIssuer`) | Superseded in part by [0033](0033-security-audit-hardening.md) |
| [0016](0016-idp-hinting-microservice.md) | `idp_hinting` micro-service | Accepted |
| [0017](0017-filter-attribute-values-microservice.md) | `filter_attribute_values` micro-service | Accepted |
| [0018](0018-rename-attributes-microservice.md) | `rename_attributes` micro-service | Accepted |
| [0019](0019-attribute-generation-microservice.md) | `attribute_generation` micro-service (Tera templates) | Accepted |
| [0020](0020-attribute-processor-pack.md) | `attribute_processor` processor pack (hash, scope, gender) | Superseded in part by [0033](0033-security-audit-hardening.md) |
| [0021](0021-hasher-microservice.md) | `hasher` micro-service | Superseded in part by [0034](0034-hasher-rejects-empty-requester-salt.md) |
| [0022](0022-primary-identifier-microservice.md) | `primary_identifier` micro-service | Superseded in part by [0033](0033-security-audit-hardening.md) |
| [0023](0023-custom-logging-microservice.md) | `custom_logging` micro-service (per-flow audit records) | Superseded in part by [0033](0033-security-audit-hardening.md), [0036](0036-custom-logging-nofollow-audit-log.md) |
| [0024](0024-openid-federation-backend.md) | OpenID Federation backend (federation-aware RP, automatic registration) | Superseded in part by [0033](0033-security-audit-hardening.md), [0042](0042-federation-resolution-hardening.md) |
| [0025](0025-external-federation-discovery-service.md) | External discovery service for the federation backend (third-party initiated login) | Accepted |
| [0026](0026-oidc-refresh-token-grant.md) | OIDC `refresh_token` grant (stateless, rotated) | Superseded in part by [0033](0033-security-audit-hardening.md) |
| [0027](0027-frontend-backend-pin.md) | Frontend-level backend pin (`backend = "<name>"`) | Accepted |
| [0028](0028-clients-file.md) | External client roster file (`clients_file`) | Superseded in part by [0040](0040-inline-clients-unknown-fields.md) |
| [0029](0029-router-exact-match-dispatch.md) | O(1) router dispatch (exact-match map + regex fallback) | Accepted |
| [0030](0030-eduid-scimapi-microservices.md) | eduID `scimapi` micro-services (`pairwiseid`, `static_attributes_for_virtual_idp`, `nameid`, `accr`) | Superseded in part by [0033](0033-security-audit-hardening.md), [0035](0035-pairwiseid-injective-hmac-framing.md) |
| [0031](0031-custom-index-page.md) | Configurable index page (`index_html`, with built-in default) | Accepted |
| [0032](0032-legacy-identifier-compatibility.md) | Legacy identifier compatibility modes | Accepted |
| [0033](0033-security-audit-hardening.md) | Fail-closed security boundaries for tunnelbana 0.3.0 | Accepted |
| [0037](0037-config-cookie-http-hardening.md) | Configuration, state-cookie, and HTTP-client hardening | Accepted |
| [0038](0038-per-frontend-token-sealing-keys.md) | Per-frontend token sealing and DPoP nonce keys | Accepted |
| [0039](0039-dpop-replay-store-bounds.md) | DPoP replay store rejects zero max age and over-long `jti` | Accepted |
| [0040](0040-inline-clients-unknown-fields.md) | Inline `clients` reject unknown fields like `clients_file` | Accepted |
| [0041](0041-oidc-backend-nonce-issuer-https.md) | OIDC backend: mandatory nonce check, explicit issuer, https endpoints | Accepted |
| [0042](0042-federation-resolution-hardening.md) | Federation trust-resolution hardening: https endpoints and negative caching | Accepted |
| [0047](0047-saml-passthrough-internal-name-collision.md) | SAML passthrough attributes must never collide with internal names | Accepted |
| [0048](0048-saml-mdq-issuer-scoped-subject.md) | Issuer-scoped subject identifiers in MDQ federation mode | Accepted |
| [0049](0049-force-authn-is-passive-propagation.md) | Propagating ForceAuthn/IsPassive through the proxy | Accepted |
| [0050](0050-saml-backend-security-preset-fail-closed.md) | Fail-closed `security` preset in the SAML2 backend | Accepted |
| [0051](0051-saml-frontend-sanitized-rejections.md) | Sanitized rejection output in the SAML2 frontend | Accepted |
| [0052](0052-embedded-cpython-microservices.md) | Embedded CPython micro-services | Accepted |
| [0053](0053-disco-to-target-issuer-flow-resume.md) | `disco_to_target_issuer` and flow-resuming micro-service endpoints | Accepted |
| [0054](0054-state-cookie-deflate-compression.md) | Deflate compression inside the sealed state cookie | Accepted |
