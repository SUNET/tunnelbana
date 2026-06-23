# Architecture Decision Records

Each ADR captures one significant decision: its context, the decision itself, the
security boundaries it establishes, and the consequences. ADRs are immutable once
accepted — supersede with a new record rather than editing history.

| # | Title | Status |
|---|-------|--------|
| [0001](0001-state-cookie-encryption.md) | Stateless encrypted state cookie | Accepted |
| [0002](0002-oidc-token-codec.md) | Stateless OIDC token codec (authorization codes & access tokens) | Accepted |
| [0003](0003-dpop-sender-constrained-tokens.md) | DPoP sender-constrained tokens (RFC 9449) | Accepted |
| [0004](0004-client-credentials-grant.md) | `client_credentials` grant | Accepted |
| [0005](0005-saml-mdq-dynamic-idp.md) | MDQ-backed dynamic IdP metadata for the SAML2 backend | Accepted |
| [0006](0006-saml-frontend-sp-metadata-store.md) | Registered SP metadata store + AuthnRequest validation in the SAML2 frontend | Accepted |
| [0007](0007-saml-discovery-service.md) | Identity-provider discovery service flow in the SAML2 backend | Accepted |
| [0008](0008-attribute-map-oids-and-passthrough.md) | OID-aware attribute map and unknown-attribute passthrough | Accepted |
| [0009](0009-saml-encrypted-assertions.md) | Encrypted assertions at the SAML2 backend (XML Encryption) | Accepted |
| [0010](0010-saml-unsolicited-fail-closed.md) | Fail-closed InResponseTo handling and `allow_unsolicited` | Accepted |
| [0011](0011-attribute-processor-microservice.md) | `attribute_processor` micro-service (regex value transforms) | Accepted |
| [0012](0012-attribute-authorization-microservice.md) | `attribute_authorization` micro-service (regex allow/deny) | Accepted |
| [0013](0013-microservice-framework-decorations.md) | Micro-service framework: target-entity and error-redirect decorations | Accepted |
| [0014](0014-filter-attributes-policy.md) | `filter_attributes` per-requester policy (`AttributePolicy`) | Accepted |
| [0015](0015-custom-routing-target-issuer.md) | `custom_routing` by target issuer (`DecideBackendByTargetIssuer`) | Accepted |
| [0016](0016-idp-hinting-microservice.md) | `idp_hinting` micro-service | Accepted |
| [0017](0017-filter-attribute-values-microservice.md) | `filter_attribute_values` micro-service | Accepted |
| [0018](0018-rename-attributes-microservice.md) | `rename_attributes` micro-service | Accepted |
| [0019](0019-attribute-generation-microservice.md) | `attribute_generation` micro-service (Tera templates) | Accepted |
| [0020](0020-attribute-processor-pack.md) | `attribute_processor` processor pack (hash, scope, gender) | Accepted |
| [0021](0021-hasher-microservice.md) | `hasher` micro-service | Accepted |
| [0022](0022-primary-identifier-microservice.md) | `primary_identifier` micro-service | Accepted |
| [0023](0023-custom-logging-microservice.md) | `custom_logging` micro-service (per-flow audit records) | Accepted |
| [0024](0024-openid-federation-backend.md) | OpenID Federation backend (federation-aware RP, automatic registration) | Accepted |
| [0025](0025-external-federation-discovery-service.md) | External discovery service for the federation backend (third-party initiated login) | Accepted |
| [0026](0026-oidc-refresh-token-grant.md) | OIDC `refresh_token` grant (stateless, rotated) | Accepted |
| [0027](0027-frontend-backend-pin.md) | Frontend-level backend pin (`backend = "<name>"`) | Accepted |
| [0028](0028-clients-file.md) | External client roster file (`clients_file`) | Accepted |
