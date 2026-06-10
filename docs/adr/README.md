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
