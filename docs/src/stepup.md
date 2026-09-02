# eduID MFA step-up

The built-in `stepup` micro-service is the Tunnelbana equivalent of eduID's
SATOSA `StepUp` response service. When a downstream SP requests REFEDS MFA but
the initial IdP response does not satisfy it, the service uses the linked
account published by `ScimAttributes` to perform a second, subject-bound SAML
authentication.

SCIM access remains optional Python code. The step-up SAML exchange is native
Rust because it owns HTTP endpoints, encrypted flow state, request signing,
metadata trust, response correlation, signature/time/audience validation, and
replay protection. A deployment that does not configure `ScimAttributes` or
`stepup` imports no eduID Python package.

## Required ordering

List the services in this order:

1. Python `ScimAttributes`, which publishes `mfa_stepup_accounts` on the
   response path.
2. `stepup`, which captures the original request on the request path and can
   interrupt/resume the response path.
3. `accr`, when used, so it validates the final normalized LoA after step-up.

The order is important because Tunnelbana runs both request and response
micro-services in configuration order.

## Configuration

The SAML keys are the same as the `saml2` backend. AuthnRequests must be signed
and unsolicited Responses are prohibited. For one statically pinned step-up
provider:

```toml
[[microservice]]
type = "python"
name = "ScimAttributes"
  [microservice.config]
  module = "tunnelbana_scimapi.scim_attributes"
  class = "ScimAttributes"
  pass_internal_attributes = true
  # [microservice.config.settings] ... see the SCIM chapter

[[microservice]]
type = "stepup"
name = "stepup"
  [microservice.config]
  sp_entity_id = "https://proxy.example.org/stepup/metadata"
  sp_key_path = "keys/stepup.key"
  sp_cert_path = "keys/stepup.crt"
  idp_entity_id = "https://accounts.example.org/idp"
  idp_sso_url = "https://accounts.example.org/sso"
  idp_cert_path = "keys/accounts-signing.crt"
  sign_authn_requests = true
  allow_unsolicited = false
  security = "strict"

  [microservice.config.mfa.by_entity_id."https://service.example.org/sp"]
  requested = ["https://refeds.org/profile/mfa"]
  extra_accepted = []
  returned = "https://refeds.org/profile/mfa"

[[microservice]]
type = "accr"
name = "accr"
  [microservice.config]
  supported_accr_sorted_by_prio = ["https://refeds.org/profile/mfa"]
```

For several linked-account providers, use trusted MDQ metadata instead of a
static IdP. The SCIM adapter's `mfa_stepup_issuer_to_entity_id` mapping remains
the allowlist that turns database issuer values into entity IDs; MDQ then
resolves and verifies the selected entity's SSO endpoint and signing keys.

```toml
[[microservice]]
type = "stepup"
name = "stepup"
  [microservice.config]
  sp_entity_id = "https://proxy.example.org/stepup/metadata"
  sp_key_path = "keys/stepup.key"
  sp_cert_path = "keys/stepup.crt"
  sign_authn_requests = true
  security = "strict"

  [microservice.config.mdq]
  url = "https://mdq.example.org/entities/"
  signing_cert_path = "keys/mdq-signer.crt"
  transform = "sha1"
  require_role = "idp"

  [microservice.config.mfa.by_entity_category."https://example.org/category/mfa-service"]
  requested = ["https://refeds.org/profile/mfa"]
  returned = "https://refeds.org/profile/mfa"
```

The service exposes its ACS at `<base_url>/<name>/acs` and metadata at
`<base_url>/<name>/metadata`. Register that metadata with every step-up IdP.
`disco_srv` is not accepted: the linked account selects the provider.

The `mfa` lookup follows the eduID precedence relevant to each leg:

- the requesting SP's exact entity ID, then its trusted metadata entity
  categories, chooses the LoAs sent to the step-up provider;
- the initial IdP's exact entity ID, then its trusted metadata assurance
  certifications, can recognize and normalize an already satisfied LoA.

For a static initial SAML backend, configure metadata-equivalent assurance
certifications with `idp_assurance_certifications = ["..."]`. MDQ mode reads
them from accepted metadata.

This folds SATOSA's separate `AuthnContext` and
`RewriteAuthnContextClass` helpers into the step-up service. Tunnelbana's
existing `accr` service and SAML backend provide the initial AuthnContext
forwarding/validation performed by eduID's `StepupSAMLBackend`; keep `accr`
after `stepup` so a completed second exchange is the value it validates.

## Runtime behavior and checks

Step-up is attempted only when the original requester included
`https://refeds.org/profile/mfa`. An already asserted REFEDS MFA value, or an
initial-provider LoA accepted by `requested`/`extra_accepted`, passes without a
second exchange. Otherwise a missing or malformed linked account fails closed.
An `IsPassive` flow that would require the second browser interaction fails as
interaction-required instead of silently dropping the passive constraint.

The first eligible linked account is used, matching eduID. Tunnelbana sends its
identifier as an `unspecified` NameID and requests the configured LoAs with
`Comparison="exact"`. On return the ordinary SAML backend validator enforces
the signature, issuer, destination, audience, time, request correlation and
assertion replay checks. Step-up additionally requires:

- the validated issuer to equal the linked account's entity ID;
- the linked identifier to occur in the configured identifier attribute;
- the asserted AuthnContextClassRef to occur in `requested`.

Values from the linked account's assurance attribute are merged into the
original response through the normal SAML attribute map. `returned`, when set,
is the downstream LoA; otherwise the first originally requested LoA is used.

The suspended response and decorations are kept only in the authenticated,
encrypted state cookie and consumed after a valid ACS response. A 32 KiB
uncompressed snapshot guard rejects extreme responses, while the global 4096
byte sealed-cookie limit remains authoritative; highly incompressible large
attribute sets can therefore fail the step-up redirect safely rather than
produce an unresumable flow.
