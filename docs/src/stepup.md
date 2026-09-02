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

## Compatibility modes

The service defaults to `behavior = "hardened"`. Set `behavior = "eduid"` to
match the policy branches and resulting `InternalData` of eduID-backend commit
`e0be0462eab2f013ca75a32959c9e7b0ae4edd4b`, `stepup.py` blob
`7537e8c11c03823362832a3c372d771fe6ed31aa`. Unknown values are rejected at
startup.

The eduID mode changes requester-policy replacement, metadata precedence,
initial-response rewriting, incomplete linked-account handling, attribute-map
selection, final LoA normalization, and duplicate assurance handling. For
valid output from the bundled `ScimAttributes` adapter, it is 100% compatible
with the reference policy and `InternalData` output behavior. It does not
weaken Tunnelbana's SAML validation, metadata trust, response correlation,
replay checks, passive-flow handling, or same-assertion provenance. It also
does not make Tunnelbana's native configuration and SAML XML byte-identical to
PySAML. See [ADR 0056](https://github.com/SUNET/tunnelbana/blob/main/docs/adr/0056-eduid-mfa-stepup.md)
for the exact contract and security substitutions.

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

The SAML keys are the same as the `saml2` backend. AuthnRequests must be signed,
unsolicited Responses are prohibited, and the test-only `permissive` security
preset is rejected. Step-up defaults to the interoperable `production` preset,
which validates signatures, Destination, Recipient, time, audience,
correlation, replay state, and `ds:Object`. `strict` remains available when the
deployment also requires encrypted assertions and its additional checks. For
one statically pinned step-up provider:

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
  behavior = "hardened" # use "eduid" for eduID policy/output compatibility
  sp_entity_id = "https://proxy.example.org/stepup/metadata"
  sp_key_path = "keys/stepup.key"
  sp_cert_path = "keys/stepup.crt"
  idp_entity_id = "https://accounts.example.org/idp"
  idp_sso_url = "https://accounts.example.org/sso"
  idp_cert_path = "keys/accounts-signing.crt"
  sign_authn_requests = true
  allow_unsolicited = false
  security = "production"

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
  behavior = "hardened"
  sp_entity_id = "https://proxy.example.org/stepup/metadata"
  sp_key_path = "keys/stepup.key"
  sp_cert_path = "keys/stepup.crt"
  sign_authn_requests = true
  security = "production"

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
MDQ metadata must be signature-verified; `mdq.allow_unverified` is rejected for
step-up even though the ordinary SAML backend retains that explicit test mode.

In the default hardened mode, `mfa` lookup is role-specific:

- the requesting SP's exact entity ID, then its trusted metadata entity
  categories, chooses the LoAs sent to the step-up provider;
- the initial IdP's exact entity ID, then its trusted metadata assurance
  certifications, can recognize and normalize an already satisfied LoA.

When several configured categories or certifications match, the first entry in
the TOML configuration wins. Metadata value order does not affect policy
priority.

In `behavior = "eduid"`, both roles use eduID's generic lookup: exact entity ID
wins, followed by entity categories and assurance certifications in trusted
metadata source order. A matched requester policy also replaces the effective
requester ACCRs with that policy's `requested` list.

For a static initial SAML backend, configure metadata-equivalent assurance
certifications and categories with `idp_assurance_certifications = ["..."]`
and `idp_entity_categories = ["..."]`. MDQ mode reads them from accepted
metadata. Entity-level extensions and only the first active SSO descriptor are
used, matching endpoint and certificate selection; later role descriptors
cannot affect policy.

This folds SATOSA's separate `AuthnContext` and
`RewriteAuthnContextClass` helpers into the step-up service. To reproduce
`StepupSAMLBackend`, step-up hands its policy to the selected SAML backend;
after resolving the initial IdP, a matching provider policy overrides the
ordinary `accr` target with its `requested` values and exact comparison. Keep
`accr` after `stepup` so it selects the ordinary fallback first and validates
the final value after a completed exchange.

## Runtime behavior and checks

In hardened mode, step-up is attempted only when the original requester
included `https://refeds.org/profile/mfa`. In eduID mode, a matched requester
policy's `requested` list determines that intent. A raw REFEDS MFA assertion is
not sufficient to bypass step-up: the initial provider must match trusted MFA
policy. Hardened mode accepts `requested`/`extra_accepted` with fallback
normalization; eduID mode bypasses only when `returned` is configured and
raises an authentication error when that policy rejects the assertion.

A missing linked account is an authentication failure in both modes. Hardened
and eduID modes also fail closed for an incomplete first account. This is a
deliberate security-envelope difference from the reference pass-through: the
bundled SCIM adapter does not emit this malformed shape, and accepting it can
bypass metadata-replaced MFA intent. When no explicit trusted requester policy
matches, the synthesized second exchange requests only REFEDS MFA, so a weaker
sibling ACCR cannot be normalized to MFA. Explicit provider LoA aliases remain
available through configured policies.
An `IsPassive` flow that would require the second browser interaction always
fails as interaction-required instead of silently dropping the passive
constraint.

The first eligible linked account is used, matching eduID. Tunnelbana sends its
identifier as an `unspecified` NameID and requests the configured LoAs with
`Comparison="exact"`. On return the ordinary SAML backend validator enforces
the signature, Response and assertion issuers, destination, audience, time,
request correlation and assertion replay checks. Step-up additionally requires:

- the validated issuer to equal the linked account's entity ID;
- the linked identifier to occur in the configured identifier attribute;
- the asserted AuthnContextClassRef to occur in `requested`.

For step-up, attributes are read only from the same assertion whose
AuthnStatement supplies the issuer, subject, and AuthnContextClassRef. Other
assertions in the Response cannot contribute the linked identifier or merged
assurance values.

Values from the linked account's assurance attribute are merged into the
original response through the normal SAML attribute map. Hardened mode removes
duplicates and normalizes a completed exchange to `returned`, the first
original requester LoA, or the asserted LoA. eduID mode preserves duplicate
assurances and returns the first effective requester LoA, falling back to the
asserted step-up LoA; its callback intentionally ignores `returned`, matching
the reference implementation.

The suspended response and decorations are kept only in the authenticated,
encrypted state cookie and consumed after a valid ACS response. A 32 KiB
uncompressed snapshot guard rejects extreme responses, while the global 4096
byte sealed-cookie limit remains authoritative; highly incompressible large
attribute sets can therefore fail the step-up redirect safely rather than
produce an unresumable flow.
The initial-provider policy is copied into discovery state only for an
effective MFA request. Tunnelbana rejects a configuration at startup when that
policy handoff exceeds its 1536-byte compressed budget, leaving cookie space
for the rest of the discovery flow.
The original frontend and backend selections are restored before later
response services run, so audit services observe the original authentication
flow rather than the embedded step-up micro-SP.
