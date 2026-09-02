# ADR 0056 - Native SAML response suspension for eduID MFA step-up

- **Status:** Accepted
- **Date:** 2026-09-02
- **Components:** `tunnelbana-core::plugin`, `tunnelbana-core::proxy`,
  `tunnelbana-plugins::microservices::stepup`, the reusable SAML2 backend, and
  trusted requester/provider metadata decorations.
- **Related:** [ADR 0030](0030-eduid-scimapi-microservices.md),
  [ADR 0053](0053-disco-to-target-issuer-flow-resume.md), and
  [ADR 0055](0055-eduid-scim-attributes-python-adapter.md).

## Context

eduID's SATOSA `stepup.py` interrupts a validated upstream response, acts as a
small SAML SP towards a linked-account provider, and resumes the original
response chain from an ACS. The merged SCIM adapter already publishes eligible
linked accounts as JSON, but Tunnelbana supported only transformation-only
response services and request-side endpoint resumption.

The compatibility reference is `SUNET/eduid-backend` commit
`e0be0462eab2f013ca75a32959c9e7b0ae4edd4b`, specifically `stepup.py` blob
`7537e8c11c03823362832a3c372d771fe6ed31aa`. Compatibility is evaluated
against the policy branches and resulting SATOSA `InternalData` in that file,
not against incidental PySAML XML serialization.

Running the complete SATOSA class through embedded Python would expose live
protocol/state objects across the deliberately JSON-only boundary and duplicate
the native SAML trust implementation. Python also cannot register endpoints or
return arbitrary HTTP challenges through that boundary.

## Decision

- Keep eduID database integration in the optional Python `ScimAttributes`
  adapter. Add a native `stepup` micro-service that consumes only its
  first-writer-wins `mfa_stepup_accounts` decoration.
- Extend the core with `MicroServiceResponseAction::{Continue, Respond}` and
  `MicroServiceAction::ResumeResponse`. Existing transform-only services keep
  implementing `process_response`; its default action wrapper is source
  compatible. A resumed response runs only services after the endpoint owner
  and is then rendered by the original frontend.
- Reuse `Saml2Backend` internally as the micro-SP rather than maintaining a
  second ACS parser. Give the embedded instance a separate state namespace,
  require signed AuthnRequests, disable unsolicited Responses and include the
  linked identifier as an unspecified Subject NameID.
- Default the embedded backend to gamlastan's secure, interoperable production
  validation policy and reject the test-only permissive policy. Keep strict as
  an explicit high-security option.
- In MDQ mode, select the target solely from the SCIM-derived linked account;
  an `entityID` query parameter on the initial ACS request cannot override it.
  Static mode requires that account entity ID to equal the pinned IdP before
  the identifier is disclosed in a redirect.
- Require signature-verified MDQ metadata for step-up; reject the ordinary
  backend's explicit `allow_unverified` test escape hatch.
- Add `behavior = "hardened" | "eduid"`, defaulting to `hardened`; unknown
  values fail startup. The mode is saved with each request so a callback cannot
  be evaluated under different semantics.
- Save original and effective requester ACCRs plus trusted requester metadata
  categories/certifications on the request path. In `eduid` mode, a matched
  requester policy replaces the effective ACCRs with its `requested` list.
- Hand the selected behavior, effective MFA intent, and provider policy to the
  ordinary SAML backend. After resolving the initial IdP and its trusted
  metadata, provider-specific `requested` values override `accr` with exact
  comparison. This is the native equivalent of `StepupSAMLBackend.authn_request`.
- Associate policy metadata with the same first SSO descriptor used for the
  endpoint and verifier. Entity-level values remain valid; later role
  descriptors cannot influence the selected role's policy.
- On the callback, require normal SAML validation plus exact linked provider,
  exact requested step-up LoA and presence of the linked identifier in its
  configured assertion attribute. Bind identifier and assurance extraction to
  the same assertion whose AuthnStatement supplies the issuer, subject, and
  LoA; never aggregate step-up identity values across assertions. Merge only
  the configured assurance attribute, normalize the returned LoA, restore the
  original decorations and consume the snapshot before resuming.
- Reject a required step-up on an `IsPassive` flow as interaction-required;
  never turn a passive request into an interactive redirect.
- Store the response snapshot in the existing encrypted state cookie, with a
  32 KiB plaintext guard in addition to the global 4096-byte sealed cookie
  limit. Do not add a process-local pending-flow store, so any replica holding
  the state key can resume the flow.
- Publish the provider policy handoff only for an effective MFA request and
  reject configuration whose DEFLATE-compressed handoff exceeds 1536 bytes.
  This reserves cookie space for discovery flow state and turns an otherwise
  request-time discovery failure into a clear startup error.
- Snapshot and restore both `target_frontend` and `target_backend` before
  resuming later response services, together with the original decorations.

## Compatibility contract

`behavior = "eduid"` is **100% compatible with eduID `stepup.py` policy and
output behavior** inside the supported Tunnelbana protocol envelope. For
valid output from the bundled `ScimAttributes` adapter, the same trusted
metadata and `InternalData` inputs select the same LoA policy, take the same
pass-through/error/step-up branch, and produce the same downstream
AuthnContextClassRef and assurance-value ordering. The security substitutions
listed below define the boundary of that promise.

`behavior = "hardened"` remains the default for existing configurations:

| Observable behavior | `hardened` | `eduid` |
|---|---|---|
| Requester MFA intent | Original requester ACCRs | A matched requester policy replaces them with `requested`; otherwise original ACCRs |
| Metadata lookup | Exact entity, then requester category/provider certification in configuration order | Exact entity, then category, then assurance certification in metadata source order for either role |
| Accepted initial-provider LoA | `requested` or `extra_accepted` bypasses; normalize to `returned`, first original requester LoA, then asserted LoA | Bypass only when `returned` exists; rewrite exactly to `returned` |
| Rejected initial-provider LoA | Continue to the second exchange | A matching policy with `returned` causes an authentication error |
| Matching policy without `returned` | May bypass through fallback normalization | Does not bypass; continue to the second exchange |
| Incomplete first linked account | Fail closed | Fail closed (security-envelope substitution for the reference pass-through) |
| Attribute-map ambiguity | Reject | Use the first mapping returned by the configured mapper |
| Completed downstream LoA | `returned`, first original requester LoA, then asserted LoA | First effective requester LoA, then asserted LoA; ignore `returned` |
| Assurance merge | Preserve order and remove duplicates | Append in order, including duplicates |

In both modes, a raw REFEDS MFA assertion does not bypass step-up without a
matching trusted initial-provider policy. eduID performs that bypass only after
`RewriteAuthnContextClass` records a successful policy rewrite.

The following are deliberate native/security substitutions and are not
relaxed by `behavior = "eduid"`:

- production or strict SAML/XML validation, signed AuthnRequests, trusted MDQ,
  response and assertion issuer binding, correlation and replay checks;
- same-assertion provenance for the subject, LoA, linked identifier, and
  assurance values, plus rejection of interactive work for passive requests;
- rejection of incomplete linked-account records. The reference passes through
  empty entity IDs or identifiers, but the bundled SCIM adapter does not emit
  that shape and accepting it can bypass metadata-replaced MFA intent;
- when no explicit trusted requester policy matches, the synthesized second
  exchange requests only REFEDS MFA instead of forwarding weaker sibling ACCRs.
  Explicit provider LoA aliases remain supported through configured policies;
- encrypted portable state and Tunnelbana's state-size limits instead of a
  process-local `outstanding_queries` map;
- the JSON SCIM decoration rather than a live Python `ScimAttributes` object;
- Tunnelbana configuration keys, one `/acs` accepting both response bindings,
  Redirect AuthnRequest initiation, and native XML IDs/timestamps/order and
  error/log messages.

Consequently, “100% compatible” does not mean byte-identical XML, copy-paste
compatibility with eduID's nested `sp_config`, or reproduction of weaker SAML
validation. It is an explicit policy and `InternalData` compatibility promise.

### Parity matrix

| eduID behavior | Tunnelbana regression coverage |
|---|---|
| `AuthnContext.process` requester-policy replacement | `eduid_requester_policy_replaces_original_accrs` |
| Generic exact/category/certification lookup and source order | `eduid_uses_metadata_order_after_exact_entity` and hardened-order counterpart |
| `StepupSAMLBackend.authn_request` late exact ACCR override | `initial_provider_policy_overrides_later_accr_selection` and no-match counterpart |
| `RewriteAuthnContextClass` accepted, missing-returned, rejected, and raw-MFA branches | shared policy tests plus `raw_refeds_mfa_without_trusted_provider_policy_does_not_bypass` |
| First/missing/incomplete linked-account branches | required-account and incomplete-account fail-closed tests |
| Callback issuer, identifier, exact requested LoA, and same-assertion provenance | ACS issuer and authenticated-assertion tests |
| Final LoA and assurance append/dedup behavior | completion and assurance-merge mode tests |
| Suspended-flow restoration | snapshot and proxy response-resume tests |
| Active metadata-role provenance | `policy_values_ignore_later_idp_roles` |

## Security boundaries

| Threat | Control | Residual risk |
|---|---|---|
| Linked account chooses an attacker IdP | SCIM issuer values require an operator mapping; static mode pins the same entity ID; step-up MDQ requires signed metadata; the validated response issuer must match | Incorrect operator mappings or compromised metadata-signing authority can authorize the wrong provider |
| Initial ACS query overrides the linked provider | The embedded SAML backend ignores request `entityID` values and uses only the account decoration | Trusted operator Python can still publish linked-account data |
| Forged, replayed or cross-flow step-up response | Native SAML signature, issuer, audience, recipient, time, `InResponseTo` and replay validation; unsolicited mode is forbidden | Replay cache remains process-local, as for ordinary SAML backends; clustered deployments need a shared cache |
| A valid account assertion authenticates another person | The linked identifier must appear in the configured mapped assertion attribute, in addition to the Subject-bound request | The provider must faithfully enforce the requested Subject and attribute semantics |
| Attributes from another valid assertion are confused with the authenticated subject | Step-up consumes attributes only from the assertion whose AuthnStatement supplies the issuer, subject and LoA | Ordinary non-step-up SAML backends retain historical multi-assertion aggregation |
| LoA inflation | Exact comparison is requested and the returned class must be in `requested`; downstream normalization follows the explicitly selected behavior | Incorrect LoA configuration, including eduID compatibility mappings, can misrepresent assurance |
| Flow state leaks or is tampered with | Snapshot is compressed inside authenticated JWE state and restored only after ACS validation | The browser holds ciphertext and large responses may exceed cookie transport limits |

## Consequences

Deployments without SCIM/step-up retain no eduID runtime dependency. Step-up
metadata and key configuration follow the existing SAML backend vocabulary,
and all established SAML hardening applies automatically. The micro-service
ordering must be `ScimAttributes`, `stepup`, then `accr` when all three are
used. Existing configurations select `hardened`; deployments migrating from
eduID must explicitly set `behavior = "eduid"`. Adding a response variant
makes exhaustive matches on `MicroServiceAction` in out-of-tree Rust plugins
require a new arm, although ordinary `process_response` implementations need
no change.
