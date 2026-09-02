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
- In MDQ mode, select the target solely from the SCIM-derived linked account;
  an `entityID` query parameter on the initial ACS request cannot override it.
  Static mode requires that account entity ID to equal the pinned IdP before
  the identifier is disclosed in a redirect.
- Save the original requester ACCRs and requester-metadata categories on the
  request path. Exact requester configuration wins, then the first configured
  entity category. On the initial response, an exact provider configuration or
  trusted assurance-certification can recognize and normalize an already
  satisfied LoA.
- On the callback, require normal SAML validation plus exact linked provider,
  exact requested step-up LoA and presence of the linked identifier in its
  configured assertion attribute. Merge only the configured assurance
  attribute, normalize the returned LoA, restore the original decorations and
  consume the snapshot before resuming.
- Reject a required step-up on an `IsPassive` flow as interaction-required;
  never turn a passive request into an interactive redirect.
- Store the response snapshot in the existing encrypted state cookie, with a
  32 KiB plaintext guard in addition to the global 4096-byte sealed cookie
  limit. Do not add a process-local pending-flow store, so any replica holding
  the state key can resume the flow.

## Security boundaries

| Threat | Control | Residual risk |
|---|---|---|
| Linked account chooses an attacker IdP | SCIM issuer values require an operator mapping; static mode pins the same entity ID; MDQ mode resolves trusted metadata; the validated response issuer must match | Incorrect operator mappings or unsafe MDQ configuration can authorize the wrong provider |
| Initial ACS query overrides the linked provider | The embedded SAML backend ignores request `entityID` values and uses only the account decoration | Trusted operator Python can still publish linked-account data |
| Forged, replayed or cross-flow step-up response | Native SAML signature, issuer, audience, recipient, time, `InResponseTo` and replay validation; unsolicited mode is forbidden | Replay cache remains process-local, as for ordinary SAML backends; clustered deployments need a shared cache |
| A valid account assertion authenticates another person | The linked identifier must appear in the configured mapped assertion attribute, in addition to the Subject-bound request | The provider must faithfully enforce the requested Subject and attribute semantics |
| LoA inflation | Exact comparison is requested and the returned class must be in `requested`; downstream output is an operator-configured normalization or an original requested value | Incorrect LoA configuration can misrepresent assurance |
| Flow state leaks or is tampered with | Snapshot is compressed inside authenticated JWE state and restored only after ACS validation | The browser holds ciphertext and large responses may exceed cookie transport limits |

## Consequences

Deployments without SCIM/step-up retain no eduID runtime dependency. Step-up
metadata and key configuration follow the existing SAML backend vocabulary,
and all established SAML hardening applies automatically. The micro-service
ordering must be `ScimAttributes`, `stepup`, then `accr` when all three are
used. Adding a response variant makes exhaustive matches on
`MicroServiceAction` in out-of-tree Rust plugins require a new arm, although
ordinary `process_response` implementations need no change.
