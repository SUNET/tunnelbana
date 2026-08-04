# ADR 0033 - Fail-closed security boundaries for tunnelbana 0.3.0

- **Status:** Accepted
- **Date:** 2026-08-04
- **Component:** workspace-wide: core state and configuration, protocol
  frontends/backends, micro-services, HTTP runtime, deployment, and CI.
- **Supersedes in part:** ADR 0001, ADR 0002, ADR 0006, ADR 0009,
  ADR 0014, ADR 0015, ADR 0020, ADR 0022, ADR 0023, ADR 0024, ADR 0026,
  and ADR 0030.

The listed ADRs remain immutable historical records. Where this record
conflicts with one of them, the earlier statement is invalid as a description
of current behavior and this record is authoritative.

## Context

A repository-wide security audit found several places where a configured trust
boundary was weaker than its operator-facing description. The recurring
failure modes were:

- accepting protocol data without binding cryptographic proof to the exact
  object being consumed;
- converting missing, weaker, stale, or conflicting identity data into an
  apparently valid result;
- permissive defaults that could release attributes or steer routing without
  an explicit policy;
- process-local replay controls presented as though every mode supported
  shared-nothing horizontal scaling;
- unbounded outbound network operations and deployment or CI inputs with
  broader access than needed.

These are security-boundary changes rather than compatibility fixes. Version
0.3.0 therefore adopts fail-closed behavior even where that requires an
operator migration.

## Decision

### State, replay, and runtime resource limits

- A state cookie retains its original issue time when unsealed and resealed.
  Its server-side validity and emitted `Max-Age` use the remaining absolute
  lifetime, so routine requests cannot create a sliding expiry window.
- Every previous state-encryption key has the same 32-byte minimum as the
  current key.
- Outbound HTTP uses configurable non-zero connect, read, and total request
  deadlines. Response bodies are streamed into a bounded buffer with an
  8 MiB default limit; `Content-Length` is only an early rejection hint, not
  the enforcement mechanism.
- The encrypted login-flow cookie and stateless OIDC tokens do not imply that
  all protocol state is shared-nothing. The built-in DPoP `jti` cache and SAML
  assertion replay cache are process-local. Their replay-sensitive modes must
  run in one process unless a shared replay store is implemented.

This supersedes the sliding-lifetime and unconditional horizontal-scaling
statements in ADR 0001, ADR 0002, and ADR 0026.

### SAML trust and output integrity

- A POST-binding AuthnRequest signature is accepted only when a locally
  digest-verified Reference covers `#<ID>` of the exact parsed AuthnRequest.
  A valid signature over a sibling element does not authorize the consumed
  request.
- `allow_unknown_sps = true` cannot be combined with
  `want_authn_requests_signed = true`: open mode has no trusted SP metadata key
  with which to enforce that policy.
- A SAML frontend must sign the assertion, the response, or both. A
  configuration that would issue a completely unsigned successful response is
  rejected at startup.
- Public SAML errors are generic. Diagnostic details remain in trusted server
  logs.
- RSA-1.5 XML key transport remains rejected. This does not resolve
  RUSTSEC-2023-0071: RSA-OAEP assertion decryption still reaches the affected
  transitive `rsa` implementation with attacker-controlled ciphertext, and
  RustSec lists no fixed release. Deployments unable to accept that residual
  timing risk must not configure SAML assertion-decryption keypairs.

This supersedes the relevant signature-validation and encrypted-assertion
security boundaries in ADR 0006 and ADR 0009.

### Assurance and identity-data binding

- When an SP requests AuthnContextClassRef values, a missing, unknown, weaker,
  or otherwise unrequested upstream value is rejected by default. The proxy
  never synthesizes stronger assurance than the IdP established.
- `allow_stronger_accr_fallback = true` is an explicit compatibility mode. It
  may normalize a stronger asserted value down to a requested level according
  to the configured ordering, but it cannot promote a weaker assertion.
- OIDC and OpenID Federation UserInfo responses must contain `sub`, and it must
  equal the subject of the verified ID Token before any returned claims are
  merged.
- UserInfo retrieval or validation failures abort authentication instead of
  silently continuing with a partial identity.

This supersedes the ACCR mismatch behavior in ADR 0030.

### OpenID Federation request and cache binding

- A signed authorization request object must bind its issuer and inner
  `client_id` to the outer client, its audience to this OP, and its `iat` and
  required `exp` to a configurable maximum age.
- A parameter present both outside and inside the signed request must match;
  unsigned outer input cannot silently replace signed content.
- Cached RP and OP federation metadata expires at the earlier of the local
  cache TTL and the signed trust result's expiry. Missing or expired signed
  bounds are rejected.
- Public OAuth and federation errors use stable `access_denied` or
  `server_error` descriptions while retaining details in server logs.

This supersedes the cache lifetime and UserInfo behavior described by
ADR 0024.

### Attribute release, routing, identifiers, and audit logs

- `filter_attributes` releases nothing when no allow-list matches.
  SATOSA-compatible pass-through requires the explicit
  `passthrough_unmatched = true` option.
- Every target-issuer routing rule has a mandatory requester allow-list. Both
  the requested issuer and the identified downstream requester must match
  before the rule can select a backend. Duplicate `(issuer, requester)` pairs
  are rejected at startup so configuration order cannot change policy.
- Hash processors require a non-empty salt at startup. Legacy MD5 remains
  separately guarded as defined by ADR 0032.
- Every `primary_identifier` result uses versioned, component-counted,
  length-prefixed framing:
  `tbpid-v1:<count>:<length>:<value>...`. Single-component values are framed
  too, preventing collisions between raw values and encoded tuples.
- On Unix, audit-log targets are created or restricted to mode `0600` before
  use.

These decisions supersede the permissive or ambiguous behavior in ADR 0014,
ADR 0015, ADR 0020, ADR 0022, and ADR 0023.

### Deployment and CI supply-chain boundaries

- Container images do not copy runtime keys or deployment binaries. Keys,
  configuration, and helper binaries are read-only runtime mounts, and the
  Docker build context excludes secret and local-build directories.
- The Pages build downloads the pinned mdBook release archive, verifies its
  SHA-256 before extraction, and pins GitHub Actions to immutable commit IDs.
- The documentation build job has repository read access only. Pages and OIDC
  publication permissions exist only on the deployment job.

## Security boundaries

| Threat | Control | Residual risk |
|--------|---------|---------------|
| Assurance inflation | Reject missing, weaker, unknown, or unrequested ACCR; compatibility mode only maps stronger assertions down | A wrong operator-defined ordering can misclassify a stronger value |
| Signature wrapping or sibling authorization | Bind locally verified digest coverage to the exact consumed SAML object ID | Compromise of a trusted SP signing key remains SP compromise |
| Cross-subject claim injection | Require UserInfo `sub` to match the verified ID Token subject | A trusted malicious OP can lie consistently in both responses |
| Federation request parameter smuggling | Require signed and outer parameters to agree and bind issuer, client, audience, issue time, and expiry | Trust still depends on configured federation anchors |
| Attribute over-release | No matching allow-list releases nothing | Explicit `passthrough_unmatched` deliberately restores permissive behavior |
| Identifier/account collision | Version, arity, and byte-length framing is injective across candidate tuples | Existing identifiers require an account-link migration |
| Replay across replicas | Single-process deployment requirement for built-in process-local replay caches | A shared replay-store implementation is still absent |
| Outbound-resource exhaustion | Connect/read/total deadlines plus streamed response-size enforcement | Operators can configure limits too generously |
| RSA timing leakage | RSA-1.5 transport rejected; encrypted-assertion decryption can be disabled by omitting keypairs | RSA-OAEP remains affected until the dependency ecosystem provides a fix |
| Build-time secret capture or CI privilege abuse | Runtime-only mounts, excluded build context, checksummed tools, immutable actions, job-scoped permissions | Compromise of an explicitly trusted upstream release remains possible |

## Consequences

**Positive**

- Protocol assurance, identity, and routing decisions are derived only from
  evidence that was actually established and bound to the current flow.
- Configuration mistakes fail at startup or deny the affected flow instead of
  silently weakening policy.
- Network and build inputs have explicit resource, integrity, and privilege
  boundaries.

**Negative / migration requirements**

- Deployments upgrading from 0.2.x must review filter defaults, issuer routing
  rules, hash salts, SAML signing settings, and ACCR compatibility policy.
- Every primary identifier changes format, including identifiers constructed
  from one component. Stored account links must be migrated before rollout.
- Built-in DPoP and SAML assertion replay protection remains limited to one
  process.
- `cargo audit --deny warnings` continues to fail on RUSTSEC-2023-0071 because
  no fixed `rsa` release is available.

## References

- `CHANGELOG.md` - 0.3.0 operator-facing release summary.
- `crates/tunnelbana-core/src/{config,state}.rs`
- `crates/tunnelbana/src/{main,reqwest_client}.rs`
- `crates/tunnelbana-plugins/src/{saml2_frontend,oidc_backend,oidc_frontend,federation_backend,federation_frontend}.rs`
- `crates/tunnelbana-plugins/src/microservices/{accr,logging,policy,primary_identifier,processor,routing}.rs`
- `.github/workflows/{ci,mdbook}.yml`
- `deploy/satosa-idp/{Dockerfile,docker-compose.yml,.dockerignore}`
