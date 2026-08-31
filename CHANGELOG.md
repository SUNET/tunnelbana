# Changelog

## Unreleased

- **OIDC authenticating authority:** the `oidc` and `oidc_federation` frontends
  can release the validated upstream IdP/OP issuer as an array-valued
  `authenticating_authority` claim.
  The reserved attribute-map entry controls whether it is released and under
  which OpenID claim name; ordinary attributes cannot spoof its value. The
  configured name is advertised in discovery and survives code and refresh
  exchanges unchanged. Mappings to provider-owned ID-token claims are rejected
  at startup rather than accepted and silently omitted during issuance.
- **Dependencies:** update `grindvakt` to 0.7.2 for typed OP-asserted claims.

## 0.3.1 [2026-08-24]

- **OIDC prompt handling:** update to grindvakt 0.7.1 and propagate
  `prompt=login` / `prompt=none` from the OIDC and federation OP frontends
  through the backend pipeline as forced/passive authentication. A passive
  request that cannot be completed without user interaction returns
  `login_required` to the validated redirect URI with the original state
  instead of entering interactive IdP discovery, fixing #23.

## 0.3.0 [2026-08-20]

- **Embedded Python micro-services:** add trusted, synchronous CPython 3.13
  micro-services through the isolated `tunnelbana-python` crate (ADR 0052).
  Configured class instances are reused, receive a strict complete
  `InternalData` dictionary and restricted context snapshot, and may atomically
  update only returned data, `target_backend`, and decorations. Calls run on
  Tokio's blocking pool behind a global semaphore and total deadline; timed-out
  calls retain their permits until they actually exit. Coroutine methods,
  awaitable results, automatic discovery, Python endpoints, and runtime pip
  installation are unsupported. Build and runtime images now include the
  matching dynamically linked CPython packages.
- **Embedded Python hardening (differential review F1-F3):** the interpreter
  starts with CPython's isolated configuration (`PYTHONPATH`/`PYTHONHOME`
  ignored, user site excluded, bytecode caches disabled, signal handlers left
  to the host); reserved first-writer-wins decorations (`target_entity_id`,
  `target_authn_context_class_ref`, `target_accr_comparison`) can no longer be
  changed or removed by Python once set by an earlier pipeline component; and
  the proxy now follows an `error_redirect` decoration only when it is an
  absolute http(s) URL without control characters, falling back to the normal
  protocol error otherwise (note: a relative `on_error` URL in
  `primary_identifier` config is now ignored at error time - use an absolute
  URL). Runtime initialization is also serialized so concurrent initializers
  cannot race the single-module-path guard.
- **Embedded Python virtual environments:** new optional `python.venv` key
  pointing at a venv directory (absolute or relative to `proxy.toml`). The
  embedded interpreter adopts it exactly like a venv-launched Python via
  `PyConfig.executable`: `pyvenv.cfg` is honored, `sys.prefix` moves into the
  venv, and its site-packages (including `.pth` files) is processed, while
  interpreter environment variables stay ignored. Create the venv with
  `uv venv --python 3.13` (or `python3.13 -m venv`) at image build time; a
  missing directory, `pyvenv.cfg`, or `bin/python` fails startup.
- **Embedded Python review fixes (PR #21):** the configured `class` must be a
  Python class (`inspect.isclass`), so factory functions and other callables
  fail startup as documented; and a `target_backend` returned by Python is
  validated against the configured backend names before commit on both the
  request and response paths instead of failing later or being silently
  retained.

- **Dependencies:** grindvakt 0.7.0 and jose-rs 0.7.0, which carry the
  protocol-layer fixes from the same audit (private_key_jwt assertions
  require `exp` and single-use `jti`; id_token verification requires
  `exp`/`iat`; authorization-request scope is checked against the client's
  registered scope; token-endpoint auth is pinned to the registered method;
  discovery requires https and an issuer match; JWTs pinning an unknown
  `kid` and JWEs carrying `zip`/empty `crit` are rejected). See their
  changelogs and ADRs for behavior-breaking details.

- **Security:** a follow-up audit pass hardened configuration loading, error
  handling, and the outbound HTTP client (ADR 0037). `${ENV}` interpolation
  now fails configuration loading with an error naming the unset variable
  instead of silently substituting the empty string; TOML parse errors keep
  line/column but no longer echo the post-interpolation source snippet, which
  could contain plaintext secrets; `cookie_same_site` is validated against
  `None`/`Lax`/`Strict` (case-insensitive) at startup; a state-cookie seal
  failure is logged instead of silently dropped; unhandled request errors
  return a generic `request failed` body while details stay in the server
  log; TTL-cache expiry arithmetic saturates instead of overflowing; a state
  cookie with an `iat` more than 60 seconds in the future is rejected rather
  than clamped to age zero; and the outbound reqwest client never follows
  redirects, so a 307/308 cannot re-send token-endpoint form bodies
  (`client_secret`, authorization code) cross-origin. The same pass also made
  `hasher` reject an empty per-requester salt (ADR 0034) and `custom_logging`
  open audit logs with `O_NOFOLLOW` (ADR 0036). The `pairwiseid`
  micro-service gained an opt-in injective HMAC framing
  (`framing = "v1"`, ADR 0035); the default `legacy` framing is unchanged,
  so existing pairwise identifiers are unaffected unless `v1` is explicitly
  enabled — enabling it changes all derived values and requires migrating
  stored account links first.

- **Security (protocol plugins):** OIDC and federation frontends now derive
  per-instance token-sealing keys (ADR 0038) — **upgrade note:** all
  authorization codes, access/refresh tokens, and DPoP nonces minted before
  the upgrade are invalidated (in-flight logins restart), and
  `previous_state_encryption_keys` does not bridge pre-upgrade tokens;
  renaming a frontend instance also invalidates its outstanding tokens.
  State cookies are unaffected. DPoP `proof_max_age_secs` must be positive
  and overlong `jti`s are rejected (ADR 0039); inline `clients` entries
  reject unknown fields like `clients_file` already did (ADR 0040); the OIDC
  backend fails closed on a missing stored nonce, requires an explicit
  `issuer` with static endpoints, and requires https upstream URLs except
  loopback (ADR 0041); the federation frontend negative-caches failed RP
  resolutions and the federation backend requires https on resolved OP
  endpoints (ADR 0042). Both OIDC frontends accept
  `client_assertion_max_age` to widen grindvakt's 300-second bound on
  `private_key_jwt` assertion age for clients that cannot mint fresh
  assertions per token request.

- **Security (SAML):** `passthrough_unmapped_attributes` can no longer merge
  into or fabricate mapped internal attributes (case-insensitive known
  check, ADR 0047); the SAML backend's `security` value must be `strict` or
  `permissive` (ADR 0050); attacker-controlled entity IDs are escaped in
  logs and no longer reflected in 403 bodies (ADR 0051); `ForceAuthn` /
  `IsPassive` are propagated upstream (`prompt=login`/`prompt=none` for the
  OIDC backend) or rejected when the backend cannot honor them (ADR 0049).
  MDQ-mode issuer scoping of composed/transient subject identifiers is
  available as an opt-in (`scope_subject_id_by_issuer = true`, ADR 0048);
  the default keeps SATOSA-compatible unscoped composed identifiers, so
  existing account links are unaffected unless the option is enabled.

- **Security (follow-up to the audit pass):** two denial-of-service defects
  found while reviewing the changes above were fixed. `custom_logging` now
  opens audit logs with `O_NONBLOCK` alongside `O_NOFOLLOW` and clears the
  flag once the target is confirmed to be a regular file: without it, opening
  a planted FIFO blocked until a reader appeared, so the regular-file check
  ADR 0036 relies on never ran and the open hung the proxy at boot, or parked
  one tokio worker per authentication response until the proxy stopped
  serving. The federation frontend's negative-resolution cache is now bounded
  - insertion uses `put_if_absent` (which carries the amortized sweep of
  expired entries) and a `client_id` over 512 bytes is not stored - because
  its keys come from an unauthenticated endpoint. Relatedly, `TtlCache::put`
  and `put_with_ttl` now perform the same amortized sweep as `put_if_absent`;
  previously only `put_if_absent` pruned, so any cache filled via `put` from
  request-derived keys retained one entry per key ever seen (TTL expiry only
  hides a value from `get`, it never reclaims the entry). See ADR 0036 and
  ADR 0042, whose security-boundaries tables were corrected accordingly.

- **Compatibility escape hatch:** `custom_logging` accepts
  `allow_insecure_log_target = true` to restore SATOSA-style behavior
  (follow symlinks, allow FIFO/stdout-linked targets) for container logging
  setups; the hardened regular-file + `O_NOFOLLOW` behavior stays the
  default (ADR 0036).

- **Repository-wide security hardening:** state cookies now retain their
  original issue time across resealing; every rotation key must satisfy the
  32-byte strength floor; outbound HTTP has configurable connect/read/total
  deadlines and an 8 MiB default streamed-body cap; deployment keys are
  runtime-only mounts; and the Pages workflow verifies mdBook's SHA-256 while
  keeping publish credentials out of the build job.

- **Protocol trust binding:** POST AuthnRequest signatures must cover the exact
  parsed request and SAML IdP configurations must sign the response, assertion,
  or both. Federation request objects require matching issuer, audience,
  client id, issued-at and expiry claims and cannot conflict with outer
  parameters. Federation metadata caches cannot outlive the trust anchor's
  signed expiry, and OIDC UserInfo subjects must match the ID Token subject.

- **Release-policy hardening:** attribute filtering is fail-closed unless
  `passthrough_unmatched` is explicitly enabled; primary identifiers use
  versioned, component-counted, length-prefixed framing; issuer routing is
  scoped to authorized requesters and rejects duplicate policy pairs; hash
  processors require a non-empty salt; audit logs are created
  owner-only on Unix; and public OAuth/SAML errors no longer disclose internal details.
  These configuration and identifier-format changes require an operator review
  when upgrading from 0.2.x.

- **Dependency-audit status:** `cargo audit --deny warnings` still reports
  RUSTSEC-2023-0071 for transitive `rsa` 0.9.10, for which RustSec has no fixed
  release. RSA-1.5 XML key transport remains rejected, but that does not resolve
  the crate-wide timing advisory: SAML RSA-OAEP private-key decryption is
  network-reachable when encrypted assertions are enabled. Deployments that
  cannot accept this residual risk must not enable SAML assertion decryption;
  remove this exception when the ecosystem publishes a compatible fix.

- **ACCR assurance validation:** when an SP requests an AuthnContextClassRef,
  missing or unrequested IdP responses now fail closed instead of being
  replaced with the strongest value requested by the SP. Controlled
  eduID-compatible deployments can opt into `allow_stronger_accr_fallback`; it
  only normalizes a stronger assertion down and never promotes a weaker one.

- **SAML / JOSE dependency refresh:** upgraded `gamlastan` and
  `gamlastan-mdq` to 0.8.0 and `jose-rs` to 0.6.0. The SAML frontend now passes
  cryptographic AuthnRequest-signature proof into gamlastan's hardened IdP
  validator, while the backend keeps an assertion replay cache for its full
  process lifetime as required by gamlastan 0.8. The development-only
  `allow_unknown_sps` mode retains its explicitly insecure, request-carried
  ACS behavior, but it can no longer be combined with
  `want_authn_requests_signed`: without registered SP metadata keys that policy
  now fails configuration instead of being silently bypassed.

- **Protocol-library releases:** upgraded to released `grindvakt` 0.6.2 and
  `jose-rs` 0.6.0 from crates.io, removing the temporary sibling-worktree
  patch used during integration.

- **Architecture record:** ADR 0033 is the authoritative record for the 0.3.0
  fail-closed security boundaries. Earlier ADR files remain unchanged as
  historical records, and the ADR index marks their conflicting portions as
  superseded.

## 0.2.0 [2026-07-07]

- **Security / SAML dependency stack:** bumped `gamlastan` and `gamlastan-mdq`
  from 0.5.x to 0.7.x, which brings in `bergshamra` 0.7.0 and `uppsala`
  0.9.0. This is the main security update in this release.

- **Uppsala 0.9.0 hardening:** the XML parser now fuses after direct pull-parser
  errors, validates computed XSLT element/attribute names as QNames, rejects
  trailing XPath tokens and depth-bypassing flat operator chains, indexes XSD
  identity constraints to avoid quadratic duplicate/keyref scans, rejects
  duplicate top-level `xs:group` / `xs:attributeGroup` definitions, exposes
  opt-in XSLT result-tree/output byte caps, normalizes retained XML declaration
  encodings from `parse_bytes()` to UTF-8, and includes the 0.8 reserved
  `xml`/`xmlns` namespace-binding rejection.

- **Bergshamra 0.7.0 hardening:** XML Encryption PBKDF2 iteration counts are
  capped before key derivation, malformed RSA `KeyValue` CryptoBinary values
  return errors instead of panicking, XML-DSig verification requires local
  Reference digest coverage by default, unsafe local Reference URI fallback
  values are rejected, detached reference debug output is redacted, raw inline
  `KeyValue` / `DEREncodedKeyValue` keys are rejected when trust anchors are
  configured, and duplicate XML ID values fail closed instead of overwriting
  earlier entries.

- **Gamlastan 0.7.0 SAML hardening:** ACS, MDQ, Sweden Connect, SPID and
  example flows now bind verified XML-DSig reference IDs to the exact SAML
  Response or Assertion being consumed. Solicited response processors require
  present and matching `InResponseTo` values and reject dangling `InResponseTo`
  on otherwise unsolicited flows. Trusted-SP metadata boundaries are enforced
  before issuing assertions or accepting dynamic entities. Metadata key
  extraction fails closed for malformed trust-anchor fragments and X.509
  lookalikes. Attribute release matches trusted SAML `Name` values, not
  SP-supplied `FriendlyName`, unless PySAML2 compatibility is explicitly
  enabled. Direct assertion-signature policies now require the consumed
  Assertion's own verified signature; a verified Response signature no longer
  satisfies `WantAssertionsSigned` / `require_signed_assertions`.

- **SAML backend signature validation:** the ACS path now collects all verified
  XML signature references with `verify_all_enveloped`, adds detached
  Redirect-binding proof for the Response ID, and verifies decrypted assertion
  signatures after decryption. This preserves valid double-signed responses
  while preventing signature markup or a signature over a different object from
  satisfying gamlastan's 0.7 validation checks.

- **OpenID / federation hardening:** bumped `grindvakt` to 0.6.0. Public
  authorization-code clients must use PKCE S256, authorization-code and refresh
  token use is protected by a `TokenUseStore`, token-use store errors are
  hidden from OAuth clients, and OpenID Federation resolve-response trust
  chains are validated end to end, including statement claims, timestamps,
  issuer/subject linkage, trust-anchor self-signature, and superior-key
  signatures.

- **Lockfile security update:** bumped `crossbeam-epoch` 0.9.18 to 0.9.20,
  clearing RUSTSEC-2026-0204 from the `tera` / `globwalk` / `ignore`
  dependency chain.

- **Audit note:** `cargo audit --deny warnings` still reports RUSTSEC-2023-0071
  for `rsa` 0.9.10. RustSec lists no fixed upgrade at release time; the crate is
  pulled in through the XML/OIDC crypto stack (`bergshamra`, `grindvakt`,
  `jose-rs`, and `kryptering`).

- **Legacy identifier compatibility:** added guarded PySAML2 MD5 compatibility
  for migrations from SATOSA / PySAML2 deployments. The new `legacy_eptid`
  response micro-service can emit PySAML2-compatible MD5
  `eduPersonTargetedID` values and, when explicitly requested, set the SAML
  subject id for SPs that historically stored that value as their persistent
  NameID. MD5 remains opt-in only: `allow_legacy_md5 = true` is required, and
  `requesters` can scope the legacy value to known SP entity IDs. The
  `hasher` and `attribute_processor` services also require the same guard
  before accepting `md5`.

- **SAML frontend compatibility:** `eduPersonTargetedID` is emitted as a
  NameID-valued SAML attribute when the attribute map identifies it by
  `eduPersonTargetedID` or OID `urn:oid:1.3.6.1.4.1.5923.1.1.1.10`. The value
  uses persistent NameID format with `NameQualifier` set to the proxy IdP
  entity ID and `SPNameQualifier` set to the requester SP entity ID. Transient
  NameIDs remain fresh opaque values per response, matching SATOSA-style
  pass-through deployments that rely on attributes rather than durable
  transient subjects.

- **Pairwise identifiers:** documented the preferred non-legacy path for new
  SPs: `pairwiseid` derives a per-SP `pairwise-id` with
  `HMAC-SHA256(pairwise_salt, "{requester}-{subject-id}")@scope`, and `nameid`
  consumes the hash part for persistent SAML NameIDs. This avoids cross-SP
  correlation while keeping legacy MD5 support isolated to migration flows.

- **Docs:** added the "Legacy identifier compatibility" chapter and expanded
  the built-in plugin and micro-service reference with PySAML2 compatibility,
  `legacy_eptid`, guarded MD5 usage, `eduPersonTargetedID` wire shape,
  pairwise identifier behavior, NameID selection, and scoping semantics.
  Added ADR 0032 for the legacy identifier compatibility decision.

## 0.1.0 [2026-06-25]

- **Dependencies:** bumped `grindvakt` 0.4 → 0.5 and `jose-rs` 0.3.1 → 0.5.0
  (shared type universe). grindvakt 0.5 encapsulates `SigningKey` (private key
  material is no longer a public field; signing goes through the `signer()` /
  `alg()` / `public_jwk()` accessors). tunnelbana does **not** enable
  grindvakt's optional `pkcs11` feature, so no HSM/`cryptoki` code is compiled.

- **Landing page:** the binary now serves a static page at `/` (logo, tagline,
  and project link) plus the logo at `/assets/tunnelbana.png`. A new top-level
  config key `index_html` lets an operator point at their own HTML file to
  replace the page; absent it, the built-in default is served. The file is read
  once at boot (resolved relative to the config file, or absolute) and served
  verbatim as `text/html`; a configured-but-unreadable path aborts startup
  (fail-fast). See [ADR 0031](docs/adr/0031-custom-index-page.md) and the
  "[The index page](docs/src/configuration.md)" section.

- **Micro-services:** ported eduID's four SATOSA `scimapi` services
  ([ADR 0030](docs/adr/0030-eduid-scimapi-microservices.md)):
  `pairwiseid` (per-SP `pairwise-id` via `HMAC-SHA256(salt, "{requester}-{subject-id}")@scope`),
  `static_attributes_for_virtual_idp` (replace/append static attributes by
  `(requester, virtual_idp)`), `nameid` (SAML subject value from
  `pairwise-id`/`mail` per requested NameID format), and `accr`
  (AuthnContextClassRef / LoA negotiation). `accr` adds request/response
  plumbing: the SAML frontend now publishes the SP's requested ACCR (and the
  resolved NameID format) for micro-services, and the SAML backend forwards a
  chosen `RequestedAuthnContext` into the outgoing AuthnRequest via new
  decorations (`KEY_REQUESTED_ACCR`, `KEY_TARGET_AUTHN_CONTEXT_CLASS_REF`, …).
  The attribute map gains literal `subject-id` / `pairwise-id` internal names.

- **Performance:** the URL router now resolves literal endpoint paths through an
  exact-match hash map instead of a linear regex scan, making `resolve` O(1) in
  the number of mounted modules. Each frontend mounts five routes, so a proxy
  fronting `N` frontends previously did up to `5N` regex matches per request
  (and a non-matching path - the scan's worst case - walked the whole list);
  this matters at federation scale (10-15k entities). `Route` gains
  `Route::exact` (literal, no regex compiled) alongside the unchanged
  `Route::new` (true regex, kept as a fallback); the `pattern` field is replaced
  by `Route::matches`. First-match precedence is preserved (including a frontend
  and backend that share a name and so both register e.g. `Saml2/metadata`).
  Verified on the `toomanyfronts/` scale rig at 10000 frontends: first/last/miss
  resolve within ~0.1 ms of each other (vs a 2.4 ms first-vs-last spread at 1000
  before), boot drops the ~5N regex compilations, and RSS fell from ~95 MB
  (1000) to ~71 MB (10000). See [ADR 0029](docs/adr/0029-router-exact-match-dispatch.md).

- **Docs:** the book gained two end-to-end tutorial chapters - *SAML and OIDC
  over a SWAMID SP backend* (SAML2 IdP + OIDC OP frontends over a SWAMID
  MDQ/SeamlessAccess SP backend, including the `email_verified` / Vaultwarden
  case) and *SAML IdP over an OpenID Federation RP backend* (discovery via
  upptackt) - plus a new *Attributes and transforms* chapter documenting the
  internal-name pivot, the attribute map, subject-id composition, the
  response-path transform pipeline, and the `email_verified` OIDC-vs-SAML gap
  with a security note. The *Built-in plugin reference* was reorganized into a
  plugin catalogue grouped under Frontends / Backends / Micro-services, and
  *Micro-services* gained a "Scoping a service to specific SPs and IdPs"
  section. Wide reference tables now render full-width and readable. No code
  changes.

- The `oidc` and `oidc_federation` frontends accept an optional **`clients_file`**
  pointing at a JSON file (a bare array of client objects) whose clients are
  **merged** with the inline `clients`. It externalizes a large or
  machine-generated client roster while keys/TTLs stay inline. A duplicate
  `client_id` anywhere in the merged set is now a fail-fast boot error
  (previously the in-memory store silently last-won, shadowing a client's
  secret/redirect URIs - this guard applies to inline-only configs too). An
  unknown field in a file entry (e.g. a misspelled `redirect_uri`) is rejected
  rather than silently dropped, so a typo cannot produce a half-configured
  client. The path is read as-given (working-directory relative, like
  `signing_key_path`), `${ENV}` applies, and the file is read once at startup. The SAML2 frontend is
  unaffected: its SPs are already file-based via `metadata.local` + MDQ. See
  ADR 0028 and [Client roster from a file](docs/src/built-in-plugins.md).

- All three frontends (`oidc`, `oidc_federation`, `saml2`) accept an optional
  **`backend = "<name>"`** config key that pins every flow from that frontend to
  a named backend, for deployments running more than one `[[backend]]`. The pin
  reuses the existing selection precedence - **frontend pin → `custom_routing` /
  `idp_hinting` → default backend (the first one listed)** - so a pinned frontend
  deterministically overrides backend selections from routing micro-services;
  leave it unset to let those services choose. An unknown name fails the flow at runtime
  (`UnknownModule`), the same surface as a stray `custom_routing` rule. See
  ADR 0027 and [Backend selection](docs/src/configuration.md).

- The `oidc` and `oidc_federation` frontends now support the **`refresh_token`
  grant** (grindvakt 0.4.0, RFC 6749 §6). A client registered with
  `refresh_token` in its `grant_types` receives a refresh token from the
  authorization-code exchange, and the token endpoint accepts
  `grant_type=refresh_token` to mint a fresh access token and id_token (scope
  may be narrowed, never widened). Refresh tokens are stateless and **rotated**
  on each use; a new `refresh_token_ttl` knob (default 30 days) sets the
  sliding lifetime. `refresh_token` is advertised in `grant_types_supported`.
  As before, statelessness means tokens cannot be revoked before expiry.
  Hardening that came with the grindvakt bump: every sealed token (code,
  access, refresh) now carries a verified type tag, so one kind can no longer
  be replayed as another.

- Bumped `gamlastan`/`gamlastan-mdq` to 0.5.0. The SAML assertion validator's
  signature check (check 6) no longer trusts the mere presence of a
  `<ds:Signature>` element: `ValidationParams` now carries a required
  `verified_signed_ids` listing the IDs whose XML-DSig references were
  actually cryptographically verified, and a signed assertion is accepted only
  when its ID (or its enclosing Response ID) is in that list. The `saml2`
  backend feeds in the IDs it already proved in `process_acs`: the Response ID
  when the envelope verified (Response-level XML signature or Redirect-binding
  detached signature over the whole message, both of which cover every
  contained assertion), otherwise each individually verified assertion ID
  (cleartext and decrypted alike).

- The `oidc_federation` backend now sends an RFC 9101 **signed request
  object** (grindvakt 0.3.1 `rp::signed_request_object`, signed with the
  `private_key_jwt` client key) on every authorization request, closing the
  ADR 0024 follow-up: OPs doing OpenID Federation automatic registration
  (e.g. the Shibboleth OIDC OP plugin) authenticate the RP at the
  authorization endpoint with it and resolve the RP's trust chain on the
  fly. Plain query parameters are kept alongside for OPs that ignore the
  `request` parameter; the proxy's own federation frontend verifies it
  against the auto-registered client keys as before.

- The `oidc_federation` backend's discovery mode now delegates OP selection to
  an external OpenID Federation discovery service (`discovery.service`, e.g.
  an upptackt deployment): `start_auth` redirects to the service and the new
  `<name>/initiate` endpoint accepts the OpenID Connect Core §4 third-party
  initiated login return, gated on an in-flight-flow marker in the state
  cookie and the trust-anchor resolution of `iss`. In discovery mode the RP
  entity configuration now publishes `initiate_login_uri`. The in-proxy
  OP-selection page (collection endpoint + HTML chooser) is retired but kept
  commented out in `federation_backend.rs` for reference; its
  `collection_endpoint`/`page_title`/`cache_ttl` config keys are replaced by
  `service`. (ADR 0025)

- Fixed response-path ordering in the proxy so response micro-services receive
  the restored requester and originating frontend context before policy runs.
  This makes requester-scoped `attribute_authorization` rules work in the real
  auth flow.
- Fixed `attribute_processor` `regex_sub` validation to reject missing or empty
  `match_pattern` and `replace_pattern` values at startup, matching the SATOSA
  contract instead of silently rewriting with an empty replacement.
