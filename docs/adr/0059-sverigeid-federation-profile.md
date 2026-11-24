# ADR 0059 - SverigeID authentication and signature approval through Sweden Connect

- **Status** Accepted
- **Date** 2026-11-24
- **Components** Federation RP backend, federation OP frontend, proxy core and local federation release gate
- **Related decisions** [Federation backend](0024-openid-federation-backend.md), [frontend backend selection](0027-frontend-backend-pin.md), [federation trust resolution](0042-federation-resolution-hardening.md), [OIDC subject compatibility](0058-grindvakt-081-subject-compatibility.md)

## Context

An existing OIDC service or SAML service provider needs to authenticate users through SverigeID without changing its account identifiers. A Sweden Connect relying party (RP) may also need Tunnelbana to act as its OpenID Provider (OP), including when asking a user to approve a signature. SverigeID authenticates the person and collects that approval. Tunnelbana is accountable to the downstream service for the identity, assurance and claims it issues.

These roles have different issuers, audiences, keys and registrations. Forwarding an upstream ID token would give the downstream RP a token addressed to Tunnelbana, with the wrong nonce and subject. Reconstructing assurance from mapped attributes or a cached session would lose the evidence of what SverigeID established for this request.

## Decision

Enable the Sweden Connect rules explicitly with `profile = "sweden_connect"` on the existing federation plugins. An existing OIDC or SAML frontend can select just the SverigeID backend. Publishing an OP in the federation additionally requires its own frontend entity and registration. Tunnelbana owns profile policy and account mapping. Grindvakt supplies OIDC and federation processing, and jose-rs supplies the signature and encryption primitives. Both libraries are consumed from crates.io. [Deployment guide](../src/sverigeid.md)

### Federation membership and assurance

Register the upstream-facing RP and downstream-facing OP under the registration intermediates for their respective roles. Publish separate leaf metadata, federation signing keys and protocol keys. Each environment has its own trust anchor and SverigeID issuer. Tunnelbana uses a signed resolution response from a configured anchor to establish a peer's metadata, keys and endorsed trust marks. Local cache lifetime is capped by the signed resolution's expiry. A withdrawn mark takes effect on fresh resolution. [Sweden Connect metadata requirements](https://docs.swedenconnect.se/federation/oidc-metadata-requirements.html)

A trust mark establishes the provider's eligibility to assert a Swedish level of assurance (LoA). The signed ID token's `acr` identifies the level achieved by this user. For a Swedish LoA, Tunnelbana requires both the matching mark for that provider and an achieved level acceptable to the request. A per-frontend assurance minimum applies even if the client omitted `acr`. An empty intersection with an essential client requirement, a missing authentication time or an unacceptable result prevents downstream issuance. [Sweden Connect OIDC profile](https://docs.swedenconnect.se/technical-framework/october-2026/OpenID_Connect_Profile_for_Sweden_Connect.html)

### One login across two protocol exchanges

1. The downstream frontend records the accepted request and requester. A federation RP submits a signed Request Object. The OP checks its signature and replay identifier on every authorization, including when the registration is cached. The profile requires authorization code flow, a nonce and S256 PKCE.
2. The backend creates fresh upstream state, nonce and PKCE verifier. It signs the upstream Request Object, binding the permitted scopes, essential claims and assurance constraints. Request microservices can tighten assurance policy. The proxy retains the original frontend request and the policy state needed on the response path.
3. On callback, Tunnelbana checks state and consumes the one-use transaction. It redeems the code using PKCE and `private_key_jwt`. It verifies the ID token against the registered algorithm, issuer, audience and nonce, checks time constraints and validates applicable token hashes. It fetches signed UserInfo from the resolved OP and verifies its signature, issuer, audience and agreement with the ID token's subject. Registered encryption requires successful decryption before signature validation.
4. The downstream frontend issues its own response. It preserves the verified `acr` and original `auth_time` through the response pipeline. An OIDC RP receives Tunnelbana's issuer, its own audience, its request nonce and the subject for its account binding. A SAML service receives the corresponding authentication context and instant.

### Subjects and claim release

Existing service frontends retain their configured subject mappings. The Sweden Connect OP derives an opaque subject with HMAC-SHA-256 over a versioned tuple containing the downstream issuer, sector when pairwise, upstream issuer and verified upstream subject. Public subjects are stable within that OP. Pairwise subjects are stable within a sector. The sector comes from the registered HTTPS sector identifier URI's host, or the single HTTPS host shared by the registered redirects. Changing the subject secret, issuer or sector changes account identifiers. [Subject compatibility decision](0058-grindvakt-081-subject-compatibility.md)

The OP evaluates ID-token and UserInfo release separately. For each destination, the value must have been verified in that upstream destination, permitted by the client's scope or explicit claim request, and retained by the requester's response filters and the profile release list. Removed or replaced identifier values stay private. A multivalued claim retains only surviving signed entries. Swedish personal identity and coordination numbers are distinct 12-digit strings, preserving leading zeroes. An `openid`-only request without an explicit number claim receives neither. [Swedish claims and scopes](https://www.oidc.se/specifications/swedish-oidc-claims-specification-1_0.html)

### Signed UserInfo and the protected type

The Swedish profile requires signed UserInfo. OIDC Core prescribes the HTTP media type `application/jwt`. The JWT specification makes the JOSE `typ` header optional and recommends `JWT` when supplied. [Swedish OIDC Profile §4.1](https://www.oidc.se/specifications/swedish-oidc-profile-1_0.html#41-userinfo-endpoint) · [OIDC Core §5.3.2](https://openid.net/specs/openid-connect-core-1_0.html#UserInfoResponse) · [RFC 7519 §5.1](https://www.rfc-editor.org/rfc/rfc7519.html#section-5.1)

Grindvakt 0.13.0 issues `typ=userinfo+jwt` from its generic signed UserInfo endpoint. The unmodified Test my eID 4.0.0 and 4.0.1 clients both rejected that type during initial login. We chose `typ=JWT` specifically for issuance by Tunnelbana's Sweden Connect OP. Patching the reference client would have left services using the published client unable to log in. [Test my eID verifier](https://github.com/swedenconnect/test-my-eid/blob/v4.0.1/src/main/java/se/swedenconnect/eid/sp/oidc/OidcResponseProcessor.java#L280-L291)

The generic type and a shared OP signing key cannot distinguish an ID token from UserInfo on their own. Profile ID-token validation requires the request nonce. UserInfo carries the authorized subject, OP issuer and client audience, and omits `nonce`, `auth_time`, `acr`, `at_hash` and `c_hash`. Its expiry is capped by both the access token's expiry and five minutes. On the upstream leg, Tunnelbana accepts signed UserInfo from OPs that share keys and omit an explicit type or issuance time. It binds the response to the expected issuer, audience and ID-token subject and rejects ID-token markers. [Profile implementation](../../crates/tunnelbana-plugins/src/sweden_connect.rs) · [Upstream verification](../../crates/tunnelbana-plugins/src/federation_backend.rs)

ID-token and UserInfo encryption follow their respective client registration policies. UserInfo is signed first, then encrypted as a nested JWT when required. An encryption algorithm without an explicit content cipher selects the OIDC default `A128CBC-HS256`. During rollover Tunnelbana tries eligible recipient keys. If none can encrypt, issuance fails.

### Signature approval

Only an explicitly allowed signature client can request `signApproval`. Tunnelbana verifies and binds the client's signed request, requires `login` and `consent` prompts, and re-signs the localized message and enforceable signer constraints for the upstream OP. The upstream OP displays the message and authenticates the signer. The callback checks the approval transaction, signer constraints and authentication time. Cancellation, unknown signer, a stale login or reuse of a completed request cannot produce a successful approval. This decision covers the extension's *Signature Approval* use case. Requests for direct signing of `tbs_data` are rejected. [Signature Extension §2.2](https://www.oidc.se/specifications/oidc-signature-extension-1_2.html)

## Operational consequences

The sealed browser cookie carries a transaction handle and OIDC state. The backend keeps the bound request, verifier and policy with the one-use transaction. A callback has at most ten minutes to consume it and must arrive before the original cookie deadline. Single-process deployments can use in-memory stores. Replicas need shared Redis for transactions, registrations and replay protection, along with consistent sealing and subject secrets. A process restart loses in-memory transactions. [Deployment and rollover guide](../src/sverigeid.md)

Prepublish the next public signing key with a distinct `kid` before switching signers. Keep retired private decryption keys available for the lifetime of cached registrations and in-flight requests. This lets one replica begin an authorization while another finishes it across a key change.

## Acceptance and deployment

`just release` requires `just test-sverigeid-local` to pass before building or pushing the release image. The gate pins the Sweden Connect reference federation revision and container digests. It runs two proxy replicas with Redis and uses the unmodified reference clients and OP. Its redacted report records the inputs and each check. [Local verification report](../src/sverigeid-local-report.json) · [Reference services](https://docs.swedenconnect.se/local-federation/services.html)

| Boundary | Acceptance evidence |
|---|---|
| Existing services and identity | OIDC and SAML logins, original authentication time and achieved LoA, Swedish numbers, claim privacy and sector-specific subjects |
| Signed and encrypted responses | Test RP 1 verifies signed responses. Test RPs 2 and 3 decrypt RSA and EC responses. A registered fixture verifies the protected UserInfo type and the absence of ID-token markers. |
| Signature approval | Test my eID completes approval, cancellation and unknown-signer flows. The browser checks the displayed message and exercises request reuse. |
| Trust and continuity | Fixtures cover an expired peer, a withdrawn LoA mark, incorrect issuer, audience or subject, concurrent redemption, cross-replica completion and decryption-key rollover. |

Live SverigeID Sandbox login and approval remain deployment milestones requiring a registered RP and test identity. Production OP onboarding also requires Digg's approval for the assurance levels the operator intends to assert. [SverigeID onboarding](https://www.swedenconnect.se/anslut-till-sweden-connect/erbjud-inloggning-med-sverigeid)
