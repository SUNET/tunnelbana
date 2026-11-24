# Connecting a service to SverigeID

SverigeID authenticates the user or collects their signature approval. Tunnelbana verifies the signed result and issues an OIDC or SAML response to the service. The response carries the original authentication time and achieved assurance level. The downstream issuer, audience, nonce and subject belong to the downstream transaction.

## Existing OIDC or SAML service

Keep the service's frontend, subject mapping and client registration. Set its `backend` to `sverigeid`. Add the following backend to the deployment's TOML. Obtain the RP registration under the selected environment's registration intermediate. The entity configuration is served at `<base_url>/sverigeid/.well-known/openid-federation`.

```toml
[[backend]]
name = "sverigeid"
type = "oidc_federation"
[backend.config]
profile = "sweden_connect"
environment = "sandbox"
signing_jwk_path = "/run/keys/rp-protocol.jwk"
redis_url = "${FEDERATION_REDIS_URL}"
scope = "openid https://id.oidc.se/scope/naturalPersonInfo https://id.oidc.se/scope/naturalPersonNumber https://id.oidc.se/scope/signApproval"
[backend.config.presentation]
client_name = "Example Service"
"client_name#sv" = "Exempeltjänst"
"client_name#en" = "Example Service"
contacts = ["operations@example.org"]
logo_uri = "https://proxy.example.org/logo.svg"
client_uri = "https://proxy.example.org"
[backend.config.federation]
signing_jwk_path = "/run/keys/rp-federation.jwk"
authority_hints = ["${SC_RP_INTERMEDIATE}"]
organization_name = "Example Organisation"
[[backend.config.federation.trust_anchor]]
entity_id = "${SC_TRUST_ANCHOR}"
keys = [${SC_ANCHOR_PUBLIC_TOML}]
```

Supply the anchor ID, intermediate ID and pinned public JWK from the same environment. `SC_ANCHOR_PUBLIC_TOML` expands to a TOML inline table containing the anchor's public key and `kid`. `environment` selects the upstream issuer.

| Environment | Issuer |
| --- | --- |
| `local` | `https://local.fed.swedenconnect.se:11010` by default |
| `sandbox` | `https://op.sandbox.sverigeid.se` |
| `qa` | `https://op.qa.sverigeid.se` |
| `production` | `https://op.sverigeid.se` |

The backend verifies the ID token and signed UserInfo against the RP's registered signing algorithm (`id_token_signed_response_alg`, default `RS256`). Both responses must identify the same user. Each certified Swedish LoA requires its corresponding resolver-endorsed trust mark. Use `required_trust_marks` for additional admission requirements. Essential ACR requirements that cannot be met end the transaction.

## Publishing a federation OP

Add the following frontend alongside the backend above. Register its entity ID under the OP registration intermediate and supply its granted trust marks in `frontend.config.federation.trust_marks`. Each entry contains the `trust_mark_type` and issued compact `trust_mark`. The same structure is available for the RP's own marks.

```toml
[[frontend]]
name = "federation-op"
type = "oidc_federation"
[frontend.config]
profile = "sweden_connect"
backend = "sverigeid"
signing_jwk_path = "/run/keys/op-protocol.jwk"
subject_secret = "${SC_SUBJECT_SECRET}"
redis_url = "${FEDERATION_REDIS_URL}"
acr_values_supported = ["http://id.elegnamnden.se/loa/1.0/loa3"]
approval_clients = ["https://service.example.org/registered-rp"]
release_claims = ["given_name", "family_name", "birthdate", "https://id.oidc.se/claim/personalIdentityNumber", "https://id.oidc.se/claim/coordinationNumber"]
[frontend.config.presentation]
display_name = "Example Identity Provider"
"display_name#sv" = "Exempelidentitet"
"display_name#en" = "Example Identity Provider"
contacts = ["operations@example.org"]
logo_uri = "https://proxy.example.org/logo.svg"
op_policy_uri = "https://proxy.example.org/policy"
[frontend.config.federation]
signing_jwk_path = "/run/keys/op-federation.jwk"
authority_hints = ["${SC_OP_INTERMEDIATE}"]
organization_name = "Example Organisation"
[[frontend.config.federation.trust_anchor]]
entity_id = "${SC_TRUST_ANCHOR}"
keys = [${SC_ANCHOR_PUBLIC_TOML}]
```

Use a stable random `subject_secret` of at least 32 bytes. Public subjects are opaque. Pairwise subjects also depend on the registered sector. Share this secret, the state encryption keys, the RP and OP registrations, and Redis across replicas. Omitting `redis_url` selects per-process memory. An authorization must return within the ten-minute transaction lifetime.

The release list limits the names that can leave the proxy. The request selects the destinations. `naturalPersonInfo` releases available names and birthdate in UserInfo. `naturalPersonNumber` releases the available 12-digit string in its authorized destinations. `openid` alone releases neither number. An approved signing client must send a signed request containing the localized message and `prompt=login consent`. Successful ordinary authentication cannot complete that approval.

For rollover, add the next public signing JWK to `rotation.signing_public_jwks` with `use="sig"` and its own `kid`. Allow peer caches to refresh before switching the active signing key. Configure current private encryption JWKs under `rotation.decryption_jwk_paths`. Move a retired key to `rotation.retired_decryption_jwk_paths` until cached registrations and in-flight requests have expired. To register encrypted upstream responses, set `id_token_encryption` or `userinfo_encryption` on the backend to an inline table such as `{ alg="RSA-OAEP-256", enc="A256GCM" }`. A matching active private recipient key is required.

## Running the local release gate

Place Sweden Connect's `local-federation` checkout beside Tunnelbana. Check out local-federation commit `5b67bedb42230fff6b8d89fb26c80e2084d2eb7b` (v1.0.1). On Linux, install Docker Compose, Rust, a Python installation usable by PyO3, uv, bubblewrap, keytool, curl, xmlsec1, and Chrome. Use `CHROME_BIN` to select a different Chromium installation. The test runs with the fixture certificate and process-local DNS. The documented reference ports and ports 11050–11052 must be available.

Run `just test-sverigeid-local`. The command creates disposable entities and keys, waits for signed resolution and discovery, runs the browser checks and tears down the fixture. `target/sverigeid-local-report.json` records the checks, reference image digests, Tunnelbana revision and local changes, and the crates.io versions and checksums for Grindvakt and jose-rs from `Cargo.lock`.

The [recorded local verification](sverigeid-local-report.json) lists the revisions and results for this implementation.

| Requirement | Acceptance evidence |
| --- | --- |
| Authentication, Swedish claims and assurance | Existing OIDC and SAML services, Test RP 1, personal identity and coordination numbers, openid-only privacy, multiple LoAs and an original-time fixture |
| Public and sector-specific subjects | Repeat requests from Test RP 1 and Test RP 2, registered sector fixtures |
| Encryption and signing key choice | Test RP 2 with RSA-OAEP-256, Test RP 3 with each signing key and ECDH-ES |
| Consent and signer binding | Test my eID displayed message, success, cancellation and unknown principal, plus scoped approval and signer rejection fixtures |
| Trust, replay and replication | Signed resolver responses, expired registration, withdrawal of a previously granted LoA mark, concurrent redemption, transaction replay, two proxy processes and overlapping keys |

Sandbox transactions require a registered RP and a test identity. Complete login and approval there before claiming actual SverigeID interoperability. Production OP onboarding also requires Digg's audit and approved assurance declarations. [Sweden Connect federation environments](https://docs.swedenconnect.se/federation/oidf-structure.html) · [SverigeID onboarding](https://www.swedenconnect.se/anslut-till-sweden-connect/erbjud-inloggning-med-sverigeid)
