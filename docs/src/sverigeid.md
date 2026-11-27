# Connecting a service to SverigeID

SverigeID authenticates the user or collects their signature approval. Tunnelbana verifies the signed result and issues an OIDC or SAML response to the service. The response carries the original authentication time. When SverigeID authenticates at certified Swedish LoA4, Tunnelbana releases `http://id.elegnamnden.se/loa/1.0/loa3` in the OIDC ID token’s `acr` or the SAML assertion’s `AuthnContextClassRef`. Lower levels retain their verified value. A service that requires LoA4 receives an authentication error. The downstream issuer, audience, nonce and subject belong to the downstream transaction.

## Existing OIDC or SAML service

The example connects a SWAMID QA SAML IdP frontend named `scqa` to a Sweden Connect Sandbox RP named `svidsandbox`. In the existing SAML frontend's `[frontend.config]`, set `backend = "svidsandbox"`. The frontend consumes SWAMID QA SP metadata. Register its public `/scqa/metadata` separately with SWAMID QA. The upstream OIDC RP has its own registration with Sweden Connect.

### Configure the Sandbox RP

This example uses the demo's public registration details. For another deployment, substitute your own base URL, legal organization, names, contact, policy and logo. Mount two distinct P-384 private keys readable by the service and set the paths below. Supply `SC_SANDBOX_ANCHOR_JWK` as a TOML inline table containing the Sandbox anchor's published public JWK, including its `kid`. Obtain it from the federation operator. [Sandbox trust anchor and intermediates](https://docs.swedenconnect.se/federation/oidf-structure.html#section-5.3)

```toml
[[backend]]
name = "svidsandbox"
type = "oidc_federation"

[backend.config]
profile = "sweden_connect"
environment = "sandbox"
op_entity_id = "https://op.sandbox.sverigeid.se"
subject_type = "pairwise"
scope = "openid profile https://id.oidc.se/scope/naturalPersonNumber https://id.oidc.se/scope/naturalPersonInfo"
signing_key_path = "/run/keys/svidsandbox-protocol.pem"
signing_algorithm = "ES384"
signing_key_id = "svidsandbox-protocol-1"
id_token_signed_response_alg = "ES384"
id_token_signing_alg_values_supported = ["RS256", "RS384", "RS512", "ES256", "ES384", "ES512"]

[backend.config.presentation]
client_name = "Tunnelbana demo"
"client_name#en" = "Tunnelbana demo"
"client_name#sv" = "Tunnelbana demo"
display_name = "Tunnelbana demo"
"display_name#en" = "Tunnelbana demo"
"display_name#sv" = "Tunnelbana demo"
organization_identifier = "urn:glue:iso6523:0007:2021005208"
"organization_name#en" = "The Swedish Research Council"
"organization_name#sv" = "Vetenskapsrådet"
contacts = ["kushal@sunet.se"]
client_uri = "https://tunnelbana-demo.labb.sunet.se"
logo_uri = "https://tunnelbana-demo.labb.sunet.se/assets/tunnelbana.png"
policy_uri = "https://wiki.sunet.se/display/SWAMID/SWAMID+Entity+Category+Release+Check+-+Privacy+Policy"

[backend.config.federation]
signing_key_path = "/run/keys/svidsandbox-federation.pem"
signing_algorithm = "ES384"
signing_key_id = "svidsandbox-federation-1"
authority_hints = ["https://fed.sandbox.swedenconnect.se/im-reg-sc"]
organization_name = "Vetenskapsrådet"
organization_uri = "https://www.sunet.se/"

[[backend.config.federation.trust_anchor]]
entity_id = "https://fed.sandbox.swedenconnect.se/trustanchor"
keys = [${SC_SANDBOX_ANCHOR_JWK}]
```

Every Sweden Connect backend requires an explicit `op_entity_id`, including in `local`, `sandbox`, `qa` and `production`. A configuration that previously relied on its environment must add the issuer before starting this build. Use the exact OP entity ID. Tunnelbana resolves it through the configured anchor and obtains the authorization, token, UserInfo and key endpoints from verified metadata. If login against the SverigeID Sandbox OP fails, follow [Test with the Sandbox Reference OP](#test-with-the-sandbox-reference-op). The backend name, RP entity ID, callback, own trust marks and key pairs belong to the RP and stay with it.

For multiple replicas, also set `redis_url` under `[backend.config]` to the shared transaction store. The example requests authentication and identity attributes.

### Register and verify the self-managed RP

1. With the demo base URL, the RP entity ID is `https://tunnelbana-demo.labb.sunet.se/svidsandbox`. Register this ID in the Sandbox portal. Tunnelbana serves its signed statement at `/svidsandbox/.well-known/openid-federation` and publishes the callback at `/svidsandbox/callback`. The signed metadata contains the single role `openid_relying_party`. The federation public key appears at the statement root and the protocol public key under the RP role.
2. Enter the ten-digit organization number without a hyphen if the portal prompts for it. Check the localized names, contact, privacy policy and HTTPS logo. The demo serves the logo as a public PNG with working GET and HEAD responses.
3. After the operator approves the RP's grants, fetch each signed mark from the Sandbox property and contract issuer. This example saves the two marks granted to the demo. [Sweden Connect registration rules](https://docs.swedenconnect.se/federation/oidf-rules.html)

Run the following from the demo's Compose directory (`~/tunnelbana-demo`) after approval. Use the same shell for all steps. The `sub` parameter is Tunnelbana's registered RP entity ID. Both grants come from the Sandbox property and contract issuer, including when you select the Reference OP for login. A successful GET returns one compact JWT as the response body. [Sandbox issuer endpoints](https://docs.swedenconnect.se/federation/oidf-structure.html#section-5.3.3.2) · [Trust Mark request and response](https://openid.net/specs/openid-federation-1_0.html#section-8.6)

```sh
cd ~/tunnelbana-demo
export RP_ENTITY_ID=https://tunnelbana-demo.labb.sunet.se/svidsandbox
export MARK_ISSUER=https://fed.sandbox.swedenconnect.se/tmi-contracts
MARK_DIR=$(mktemp -d)
export MARK_DIR

for mark_type in \
  https://id.swedenconnect.se/contract/sc/eid-authorization-system \
  https://id.swedenconnect.se/tm-prop/public-body
do
  curl --fail --silent --show-error --get "$MARK_ISSUER/trust_mark" \
    --header 'Accept: application/trust-mark+jwt' \
    --data-urlencode "sub=$RP_ENTITY_ID" \
    --data-urlencode "trust_mark_type=$mark_type" \
    --output "$MARK_DIR/${mark_type##*/}.jwt" || break
done
```

Verify each JWT signature against the issuer's federation keys through the pinned Sandbox anchor and confirm that the anchor authorizes the issuer for its mark type. The following command checks the downloaded claims, prints the renewal deadlines, and generates **one TOML assignment containing both complete JWTs**. These content checks are separate from signature verification.

```sh
python3 - <<'PY'
import base64
import datetime
import json
import os
from pathlib import Path
import time

directory = Path(os.environ["MARK_DIR"])
rows = []
for suffix in ("contract/sc/eid-authorization-system", "tm-prop/public-body"):
    kind = "https://id.swedenconnect.se/" + suffix
    token = (directory / (suffix.split("/")[-1] + ".jwt")).read_text().strip()
    header, payload, signature = token.split(".")
    def decode(part):
        return json.loads(base64.urlsafe_b64decode(part + "==="))
    claims = decode(payload)
    if not (signature and decode(header)["typ"] == "trust-mark+jwt"
            and claims["iss"] == os.environ["MARK_ISSUER"]
            and claims["sub"] == os.environ["RP_ENTITY_ID"]
            and claims["trust_mark_type"] == kind
            and claims["iat"] <= time.time() < claims["exp"]):
        raise ValueError(f"Unexpected or expired trust mark: {kind}")
    print(kind, "expires", datetime.datetime.fromtimestamp(
        claims["exp"], datetime.timezone.utc).isoformat())
    rows.append("  { trust_mark_type = " + json.dumps(kind)
                + ", trust_mark = " + json.dumps(token) + " }")
snippet = directory / "trust-marks.toml"
snippet.write_text("trust_marks = [\n" + ",\n".join(rows) + "\n]\n")
print("TOML ready at", snippet)
PY
```

After the command reports **TOML ready**, back up the configuration and open it at the correct backend. For example, with Vim:

```sh
backup=$(mktemp config/proxy.toml.before-marks.XXXXXXXX)
cp -p config/proxy.toml "$backup"
vim '+/name = "svidsandbox"' config/proxy.toml
```

In that backend, move to the **`[backend.config.federation]` header line**. On renewal, first remove the old entries for these two types, including their old array declaration if replacing the entire array. At the header line, run this Vim command to insert the generated assignment immediately below it, then save with `:wq`:

```vim
:read $MARK_DIR/trust-marks.toml
```

The demo has exactly these two marks. If your RP holds other marks, retain their entries in the same array. Keep the assignment above the next table header, especially `[[backend.config.federation.trust_anchor]]`. Tunnelbana reads the literal JWTs from `proxy.toml`; the temporary download directory is only needed for this procedure. The separate `required_trust_marks` setting controls which upstream OPs can authenticate users.

Restart the demo service to load the updated file:

```sh
docker compose restart tunnelbana
curl --fail --silent --show-error --retry 10 --retry-all-errors --retry-delay 1 \
  https://tunnelbana-demo.labb.sunet.se/health
```

Compare the **top-level** published marks with the exact files you downloaded. This also catches edits placed under the wrong backend or trust anchor:

```sh
python3 - <<'PY'
import base64
import json
import os
from pathlib import Path
from urllib.request import urlopen

url = os.environ["RP_ENTITY_ID"] + "/.well-known/openid-federation"
with urlopen(url, timeout=15) as response:
    payload = response.read().strip().split(b".")[1]
statement = json.loads(base64.urlsafe_b64decode(payload + b"==="))
published = {m["trust_mark_type"]: m["trust_mark"] for m in statement["trust_marks"]}
for suffix in ("contract/sc/eid-authorization-system", "tm-prop/public-body"):
    kind = "https://id.swedenconnect.se/" + suffix
    filename = suffix.split("/")[-1] + ".jwt"
    if published.get(kind) != (Path(os.environ["MARK_DIR"]) / filename).read_text().strip():
        raise ValueError(f"Published mark differs: {kind}")
    print("Published", kind)
PY
```

If startup or verification fails, restore the saved configuration with `cp -p "$backup" config/proxy.toml` and restart the service. Repeat the fetch and replacement before the earlier of the two expiry times.

Verify that the registration intermediate issued a subordinate statement for the RP, and that the Sandbox anchor's signed resolve response identifies the RP under `openid_relying_party`. Begin an end-to-end login at a QA service provider that trusts `scqa`.

### Required `openid_relying_party` metadata

Sweden Connect applies its registration requirements to **resolved metadata**: the RP's signed declaration combined with the registration intermediate's assignments and the trust anchor's metadata policy. Use the table when completing the portal form or reviewing a resolved RP. The next section shows the full declaration the demo publishes. [Common metadata requirements (§3)](https://docs.swedenconnect.se/federation/oidc-metadata-requirements.html#section-3) · [Relying party requirements (§4)](https://docs.swedenconnect.se/federation/oidc-metadata-requirements.html#section-4)

| Required in the resolved RP metadata | How the Sandbox example satisfies it |
| --- | --- |
| `organization_name`, `organization_identifier` | The registration intermediate assigns the verified legal name and organization number. The demo also declares the legal name, Swedish and English names, and the GLUE URN. Enter the ten digits without a hyphen when the portal requests the number. |
| `client_name`, `client_name#sv`, `client_name#en` | Supply both Swedish and English service names in `presentation`. The operator checks and pins the names and supplies an untagged name in the resolved metadata. |
| `display_name` | The demo supplies the untagged, Swedish and English values. The operator can derive the display name from the RP's client name when omitted. |
| `logo_uri`, `contacts`, `client_uri` | Supply a public HTTPS image URL, at least one operational email address, and an HTTPS URL for the RP's home page. The portal checks the logo. |
| `jwks` or `jwks_uri` | The RP must publish its protocol public keys. Tunnelbana generates inline `metadata.openid_relying_party.jwks` from its protocol key configuration. The outer federation `jwks` signs the entity statement and serves a different purpose. |
| `redirect_uris`, `response_types`, `grant_types`, `token_endpoint_auth_method` | Tunnelbana generates the callback URL and publishes `["code"]`, `["authorization_code"]`, and `"private_key_jwt"` respectively for the last three fields. |
| `subject_type` | Configure `pairwise` for the demo. Sweden Connect assigns `public` if the RP omits the field. When registering an optional `sector_identifier_uri` for pairwise subjects, its HTTPS JSON document must list the registered redirect URIs. |
| `id_token_signing_alg_values_supported`, `userinfo_signing_alg_values_supported` | Tunnelbana publishes its configured ID-token list and its single registered UserInfo algorithm. The trust anchor adds the federation algorithms during resolution and removes `id_token_signed_response_alg` and `userinfo_signed_response_alg` from resolved metadata. Check the selected OP's actual signing algorithms against the backend's verification settings. |

The demo also publishes `client_registration_types = ["automatic"]`, the requested `scope`, `require_auth_time = true`, and signing algorithms for request objects and client assertions. `organization_uri` is recommended and `policy_uri` is optional. If registering encrypted responses, configure the matching recipient key and `id_token_encryption` or `userinfo_encryption` so Tunnelbana publishes the corresponding `_encrypted_response_alg` and `_encrypted_response_enc` fields. The RP's own signed trust marks belong at the statement root. [Algorithm policy (§4.1)](https://docs.swedenconnect.se/federation/oidc-metadata-requirements.html#section-4.1) · [Operator assignments (§6)](https://docs.swedenconnect.se/federation/oidc-metadata-requirements.html#section-6)

### Published RP entity configuration

Compare the signed statement with the TOML above when checking registration. The decoded example shows the demo's SverigeID configuration before the switch to the Reference OP. With the Reference OP settings below, the registered ID-token and UserInfo response algorithms are RS256. The timestamps and public key coordinates are a snapshot. Each `trust_mark` string stands for the full signed JWT issued for that type. [Live signed entity configuration](https://tunnelbana-demo.labb.sunet.se/svidsandbox/.well-known/openid-federation)

**Protected header**

```json
{
  "alg": "ES384",
  "kid": "svidsandbox-federation-1",
  "typ": "entity-statement+jwt"
}
```

**Statement payload**

```json
{
  "iss": "https://tunnelbana-demo.labb.sunet.se/svidsandbox",
  "sub": "https://tunnelbana-demo.labb.sunet.se/svidsandbox",
  "exp": 1795877705,
  "iat": 1795791305,
  "authority_hints": [
    "https://fed.sandbox.swedenconnect.se/im-reg-sc"
  ],
  "jwks": {
    "keys": [
      {
        "kty": "EC",
        "use": "sig",
        "alg": "ES384",
        "kid": "svidsandbox-federation-1",
        "crv": "P-384",
        "x": "Jwwk0iguaLuk5VpuMz3wphGDOgP2V8TYREbeFBBW-UzcIx7bnrOnkFClTBpBxJ_k",
        "y": "05E5seNIJZ_ZaKXcweZ_MKG90ohxtwzlk0B5OBgsinwdIKu9ANpMSxmrwwRnENS6"
      }
    ]
  },
  "metadata": {
    "openid_relying_party": {
      "organization_identifier": "urn:glue:iso6523:0007:2021005208",
      "organization_name#en": "The Swedish Research Council",
      "organization_name#sv": "Vetenskapsrådet",
      "policy_uri": "https://wiki.sunet.se/display/SWAMID/SWAMID+Entity+Category+Release+Check+-+Privacy+Policy",
      "display_name": "Tunnelbana demo",
      "display_name#en": "Tunnelbana demo",
      "display_name#sv": "Tunnelbana demo",
      "client_name": "Tunnelbana demo",
      "client_name#en": "Tunnelbana demo",
      "client_name#sv": "Tunnelbana demo",
      "client_uri": "https://tunnelbana-demo.labb.sunet.se",
      "logo_uri": "https://tunnelbana-demo.labb.sunet.se/assets/tunnelbana.png",
      "contacts": [
        "kushal@sunet.se"
      ],
      "require_auth_time": true,
      "subject_type": "pairwise",
      "request_object_signing_alg": "ES384",
      "token_endpoint_auth_signing_alg": "ES384",
      "userinfo_signed_response_alg": "ES384",
      "userinfo_signing_alg_values_supported": [
        "ES384"
      ],
      "id_token_signing_alg_values_supported": [
        "RS256",
        "RS384",
        "RS512",
        "ES256",
        "ES384",
        "ES512"
      ],
      "redirect_uris": [
        "https://tunnelbana-demo.labb.sunet.se/svidsandbox/callback"
      ],
      "client_registration_types": [
        "automatic"
      ],
      "id_token_signed_response_alg": "ES384",
      "response_types": [
        "code"
      ],
      "grant_types": [
        "authorization_code"
      ],
      "token_endpoint_auth_method": "private_key_jwt",
      "jwks": {
        "keys": [
          {
            "kty": "EC",
            "use": "sig",
            "alg": "ES384",
            "kid": "svidsandbox-protocol-1",
            "crv": "P-384",
            "x": "DSDg0OFVjc1Y99yX24yg8rm9h0FwiQn_bp3KC5aI6rEBUXwf7A3bMzvTizIKF-Cv",
            "y": "S2nwc4_vDkXqP-912Cfjj5spMH6_6Lue2cENt7Nz7sC7jokTsLe0CzQhtVs1NshB"
          }
        ]
      },
      "scope": "openid profile https://id.oidc.se/scope/naturalPersonNumber https://id.oidc.se/scope/naturalPersonInfo",
      "organization_name": "Vetenskapsrådet",
      "organization_uri": "https://www.sunet.se/"
    }
  },
  "trust_marks": [
    {
      "trust_mark_type": "https://id.swedenconnect.se/contract/sc/eid-authorization-system",
      "trust_mark": "<signed JWT for eid-authorization-system>"
    },
    {
      "trust_mark_type": "https://id.swedenconnect.se/tm-prop/public-body",
      "trust_mark": "<signed JWT for public-body>"
    }
  ]
}
```

**How the published fields are set**

| Published fields | Source |
| --- | --- |
| Header `alg`, `kid`, `typ` | The federation signing key supplies the algorithm and key ID. Tunnelbana sets the entity statement type. |
| `iss`, `sub` | Both identify this RP. The entity ID defaults to the module base URL, or you can set `backend.config.entity_id`. The upstream `op_entity_id` controls which provider handles login. |
| `iat`, `exp` | Tunnelbana sets the issue time when it signs and adds `federation.entity_configuration_lifetime` in seconds for the expiry. |
| Root `jwks`, `authority_hints`, `trust_marks` | The federation signing key supplies the public JWK. The federation table supplies the registration intermediate and the RP's issued marks. The trust anchor's pinned key is a local verification input. |
| `metadata.openid_relying_party` presentation fields | The presentation table supplies localized names, organization identifier, contacts and URLs. The federation table supplies the default organization name and organization URI in this example. |
| `require_auth_time`, `subject_type`, `scope` | The Sweden Connect profile requests authentication time. The backend supplies the registered subject type and scopes. |
| `redirect_uris` | Tunnelbana appends `/callback` to the backend's public module base URL. |
| `client_registration_types`, `response_types`, `grant_types`, `token_endpoint_auth_method` | The federation RP publishes automatic registration, code responses, the authorization code grant and private-key JWT client authentication. |
| RP `jwks`, `request_object_signing_alg`, `token_endpoint_auth_signing_alg` | The backend protocol key signs request objects and client assertions. The RP role publishes its public key and signing algorithm. |
| `id_token_signed_response_alg`, `id_token_signing_alg_values_supported` | The backend configures the registered ID-token algorithm and the list accepted during verification. |
| `userinfo_signed_response_alg`, `userinfo_signing_alg_values_supported` | Tunnelbana publishes the registered ID-token algorithm as the single accepted UserInfo signing algorithm. |

### Authorize this issuer through scqa

The demo's ordinary SWAMID logins require a nonempty `subjectid`. Its Sandbox exception admits an authenticated user when the response came through `scqa`. Place the frontend marker before the authorization check in the response pipeline. Merge these rules into the existing authorization microservice if one is already configured.

```toml
[[microservice]]
name = "ScqaFrontend"
type = "static_attributes_for_virtual_idp"
[microservice.config.static_attributes_for_virtual_idp.default.default]
scqa_login = []
personalidentitynumber = []
[microservice.config.static_attributes_for_virtual_idp.default.scqa]
scqa_login = ["yes"]

[[microservice]]
name = "AttributeAuthorization"
type = "attribute_authorization"
[microservice.config]
force_attributes_presence_on_allow = true
[microservice.config.attribute_allow.default.default]
subjectid = ["."]
[microservice.config.attribute_allow.default."https://op.sandbox.sverigeid.se"]
scqa_login = ["^yes$"]
```

### Test with the Sandbox Reference OP

If you cannot complete a login with the SverigeID Sandbox OP, you can exercise the same Tunnelbana RP and SAML frontend against the Sweden Connect Reference OP. This is a manual choice per backend. A successful test covers the Reference OP path; testing SverigeID itself still requires a login with that issuer. [Sweden Connect Sandbox providers](https://sandbox.swedenconnect.se/home/oidc)

1. In the existing `svidsandbox` backend's `[backend.config]` table, replace the issuer and response algorithm with the values below. The demo keeps its six-algorithm ID-token allowlist. Its callback accepts a single signing algorithm for UserInfo, selected by `id_token_signed_response_alg`. With the Reference OP, the demo initially rejected RS256 at the callback even though RS256 was already on its ID-token list. Login succeeded with these settings.

   ```toml
   op_entity_id = "https://ref.sandbox.swedenconnect.se"
   id_token_signed_response_alg = "RS256"
   ```

2. In `AttributeAuthorization`, replace the SverigeID issuer table with the following table. An issuer without an exact match falls through to the default SWAMID `subjectid` rule. Keep `scqa` pinned to `svidsandbox`.

   ```toml
   [microservice.config.attribute_allow.default."https://ref.sandbox.swedenconnect.se"]
   scqa_login = ["^yes$"]
   ```

3. Restart Tunnelbana from the demo Compose directory with `docker compose restart tunnelbana`. Open a **fresh login** from the QA service provider and select `scqa`. The browser should reach `https://ref.sandbox.swedenconnect.se/oidc/authorize`. Complete authentication there and check the attributes returned to the SAML service. Changing issuers can change the user's account identifier. [Start a fresh login at QA Release Check](https://release-check.qa.swamid.se/Shibboleth.sso/Login?entityID=https%3A%2F%2Ftunnelbana-demo.labb.sunet.se%2Fscqa&target=https%3A%2F%2Frelease-check.qa.swamid.se%2Fresult)

The RP keeps its registered entity ID, callback, trust marks, Sandbox trust anchor and ES384 federation and protocol keys. To switch back, restore the SverigeID issuer in **both** tables, restore the response algorithm for that OP (ES384 in the SverigeID example above), restart, and begin a new login.

### Release the personal number to QA Release Check

The demo requests `https://id.oidc.se/scope/naturalPersonNumber` alongside `openid profile https://id.oidc.se/scope/naturalPersonInfo`. If the OP returns a personal number for the test identity, two additional settings carry it to the **Attributes** page of the main QA Release Check service.

In `config/attributes.toml`, add or extend the mapping for this internal attribute:

```toml
[attributes.personalidentitynumber]
openid = ["https://id.oidc.se/claim/personalIdentityNumber"]
saml = { names = ["personalIdentityNumber"], oid = "urn:oid:1.2.752.29.4.13", friendly_name = "personalIdentityNumber" }
```

In `config/proxy.toml`, under the `scqa` SAML frontend, use the URI attribute name format (`attribute_name_format = "uri"` in `[frontend.config]`). Configure the default and exact-SP policies as follows. The SP-specific list replaces the default, so repeat the name attributes you want to release.

```toml
[frontend.config.policy.default]
attribute_restrictions = ["givenname", "surname", "name"]

[frontend.config.policy."https://release-check.qa.swamid.se/shibboleth"]
attribute_restrictions = ["givenname", "surname", "name", "personalidentitynumber"]
```

The frontend marker above clears `personalidentitynumber` for other frontends. Within `scqa`, other service providers receive the names-only default. The main Release Check, MFA, and entity-category tests have separate SP entity IDs. After restarting with both files, start a new main Release Check login and look for `personalIdentityNumber` on the Attributes page. An absent value can indicate that the test identity supplied no number or that a different SP policy matched. [QA Release Check](https://release-check.qa.swamid.se/)

### Subject, signature and assurance settings

Under `backend.config`, `subject_type` selects the upstream subject type (`public` by default, or `pairwise`). The RP accepts ID tokens signed with `id_token_signed_response_alg` (default `RS256`). To accept additional algorithms, set `id_token_signing_alg_values_supported` to a list that includes the registered algorithm. Tunnelbana publishes this list and enforces it during ID-token verification. Signed UserInfo uses `id_token_signed_response_alg`. Both responses must identify the same user.

Use `backend.config.presentation` for the organization identifier, localized organization names, and privacy policy URL. For a Swedish organization, set `organization_identifier` to `urn:glue:iso6523:0007:` followed by its ten-digit organization number without a hyphen.

Each certified Swedish LoA requires its corresponding resolver-endorsed trust mark. Tunnelbana verifies the LoA4 mark before releasing LoA3 for a LoA4 login. Use `required_trust_marks` for additional admission requirements. Essential ACR requirements that cannot be met end the transaction.

When an `accr` microservice sets a minimum for the frontend, the signed upstream request includes the assurance levels that satisfy both operator policy and the client's essential `acr` constraint. The callback checks the returned ID token against those levels even when the client requested no particular level.

For rollover, add the next public signing JWK to `rotation.signing_public_jwks` with `use="sig"` and its own `kid`. Allow peer caches to refresh before switching the active signing key. Configure current private encryption JWKs under `rotation.decryption_jwk_paths`. Move a retired key to `rotation.retired_decryption_jwk_paths` until cached registrations and in-flight requests have expired. To register encrypted upstream responses, set `id_token_encryption` or `userinfo_encryption` on the backend to an inline table such as `{ alg="RSA-OAEP-256", enc="A256GCM" }`. A matching active private recipient key is required.

## Running the local release gate

Place Sweden Connect's `local-federation` checkout beside Tunnelbana. Check out local-federation commit `5b67bedb42230fff6b8d89fb26c80e2084d2eb7b` (v1.0.1). On Linux, install Docker Compose, Rust, a Python installation usable by PyO3, uv, bubblewrap, keytool, curl, xmlsec1, and Chrome. Use `CHROME_BIN` to select a different Chromium installation. Local replicas use bubblewrap for process-local DNS. GitHub Actions maps the fixture hostname to loopback on its disposable runner. Both modes use the fixture certificate. The documented reference ports and ports 11050–11052 must be available.

Run `just test-sverigeid-local`. The command creates disposable entities and keys, waits for signed resolution and discovery, runs the browser checks and tears down the fixture. `target/sverigeid-local-report.json` records the checks, reference image digests, Tunnelbana revision and local changes, and the crates.io versions and checksums for Grindvakt and jose-rs from `Cargo.lock`.

The suite exercises upstream issuer and audience checks, signed UserInfo, encrypted responses, and downstream assurance release. [Recorded local verification](sverigeid-local-report.json)

Sandbox transactions require a registered RP and a test identity. Complete login and approval there before claiming actual SverigeID interoperability. [Sweden Connect federation environments](https://docs.swedenconnect.se/federation/oidf-structure.html) · [SverigeID onboarding](https://www.swedenconnect.se/anslut-till-sweden-connect/erbjud-inloggning-med-sverigeid)
