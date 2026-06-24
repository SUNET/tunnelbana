# Attributes and transforms

Identity is carried as **attributes** - `mail`, `givenName`, an `eduPersonPrincipalName`,
a subject identifier. Every protocol spells those differently: OIDC calls the
mailbox `email`, SAML calls it `mail` or `urn:oid:0.9.2342.19200300.100.1.3`.
tunnelbana never translates one protocol's names directly into another's.
Instead it pivots through a single neutral vocabulary - **internal attribute
names** - and lets a small set of response-path [micro-services](micro-services.md)
reshape those internal values before they reach the downstream application.

This chapter is the end-to-end story: the map that defines the vocabulary, how
attributes flow in and back out, how the subject id is built, and the transform
services that sit in the middle. It complements the per-key
[built-in plugin reference](built-in-plugins.md) and the
[micro-services chapter](micro-services.md).

## The pivot: one internal name in the middle

A frontend and a backend never see each other's protocol attributes. The
backend maps what an upstream IdP/OP asserted **into** internal names; any
micro-services operate **on** internal names; the frontend maps internal names
**out** into what the downstream RP/SP expects. The internal name is the only
thing the middle of the proxy ever deals with.

```text
  upstream IdP/OP                tunnelbana                 downstream RP/SP
  ───────────────   ┌──────────────────────────────────┐   ────────────────
  eduPersonPrincipalName ─► to_internal ─► edupersonprincipalname
  mail               ─►  (backend)    ─►  mail   ─┐
                                                  │  micro-services
                                                  │  (transform internal
                                                  │   names in place)
                                                  ▼
                                          edupersonprincipalname ─► from_internal ─► sub
                                          mail                   ─► (frontend)   ─► email
```

Two consequences fall out of this and are worth internalizing early:

- An attribute that has **no entry in the map is dropped** at both edges -
  unmapped inbound attributes never become internal names, and internal names
  the target profile does not list are not emitted. (The SAML backend's
  `passthrough_unmapped_attributes` is the one escape hatch for inbound, and
  even then frontends still drop what they cannot name.)
- Because micro-services act on internal names, the **same** transform config
  works regardless of whether the flow is OIDC-to-SAML, SAML-to-OIDC,
  SAML-to-SAML, or OIDC-to-OIDC.

## The map that drives it: `attributes.toml`

The file pointed at by the top-level `attributes` key declares, for each
internal attribute, the external names used by each protocol profile. The
profiles are `openid` and `saml`. This mirrors SATOSA's
`internal_attributes.yaml`.

```toml
# config/attributes.toml
user_id_from_attrs = ["edupersonprincipalname"]

[attributes.mail]
openid = ["email"]
saml   = { names = ["mail", "email", "emailAddress"], oid = "urn:oid:0.9.2342.19200300.100.1.3", friendly_name = "mail" }

[attributes.givenname]
openid = ["given_name"]
saml   = ["givenName"]                 # plain-list form, still valid

[attributes.edupersonprincipalname]
openid = ["sub"]
saml   = { names = ["eduPersonPrincipalName"], oid = "urn:oid:1.3.6.1.4.1.5923.1.1.1.6", friendly_name = "eduPersonPrincipalName" }
```

- Each `[attributes.<internal>]` table lists the external names per profile.
- A profile entry is either a **plain list** of names (`["given_name"]`, the
  legacy form) or a **detailed table** with `names`, an `oid` URN, and a
  `friendly_name`. The OID and FriendlyName are matched on the way *in*, and
  they feed the SAML frontend's `attribute_name_format = "uri"` mode, which
  emits OID-named attributes with a FriendlyName - what SWAMID SPs expect.
- The order of `names` matters on the way *out*: the **first** name is the
  canonical one the attribute is emitted under for that profile (see
  [Outbound](#outbound-from_internal-internal-to-protocol)).

## Inbound: `to_internal` (protocol to internal)

When a backend receives a response, it asks the map to fold the protocol
attributes into internal names. For each internal attribute, the external
`names` (plus the `oid` and `friendly_name`, when present) are tried in order,
and values from **every** matching external name are collected, deduplicated,
and order-preserving.

So a SAML assertion that carries the mailbox under both `mail` and
`urn:oid:0.9.2342.19200300.100.1.3` contributes both, deduplicated, to the
single internal `mail`:

```text
SAML assertion attributes          internal (profile = "saml")
  urn:oid:0.9.2342...100.1.3  ─┐
  mail                        ─┴─►  mail = ["anna@example.org"]
  eduPersonPrincipalName      ───►  edupersonprincipalname = ["anna@example.org"]
  someUnknownAttr             ───►  (dropped: no map entry)
```

An internal attribute with no matching external value is simply absent (not an
empty list).

## Outbound: `from_internal` (internal to protocol)

On the way out, each internal attribute is emitted under the **first** external
name listed for the target profile - its canonical name. Internal attributes
the target profile does not list are not emitted at all.

The same internal set, emitted to an OIDC RP and to a SAML SP:

```text
internal                          OIDC (profile = "openid")     SAML (profile = "saml")
  mail = [...]                ─►  email                     ─►  mail
  edupersonprincipalname = .. ─►  sub                       ─►  eduPersonPrincipalName
  givenname = [...]           ─►  given_name                ─►  givenName
```

For SAML with `attribute_name_format = "uri"`, the attribute is named by its
`oid` and tagged with the `friendly_name`; in `basic` mode the first plain name
is used.

## Composing the subject id (the OIDC `sub`)

`user_id_from_attrs` lists the internal attributes that compose the stable
subject identifier when a backend does not hand one over directly. The first
value of each named attribute is taken and the parts are joined with a colon
(`:`); if any part is missing, no composed id is produced and the proxy falls
back to whatever the backend supplied.

```toml
user_id_from_attrs = ["edupersonprincipalname"]   # sub = the eppn
# user_id_from_attrs = ["edupersonprincipalname", "schachomeorganization"]
#                                                  # sub = "anna@x.org:x.org"
```

Subject-id handling differs by backend, and the rules are covered where they
apply:

- The **SAML SP backend** in MDQ mode prefers the `user_id_from_attrs`
  composition, then falls back to the raw `NameID`; a persistent `NameID` is
  scoped by the upstream IdP issuer so two IdPs minting the same value do not
  collide. See [configuration](configuration.md#the-attribute-map).
- The **OIDC-Federation RP backend** reports the subject as `pairwise`.
- The [`primary_identifier`](micro-services.md#primary_identifier-ordered-identifier-candidates)
  and [`hasher`](micro-services.md#hasher-pseudonymizing-subject-ids-and-attributes)
  micro-services can rebuild or pseudonymize the subject id on the response
  path - the only place the subject id (as opposed to an ordinary attribute)
  can be rewritten.

> The composed subject id is taken **before** the response-path micro-services
> run, so an `attribute_processor` that rewrites the *released* eppn does not
> change a `sub` already composed from it. Use `hasher` or `primary_identifier`
> when you mean to change the subject id itself.

## SAML in front and behind: do attributes still transform?

Yes. Even a SAML-to-SAML flow round-trips through internal names, with three
consequences:

1. **Name-format normalization.** Inbound `urn:oid:…` / FriendlyName attributes
   land on internal names and are re-emitted under the frontend's configured
   `attribute_name_format` - so a `uri`-named upstream can feed a `basic`-named
   downstream and vice versa.
2. **Unmapped attributes drop.** Anything without a map entry disappears at the
   pivot (unless the backend sets `passthrough_unmapped_attributes`, and even
   then the frontend only emits what it can name).
3. **Subject re-derivation.** The downstream NameID/subject is derived from the
   internal subject id, not blindly copied from the upstream NameID.

## Transforming internal attributes: the response-path pipeline

Between `to_internal` and `from_internal`, the ordered list of micro-services
runs on the **response path**, each receiving and returning the internal
attribute set. This is tunnelbana's attribute-transform pipeline; the
[micro-services chapter](micro-services.md) is the full treatment and the
[built-in plugin reference](built-in-plugins.md#micro-service-types) is the
config reference. In brief, the transform-capable services are:

| Service | What it does to internal attributes |
| --- | --- |
| [`static_attributes`](built-in-plugins.md#static_attributes---inject-fixed-attributes) | Adds fixed attributes (without overwriting existing ones). |
| [`rename_attributes`](built-in-plugins.md#rename_attributes---internal-renames-adr-0018) | Renames an internal attribute (merging values on collision). |
| [`attribute_processor`](built-in-plugins.md#attribute_processor---value-transform-chains-adrs-0011-0020) | Rewrites values through per-attribute chains: `regex_sub`, `hash`, `scope`, `scope_extractor`, `scope_remover`, `gender`. |
| [`attribute_generation`](built-in-plugins.md#attribute_generation---synthesized-attributes-adr-0019) | Synthesizes new attributes from Tera templates over the existing set. |
| [`filter_attributes`](built-in-plugins.md#filter_attributes---attribute-allow-list-adr-0014) | Allow-lists whole attributes, globally or per requester. |
| [`filter_attribute_values`](built-in-plugins.md#filter_attribute_values---value-level-regex-filter-adr-0017) | Drops individual values failing a regex, per provider/requester. |
| [`hasher`](built-in-plugins.md#hasher---subject-id--attribute-pseudonymization-adr-0021) | Salted-hashes the subject id and/or selected attributes per requester. |
| [`primary_identifier`](built-in-plugins.md#primary_identifier---ordered-identifier-candidates-adr-0022) | Builds one canonical identifier from an ordered candidate list. |
| [`attribute_authorization`](built-in-plugins.md#attribute_authorization---regex-allowdeny-gate-adr-0012) | Rejects the flow when attributes fail regex allow/deny rules. |

A typical shaping chain - synthesize, then rewrite, then police, then filter -
is ordered exactly as listed in the config (the order is the same on both
paths, no automatic reversal). Two rules of thumb:

- Put services that **produce** values (`static_attributes`,
  `attribute_generation`, `attribute_processor`) before services that **match
  on** them (`attribute_authorization`, `filter_attribute_values`).
- Put `filter_attributes` / `filter_attribute_values` near the **end**, after
  anything that needs to read an attribute you are about to drop.

Most of these can be scoped to one SP/RP or one upstream IdP/OP through their
config nesting - see
[Scoping a service to specific SPs and IdPs](micro-services.md#scoping-a-service-to-specific-sps-and-idps).

## `email_verified`: the OIDC requirement with no SAML equivalent

OpenID Connect defines a boolean
[`email_verified`](https://openid.net/specs/openid-connect-core-1_0.html#StandardClaims)
claim: "True if the End-User's e-mail address has been verified." Many OIDC
relying parties **gate signup on it**. [Vaultwarden](https://github.com/dani-garcia/vaultwarden)
(and OIDCWarden) is the canonical example: by default it refuses to provision an
account from an SSO login whose `email_verified` is missing or `false`, unless
the operator sets `SSO_ALLOW_UNKNOWN_EMAIL_VERIFICATION=true`.

The SAML world has **no equivalent attribute**. A SAML IdP asserts `mail`, but
there is no standard "this mailbox was verified" flag - the assurance is carried
out-of-band, in the federation's registration practices, not in the assertion.
So when tunnelbana fronts an OIDC RP like Vaultwarden with a **SAML SP
backend**, the upstream assertion simply cannot supply `email_verified`, and the
RP blocks the login.

tunnelbana closes the gap by **asserting the claim itself**, with a one-line
`static_attributes` micro-service, and mapping it `openid`-only so it surfaces
only on the OIDC side:

```toml
# proxy.toml - assert email_verified for every flow.
[[microservice]]
type = "static_attributes"
name = "StaticAttributes"
  [microservice.config.attributes]
  email_verified = ["true"]
```

```toml
# attributes.toml - openid-only, so the SAML frontend never emits it.
[attributes.email_verified]
openid = ["email_verified"]
```

The OP coerces the released string into a real JSON boolean on the wire (OIDC
Core §5.1): `email_verified`, like `phone_number_verified`, is emitted as
`true`/`false`, not the string `"true"`. (`"true"`, `"1"`, `"yes"`, `"on"` map
to `true`; `"false"`, `"0"`, `"no"`, `"off"` to `false`; anything else is left
as a string rather than fabricating a value.) With this in place the Vaultwarden
RP sees `email_verified: true` and `SSO_ALLOW_UNKNOWN_EMAIL_VERIFICATION` is not
needed.

> **Security note - when is asserting `email_verified = true` legitimate?**
> Injecting the claim unconditionally is only honest when the **upstream
> assurance actually guarantees it**, because the static service cannot
> distinguish a verified mailbox from an unverified one - it asserts `true` for
> every flow. It is justified when:
>
> - the mailbox is **institutionally managed** and released under a known
>   assurance profile and
> - the backend only ever talks to such IdPs (a closed federation via MDQ with
>   signature-verified metadata), so an IdP that lets users self-assert an
>   arbitrary unverified `mail` cannot reach this RP.
>
> It is **not** safe to blanket-assert `email_verified = true` when the upstream
> is an open or social IdP (or in a federation) that permits unverified addresses, or when `mail`
> can be user-edited - a relying party that trusts `email_verified` for account
> linking could then be tricked into binding a session to someone else's
> mailbox. If different upstreams have different assurance, do not assert it
> globally: scope the release (a per-IdP
> [`attribute_generation`](built-in-plugins.md#attribute_generation---synthesized-attributes-adr-0019)
> recipe, or split the trusted IdP into its own backend) so only flows from a
> verifying IdP carry the claim. Treat `email_verified` as a claim about the
> *federation's* practices, and only emit it where those practices hold.

## Where the mapping fits in a real flow

Putting it together, a SAML-backed OIDC login looks like this:

```text
RP ─► OIDC OP frontend ─► [request-path micro-services] ─► SAML SP backend ─► IdP
                                                                                │
IdP assertion ─► backend: to_internal("saml", …)  ────────────────────────────┘
                          │  internal attributes + subject id
                          ▼
              [response-path micro-services, in config order]
                  static_attributes  (inject email_verified)
                  attribute_processor (rewrite scoped values)
                  attribute_authorization (require subject id)
                          │  shaped internal attributes
                          ▼
              OIDC OP frontend: from_internal("openid", …) + flatten_claims
                          │  email, email_verified=true (bool), sub, …
                          ▼
                         id_token / userinfo ─► RP
```

The two tutorials show this wired up against real federations:
[SAML and OIDC over a SWAMID SP backend](tutorial-saml-mdq.md) (where the
`email_verified` + Vaultwarden case is live) and
[a SAML IdP over an OpenID Federation RP backend](tutorial-oidc-federation.md).
