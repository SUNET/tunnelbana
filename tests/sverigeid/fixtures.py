"""Registered test peers for invariants the independent clients cannot vary."""

import base64
import copy
import hashlib
import json
import secrets
import subprocess
import tempfile
import threading
import time
from urllib.parse import parse_qs, urlencode, urlsplit

import jwt
from federation import BASE, HOST, fetch
from jwcrypto import jwe, jwk

LOA = "http://id.elegnamnden.se/loa/1.0/loa"
RP = BASE + "/rp"
KINDS = {"sector-a", "sector-b", "probe-op", "expired-op"}
PIN = "https://id.oidc.se/claim/personalIdentityNumber"
SIGN = "https://id.oidc.se/param/signRequest"
APPROVAL = "https://id.oidc.se/scope/signApproval"


def challenge(verifier):
    return (
        base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest())
        .decode()
        .rstrip("=")
    )


class Peers:
    def __init__(self, directory):
        self.directory = directory
        self.codes = {}
        self.tokens = {}
        self.lock = threading.Lock()
        self.mode = "valid"
        self.original_time = 0
        self.marks = {}
        self.templates = {}
        self.metadata_ready = False
        self.auth_calls = 0
        self.errors = []

        self.recipients = []
        for label in ["initial", "next"]:
            recipient = jwk.JWK.generate(kty="RSA", size=2048)
            recipient.update(kid=recipient.thumbprint(), use="enc", alg="RSA-OAEP-256")
            path = directory / f"recipient-{label}.jwk"
            path.write_text(recipient.export(private_key=True))
            self.recipients.append(path)

    def withdraw_mark(self, role, mark_type):
        config = self.directory / "config/openid-federation/trust-mark-issuers.json"
        issuers = json.loads(config.read_text())
        (mark,) = [
            m
            for issuer in issuers
            for m in issuer["trust-marks"]
            if m["trust-mark-type"] == mark_type
        ]
        (grant,) = [
            g for g in mark["trust-mark-subjects"] if g["sub"] == BASE + "/" + role
        ]
        mark["trust-mark-subjects"].remove(grant)
        config.write_text(json.dumps(issuers))
        self.marks[role] = [
            m for m in self.marks[role] if m["trust_mark_type"] != mark_type
        ]

    def encryption_config(self, rotated):
        initial, next_key = self.recipients
        fields = [
            'id_token_encryption = {alg="RSA-OAEP-256",enc="A256GCM"}',
            'userinfo_encryption = {alg="RSA-OAEP-256",enc="A256GCM"}',
            f'rotation.decryption_jwk_paths = ["{next_key if rotated else initial}"]',
        ]
        if rotated:
            fields.append(f'rotation.retired_decryption_jwk_paths = ["{initial}"]')
        return "\n".join(fields)

    def response(self, role, claims, recipient, plain):
        wire = self.sign(role, claims)
        if plain:
            return wire
        message = jwe.JWE(
            wire.encode(),
            protected={
                "alg": "RSA-OAEP-256",
                "enc": "A256GCM",
                "kid": recipient["kid"],
                "cty": "JWT",
            },
        )
        message.add_recipient(jwk.JWK(**recipient))
        return message.serialize(compact=True)

    def keys(self, role, protocol=True):
        key = json.loads(
            (
                self.directory
                / ("tunnelbana-" + role + ("-sign" if protocol else "") + ".jwk")
            ).read_text()
        )
        return jwt.PyJWK.from_dict(key).key, dict(
            {k: v for k, v in key.items() if k != "d"}, use="sig", alg="ES256"
        )

    def sign(self, role, claims, typ="JWT", protocol=True):
        key, public = self.keys(role, protocol)
        return jwt.encode(
            claims, key, algorithm="ES256", headers={"typ": typ, "kid": public["kid"]}
        )

    def prepare_metadata(self):
        for base_role in ("rp", "op"):
            self.templates[base_role] = jwt.decode(
                fetch(
                    self.directory,
                    BASE + "/" + base_role + "/.well-known/openid-federation",
                ),
                options={"verify_signature": False},
            )
        for role in KINDS:
            self.entity(role)
        self.metadata_ready = True

    def entity(self, role):
        is_rp = role.startswith("sector")
        base_role = "rp" if is_rp else "op"
        entity = BASE + "/" + role
        template = copy.deepcopy(self.templates[base_role])
        public = self.keys(role)[1]
        template.update(
            iss=entity, sub=entity, jwks={"keys": [self.keys(role, False)[1]]}
        )
        if role not in self.marks:
            entries = []
            source = self.directory / "config/openid-federation/trust-mark-issuers.json"
            for issuer in json.loads(source.read_text()):
                for m in issuer["trust-marks"]:
                    if any(
                        subject["sub"] == entity for subject in m["trust-mark-subjects"]
                    ):
                        kind = m["trust-mark-type"]
                        wire = fetch(
                            self.directory,
                            issuer["entity-identifier"]
                            + "/trust_mark?"
                            + urlencode({"sub": entity, "trust_mark_type": kind}),
                        )
                        entries.append(
                            {
                                "trust_mark_type": kind,
                                "trust_mark": wire.decode().strip(),
                            }
                        )
            self.marks[role] = entries
        template["trust_marks"] = self.marks[role]
        if is_rp:
            meta = template["metadata"]["openid_relying_party"]
            # These RPs register a signing key only. Upstream encryption
            # belongs to the separate RP that redeems at the probe OP.
            for prefix in ("id_token", "userinfo"):
                for field in ("alg", "enc"):
                    meta.pop(f"{prefix}_encrypted_response_{field}", None)
            meta.update(
                jwks={"keys": [public]},
                subject_type="pairwise",
                redirect_uris=[f"https://{role}.example.test/callback"],
                id_token_signed_response_alg="ES256",
                userinfo_signed_response_alg="ES256",
                scope="openid " + APPROVAL,
            )
        else:
            meta = template["metadata"]["openid_provider"]
            meta.update(
                issuer=entity,
                authorization_endpoint=entity + "/authorize",
                token_endpoint=entity + "/token",
                userinfo_endpoint=entity + "/userinfo",
                jwks_uri=entity + "/keys",
            )
        now = int(time.time())
        template.update(
            iat=now - 120, exp=now - 100 if role == "expired-op" else now + 600
        )
        return self.sign(role, template, "entity-statement+jwt", False)

    def verify_expired_leaf(self):
        entity = BASE + "/expired-op"
        wire = fetch(self.directory, entity + "/.well-known/openid-federation")
        statement = jwt.decode(
            wire,
            self.keys("expired-op", False)[0].public_key(),
            algorithms=["ES256"],
            issuer=entity,
            options={"verify_exp": False},
        )
        assert (
            statement["sub"] == entity
            and statement["iat"] < statement["exp"] < time.time()
        )

    def serve(self, handler, role, endpoint):
        def answer(status, body, content_type, location=None):
            payload = body.encode()
            handler.send_response(status)
            if location:
                handler.send_header("Location", location)
            handler.send_header("Content-Type", content_type)
            handler.send_header("Content-Length", str(len(payload)))
            handler.end_headers()
            handler.wfile.write(payload)

        issuer = BASE + "/" + role
        if endpoint == ".well-known/openid-federation":
            if not self.metadata_ready:
                return answer(503, "", "text/plain")
            return answer(200, self.entity(role), "application/entity-statement+jwt")
        if endpoint == "keys":
            return answer(
                200, json.dumps({"keys": [self.keys(role)[1]]}), "application/json"
            )
        query = urlsplit(handler.path).query
        if handler.command == "POST":
            query = handler.rfile.read(
                int(handler.headers.get("Content-Length", 0))
            ).decode()
        params = {name: items[0] for name, items in parse_qs(query).items()}
        if endpoint == "authorize":
            jar = jwt.decode(
                params["request"],
                self.keys("rp")[0].public_key(),
                algorithms=["ES256"],
                issuer=RP,
                audience=issuer,
            )
            assert (
                jar["redirect_uri"] == RP + "/callback"
                and jar["code_challenge_method"] == "S256"
            )
            self.auth_calls += 1
            code = secrets.token_urlsafe(24)
            with self.lock:
                metadata = jwt.decode(
                    fetch(self.directory, RP + "/.well-known/openid-federation"),
                    options={"verify_signature": False},
                )["metadata"]["openid_relying_party"]
                assert (
                    metadata["id_token_encrypted_response_alg"] == "RSA-OAEP-256"
                    and metadata["userinfo_encrypted_response_enc"] == "A256GCM"
                )
                self.codes[code] = (
                    jar,
                    next(k for k in metadata["jwks"]["keys"] if k.get("use") == "enc"),
                )
            return answer(
                302,
                "",
                "text/plain",
                RP
                + "/callback?"
                + urlencode({"code": code, "state": jar["state"], "iss": issuer}),
            )
        now = int(time.time())
        if endpoint == "token":
            jwt.decode(
                params["client_assertion"],
                self.keys("rp")[0].public_key(),
                algorithms=["ES256"],
                issuer=RP,
                audience=[issuer, issuer + "/token"],
            )
            with self.lock:
                jar, recipient = self.codes.pop(params["code"])
            assert jar["code_challenge"] == challenge(params["code_verifier"])
            self.original_time = now - 97
            claims = {
                "iss": issuer,
                "sub": "test-subject",
                "aud": RP,
                "nonce": jar["nonce"],
                "auth_time": self.original_time,
                "acr": LOA + "3",
                "iat": now,
                "exp": now + 180,
            }
            if self.mode == "wrong-issuer":
                claims["iss"] = BASE + "/another-op"
            if self.mode == "wrong-audience":
                claims["aud"] = BASE + "/another-rp"
            if self.mode == "achieved-loa4":
                claims["acr"] = LOA + "4"
            if self.mode == "unmet-acr":
                claims["acr"] = LOA + "2"
            if SIGN in jar:
                claims[PIN] = (
                    "100000000002" if self.mode == "wrong-signer" else "100000000001"
                )
            token = secrets.token_urlsafe(24)
            self.tokens[token] = recipient
            return answer(
                200,
                json.dumps(
                    {
                        "access_token": token,
                        "token_type": "Bearer",
                        "expires_in": 180,
                        "scope": "openid"
                        if self.mode == "ordinary-login"
                        else jar["scope"],
                        "id_token": self.response(
                            role, claims, recipient, self.mode == "unencrypted-id"
                        ),
                    }
                ),
                "application/json",
            )
        if endpoint == "userinfo":
            token = handler.headers["Authorization"].removeprefix("Bearer ")
            assert token in self.tokens
            claims = {
                "iss": issuer,
                "sub": "other" if self.mode == "wrong-userinfo-sub" else "test-subject",
                "aud": RP,
                "iat": now,
                "exp": now + 180,
            }
            return answer(
                200,
                self.response(
                    role,
                    claims,
                    self.tokens[token],
                    self.mode == "unencrypted-userinfo",
                ),
                "application/jwt",
            )
        return answer(404, "", "text/plain")


def transaction(fixtures, role, approval=False, rollover=None, required_acr=LOA + "3"):
    """Exercise a registered RP with its own sector, key, nonce and verifier."""
    iss = BASE + "/op"
    client = BASE + "/" + role
    callback = f"https://{role}.example.test/callback"
    nonce, state, verifier = [secrets.token_urlsafe(32) for _ in range(3)]
    now = int(time.time())
    req = {
        "iss": client,
        "client_id": client,
        "aud": iss,
        "iat": now,
        "exp": now + 120,
        "jti": secrets.token_hex(16),
        "response_type": "code",
        "scope": "openid",
        "redirect_uri": callback,
        "nonce": nonce,
        "state": state,
        "code_challenge": challenge(verifier),
        "code_challenge_method": "S256",
        "claims": {"id_token": {"acr": {"essential": True, "value": required_acr}}},
    }
    if approval:
        req.update(scope="openid " + APPROVAL, prompt="login consent")
        req[SIGN] = {"sign_message": {"mime_type": "text/plain", "message": "VGVzdA=="}}
        req["claims"]["id_token"][PIN] = {"essential": True, "value": "100000000001"}
    curl = [
        "curl",
        "-fsS",
        "--max-time",
        "20",
        "--cacert",
        fixtures.directory / "config/common/tls.crt",
        "--resolve",
        f"{HOST}:11050:127.0.0.1",
    ]
    url = (
        iss
        + "/authorization?"
        + urlencode(
            {
                "client_id": client,
                "request": fixtures.sign(role, req, "oauth-authz-req+jwt"),
            }
        )
    )
    with tempfile.NamedTemporaryFile(dir=fixtures.directory) as cookie:
        for _ in range(5):
            if url.startswith(callback + "?"):
                break
            assert url.startswith(BASE + "/")
            if rollover and url.startswith(RP + "/callback?"):
                rollover()
            response = subprocess.check_output(
                curl
                + [
                    "-b",
                    cookie.name,
                    "-c",
                    cookie.name,
                    "-o",
                    "/dev/null",
                    "-w",
                    "%{http_code} %{redirect_url}",
                    url,
                ]
            ).decode()
            status, url = response.split(" ", 1)
            assert status == "302", "fixture flow did not redirect"
        assert url.startswith(callback + "?")
        query = parse_qs(urlsplit(url).query)
        assert query["state"] == [state]
        if "error" in query:
            assert "code" not in query
            return query["error"][0], None
        code = query["code"][0]
        params = {
            "grant_type": "authorization_code",
            "code": code,
            "client_id": client,
            "redirect_uri": callback,
            "code_verifier": verifier,
            "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            "client_assertion": fixtures.sign(
                role,
                {
                    "iss": client,
                    "sub": client,
                    "aud": iss + "/token",
                    "exp": now + 120,
                    "iat": now,
                    "jti": secrets.token_hex(16),
                },
            ),
        }
        wire = subprocess.check_output(
            curl + ["--data", urlencode(params), iss + "/token"]
        )
        tokens = json.loads(wire)
        token = tokens["id_token"]
        kid = jwt.get_unverified_header(token)["kid"]
        keys = json.loads(fetch(fixtures.directory, iss + "/jwks"))["keys"]
        key = jwt.PyJWK.from_dict(next(k for k in keys if k["kid"] == kid)).key
        claims = jwt.decode(
            token, key, algorithms=["ES256"], audience=client, issuer=iss
        )
        assert (
            claims["auth_time"] == fixtures.original_time
            and claims["acr"] == LOA + "3"
            and claims["nonce"] == nonce
        )
        # UserInfo and ID tokens can be signed by different replicas. Verify
        # the protected type with the UserInfo signer's own registered key.
        userinfo = subprocess.check_output(
            curl + ["-H", "@-", iss + "/userinfo"],
            input=f"Authorization: Bearer {tokens['access_token']}\n".encode(),
        )
        kid = jwt.get_unverified_header(userinfo)["kid"]
        key = jwt.PyJWK.from_dict(next(k for k in keys if k["kid"] == kid)).key
        verified = jwt.decode_complete(
            userinfo, key, algorithms=["ES256"], audience=client, issuer=iss
        )
        assert verified["header"]["typ"] == "JWT"
        ui = verified["payload"]
        assert ui["sub"] == claims["sub"] and 0 < ui["exp"] - ui["iat"] <= 300
        assert not {"nonce", "auth_time", "acr", "at_hash", "c_hash"}.intersection(ui)
        return None, claims["sub"]
