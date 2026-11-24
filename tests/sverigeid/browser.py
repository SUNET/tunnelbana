"""Browser acceptance checks against independent Sweden Connect services."""

import base64
import hashlib
import json
import secrets
import subprocess
import time
import zlib
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from urllib.parse import parse_qs, urlencode, urlsplit
from xml.etree import ElementTree as ET

import jwt
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from federation import ANCHOR, BASE, HERE, HOST, fetch

RP = f"https://{HOST}:11030"
EID = f"https://{HOST}:11020/testmyeid"
INFO = "https://id.oidc.se/scope/naturalPersonInfo"
NUMBER = "https://id.oidc.se/scope/naturalPersonNumber"
PIN = "https://id.oidc.se/claim/personalIdentityNumber"
COORD = "https://id.oidc.se/claim/coordinationNumber"
LOA = "http://id.elegnamnden.se/loa/1.0/loa"


def launch(playwright, directory):
    import os
    import shutil

    cert = x509.load_pem_x509_certificate(
        (directory / "config/common/tls.crt").read_bytes()
    )
    spki = cert.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    pin = base64.b64encode(hashlib.sha256(spki).digest()).decode()
    return playwright.chromium.launch(
        executable_path=os.environ.get("CHROME_BIN") or shutil.which("google-chrome"),
        args=[
            f"--host-resolver-rules=MAP {HOST} 127.0.0.1",
            f"--ignore-certificate-errors-spki-list={pin}",
        ],
    )


def resolved_entity(directory, role, *, quiet=False):
    entity = BASE + "/" + role
    anchor_key = jwt.PyJWK.from_dict(
        json.loads((directory / "config/common/oidf-trust-anchor.jwk").read_text())
    ).key
    raw = fetch(
        directory,
        ANCHOR + "/resolve?" + urlencode({"sub": entity, "trust_anchor": ANCHOR}),
        quiet=quiet,
    )
    resolved = jwt.decode(
        raw,
        anchor_key,
        algorithms=["ES512"],
        issuer=ANCHOR,
        options={"require": ["iat", "exp", "sub"]},
    )
    assert resolved["sub"] == entity
    return resolved


def readiness(directory):
    for role in ["rp", "op"]:
        resolved = resolved_entity(directory, role, quiet=True)
        intermediate = ANCHOR.rsplit("/", 1)[0] + (
            "/im-reg-sc-op" if role == "op" else "/im-reg-sc"
        )
        assert (
            jwt.decode(resolved["trust_chain"][1], options={"verify_signature": False})[
                "iss"
            ]
            == intermediate
        )
    assert BASE + "/op" in [
        op["entity_id"]
        for op in json.loads(fetch(directory, RP + "/oidc/authn/info", quiet=True))[
            "ops"
        ]
    ]


def authenticate(page, coordination=False):
    selector = page.locator("#selectSimulatedUser")
    selector.wait_for()
    people = selector.locator("option").evaluate_all(
        "options => options.map(o => o.value)"
    )
    person = next(
        value
        for value in people
        if len(value) == 12
        and value.isdigit()
        and (int(value[6:8]) > 60) == coordination
    )
    selector.select_option(person)
    page.click("#submitButton")
    return person


def reference_client(
    browser,
    directory,
    rp,
    level,
    scope,
    signing_key=0,
    method="get",
    coordination=False,
):
    page = browser.new_page()
    try:
        page.goto(RP)
        page.click("#menu-oidc")
        page.select_option("#oidc-rp-select", RP + f"/testrp{rp}")
        page.select_option("#oidc-op-select", BASE + "/op")
        page.click("#oidc-authn-next-button")
        page.click("#oidc-request-mode-request-body")

        # Supply the generator's documented form model to its own endpoint.
        # The reference client signs the JAR, later decrypts and validates
        # both responses with its own registrations and protocol keys.
        def configure(route):
            params = route.request.post_data_json
            params["requestObject"]["signRequest"] = True
            params["scope"]["value"] = params["requestBodyScope"] = scope
            params["claims"] = {
                "id_token": {"acr": {"essential": True, "value": level}}
            }
            params["claimInRequestBody"] = True
            params["callUserInfo"] = True
            registered = [
                k["kid"]
                for k in params["keys"]["signKeys"]
                if "Registered" in (k.get("description") or "")
            ]
            params["keys"]["signKey"] = registered[signing_key]
            route.continue_(post_data=json.dumps(params))

        page.route("**/oidc/authn/generate?*", configure)
        page.click("#oidc-request-submit-" + method + "-button")
        person = authenticate(page, coordination)
        page.wait_for_url(RP + "/**")
        page.wait_for_function(
            "typeof OIDC_STATE !== 'undefined' && OIDC_STATE.getAuthnResult()?.responseParameters"
        )
        result = page.evaluate("OIDC_STATE.getAuthnResult()")
        assert (
            not result["errors"] and not result["tokenError"] and not result["op_error"]
        ), "reference RP rejected the authorization or token response"
        id_token, ui = result["idTokenClaims"], result["userInfoClaims"]
        assert id_token["iss"] == ui["iss"] == BASE + "/op"
        aud = RP + f"/testrp{rp}"
        assert all(c["aud"] in (aud, [aud]) for c in [id_token, ui])
        assert id_token["sub"] == ui["sub"] and id_token["sub"] != person
        assert (
            id_token["acr"] == level
            and 0 <= id_token["iat"] - id_token["auth_time"] <= 60
        )
        assert 0 < id_token["exp"] - id_token["iat"] <= 300
        assert id_token["nonce"]
        expected_alg = {1: None, 2: "RSA-OAEP-256", 3: "ECDH-ES"}[rp]
        for protection in [result["idTokenProtection"], result["userInfoProtection"]]:
            assert protection["signed"] and protection["encrypted"] == bool(
                expected_alg
            )
            if expected_alg:
                assert (
                    protection["encryptionAlgorithm"],
                    protection["encryptionMethod"],
                ) == (expected_alg, "A256GCM")
        if INFO in scope:
            assert (
                ui["given_name"] and ui["family_name"] and "given_name" not in id_token
            )
        if NUMBER in scope:
            number, other = (COORD, PIN) if coordination else (PIN, COORD)
            assert (
                id_token[number] == ui[number] == person
                and other not in id_token
                and other not in ui
            )
        else:
            assert not {PIN, COORD}.intersection(id_token) and not {
                PIN,
                COORD,
            }.intersection(ui)
        return id_token["sub"]
    finally:
        page.close()


def direct(browser, directory, level):
    page = browser.new_page()
    try:
        verifier = secrets.token_urlsafe(32)
        challenge = (
            base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest())
            .decode()
            .rstrip("=")
        )
        callback = BASE + "/fixture-callback"
        nonce = secrets.token_urlsafe(16)
        state = secrets.token_urlsafe(16)
        params = {
            "client_id": "fixture",
            "redirect_uri": callback,
            "response_type": "code",
            "scope": f"openid {INFO} {NUMBER}",
            "nonce": nonce,
            "state": state,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "claims": json.dumps(
                {"id_token": {"acr": {"essential": True, "values": [level]}}}
            ),
        }
        page.route(
            "**/fixture-callback*",
            lambda route: route.fulfill(status=200, body="complete"),
        )
        page.goto(BASE + "/service/authorization?" + urlencode(params))
        person = authenticate(page)
        page.wait_for_url(callback + "*")
        query = parse_qs(urlsplit(page.url).query)
        assert query["state"] == [state] and "code" in query
        form = {
            "grant_type": "authorization_code",
            "client_id": "fixture",
            "code": query["code"][0],
            "redirect_uri": callback,
            "code_verifier": verifier,
        }

        def redeem(_):
            return json.loads(
                subprocess.check_output(
                    [
                        "curl",
                        "-sS",
                        "--cacert",
                        directory / "config/common/tls.crt",
                        "--resolve",
                        f"{HOST}:11050:127.0.0.1",
                        "--data",
                        urlencode(form),
                        BASE + "/service/token",
                    ]
                )
            )

        with ThreadPoolExecutor(max_workers=2) as pool:
            responses = list(pool.map(redeem, range(2)))
        assert sorted("id_token" in r for r in responses) == [False, True]
        token = next(r["id_token"] for r in responses if "id_token" in r)
        keys = json.loads(fetch(directory, BASE + "/service/jwks"))["keys"]
        claims = jwt.decode(
            token,
            jwt.PyJWK.from_dict(keys[0]).key,
            algorithms=["ES256"],
            issuer=BASE + "/service",
            audience="fixture",
        )
        assert (
            claims["nonce"] == nonce
            and claims["acr"] == level
            and claims[PIN] == person
            and claims["auth_time"] <= claims["iat"]
        )
    finally:
        page.close()


def saml(browser, directory):
    ns = "urn:oasis:names:tc:SAML:2.0:assertion"
    acs = "https://proxy.example.com/SP/acs"
    req_id = "_" + secrets.token_hex(16)
    now = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    xml = f'<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="{ns}" Version="2.0" ID="{req_id}" IssueInstant="{now}" Destination="{BASE}/saml/sso" AssertionConsumerServiceURL="{acs}"><saml:Issuer>https://proxy.example.com/SP</saml:Issuer><samlp:RequestedAuthnContext Comparison="exact"><saml:AuthnContextClassRef>{LOA}4</saml:AuthnContextClassRef></samlp:RequestedAuthnContext></samlp:AuthnRequest>'
    compression = zlib.compressobj(wbits=-15)
    wire = base64.b64encode(
        compression.compress(xml.encode()) + compression.flush()
    ).decode()
    page = browser.new_page()
    received = []

    def accept(route):
        received.append(
            base64.b64decode(parse_qs(route.request.post_data)["SAMLResponse"][0])
        )
        route.fulfill(status=200, body="complete")

    try:
        page.route(acs, accept)
        page.goto(BASE + "/saml/sso?" + urlencode({"SAMLRequest": wire}))
        authenticate(page)
        page.wait_for_url(acs)
        path = directory / "response.xml"
        path.write_bytes(received[0])
        try:
            subprocess.run(
                [
                    "xmlsec1",
                    "--verify",
                    "--pubkey-cert-pem",
                    HERE.parents[1] / "crates/tunnelbana-plugins/testdata/idp-cert.pem",
                    "--id-attr:ID",
                    ns + ":Assertion",
                    path,
                ],
                capture_output=True,
                check=True,
            )
            doc = ET.fromstring(received[0])
            statement = doc.find(f".//{{{ns}}}AuthnStatement")
            assert (
                doc.get("InResponseTo") == req_id
                and statement.find(f".//{{{ns}}}AuthnContextClassRef").text == LOA + "4"
            )
            assert (
                abs(
                    time.time()
                    - datetime.fromisoformat(statement.get("AuthnInstant")).timestamp()
                )
                < 90
            )
        finally:
            path.unlink(missing_ok=True)
    finally:
        page.close()


def eid(browser, directory, mode):
    page = browser.new_page(locale="en")
    requests = {}
    callback_requests = []

    def observe(request):
        endpoint = urlsplit(request.url)
        if request.url.startswith(BASE + "/rp/callback?"):
            callback_requests.append(
                (request.url, request.header_value("cookie") or "")
            )
        if endpoint.path not in {"/op/authorization", "/oidc/authorize"}:
            return
        params = parse_qs(endpoint.query or request.post_data or "")
        if "request" in params:
            # The independent parties verify the signatures. Observe their JARs
            # only to compare the two localized messages and constraints.
            requests[endpoint.path] = (
                params,
                jwt.decode(params["request"][0], options={"verify_signature": False}),
            )

    try:
        page.goto(EID + "/")
        page.locator('[value="' + BASE + '/op"]').click()
        person = authenticate(page)
        page.wait_for_url(EID + "/result*")
        assert "Your eID works for authentication" in page.locator("body").inner_text()
        page.on("request", observe)
        page.get_by_role("button", name="Sign using Tunnelbana OP").click()
        selector = page.locator("#selectSimulatedUser")
        selector.wait_for()
        downstream, upstream = [
            requests[path][1] for path in ["/op/authorization", "/oidc/authorize"]
        ]
        field = "https://id.oidc.se/param/signRequest"
        assert (
            downstream[field] == upstream[field]
            and downstream["claims"] == upstream["claims"]
        )
        assert set(upstream["prompt"].split()) == {"login", "consent"}
        message = base64.b64decode(
            upstream[field]["sign_message"]["message"], validate=True
        ).decode()
        assert page.get_by_text(message, exact=True).is_visible()
        assert selector.is_disabled() and selector.input_value() == person
        if mode == "cancel":
            page.get_by_text("Cancel and return to the service", exact=True).click()
        elif mode == "unknown-signer":
            page.click("#simulateErrorButton")
            page.select_option("#selectError", label="UNKNOWN_PRINCIPAL")
            page.click("#submitErrorButton")
        else:
            page.click("#submitButton")
        page.wait_for_url(EID + "/result*")
        text = page.locator("body").inner_text()
        if mode == "approve":
            assert "Your eID works for signing" in text and message in text
            # A second submission cannot begin another approval, even while the
            # client's resolved registration is still present on both replicas.
            curl = [
                "curl",
                "-sS",
                "--cacert",
                directory / "config/common/tls.crt",
                "--resolve",
                f"{HOST}:11050:127.0.0.1",
            ]
            replay = subprocess.check_output(
                curl
                + [
                    "--data",
                    urlencode(requests["/op/authorization"][0], doseq=True),
                    BASE + "/op/authorization",
                ]
            )
            assert json.loads(replay)["error"] == "invalid_request"
            url, cookies = callback_requests[-1]
            status = subprocess.check_output(
                curl
                + [
                    "-b",
                    cookies,
                    "-o",
                    "/dev/null",
                    "-w",
                    "%{http_code} %{redirect_url}",
                    url,
                ]
            ).decode()
            assert int(status[:3]) >= 300 and "code=" not in status
        else:
            assert "Your eID works for signing" not in text and "error" in text.lower()
    finally:
        page.close()
