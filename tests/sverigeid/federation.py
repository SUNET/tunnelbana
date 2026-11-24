"""Create a disposable Sweden Connect federation from its pinned sources."""

import base64
import copy
import hashlib
import json
import os
import secrets
import socket
import subprocess
from pathlib import Path

import yaml
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

BASELINE = "5b67bedb42230fff6b8d89fb26c80e2084d2eb7b"
HERE = Path(__file__).resolve().parent
HOST = "local.fed.swedenconnect.se"
BASE = f"https://{HOST}:11050"
ANCHOR = f"https://{HOST}:11040/trustanchor"
REFERENCE = f"https://{HOST}:11010"


def key(directory, name):
    private = ec.generate_private_key(ec.SECP256R1())
    numbers = private.public_key().public_numbers()

    def b64(data):
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

    public = {
        "crv": "P-256",
        "kty": "EC",
        "x": b64(numbers.x.to_bytes(32, "big")),
        "y": b64(numbers.y.to_bytes(32, "big")),
    }
    kid = b64(
        hashlib.sha256(
            json.dumps(public, separators=(",", ":"), sort_keys=True).encode()
        ).digest()
    )
    public["kid"] = kid
    jwk = dict(
        public, d=b64(private.private_numbers().private_value.to_bytes(32, "big"))
    )
    (directory / f"{name}.jwk").write_text(json.dumps(jwk))
    return public


def prepare(source, directory):
    revision = subprocess.check_output(
        ["git", "-C", source, "rev-parse", "HEAD"], text=True
    ).strip()
    if revision != BASELINE:
        raise ValueError(f"Expected local-federation {BASELINE}, found {revision}")
    # Read the immutable revision. Local configuration or generated files in the checkout
    # must never become part of the gate or be overwritten by a reference service.
    archive = directory / "source.tar"
    subprocess.run(
        ["git", "-C", source, "archive", "-o", archive, revision], check=True
    )
    subprocess.run(["tar", "-xf", archive, "-C", directory], check=True)
    client_config = directory / "config/test-client/application-compose.yml"
    client_config.write_text(
        client_config.read_text()
        .replace("initial-refresh-delay: 30s", "initial-refresh-delay: 5s")
        .replace("refresh-interval: 10m", "refresh-interval: 10s")
    )
    pins = json.loads((HERE / "images.json").read_text())
    compose = yaml.safe_load((directory / "docker-compose.yml").read_text())
    project = "sverigeid-" + secrets.token_hex(5)
    compose["name"] = project
    compose["networks"]["local-federation"]["name"] = project
    for name, service in compose["services"].items():
        service.pop("container_name")
        service["image"] = pins[name]
        if name != "redis":
            service["environment"]["JAVA_TOOL_OPTIONS"] += (
                " -XX:ActiveProcessorCount=2 -Xmx384m"
            )
    (directory / "compose.yaml").write_text(yaml.safe_dump(compose))
    fed = directory / "config/openid-federation"
    application = yaml.safe_load((fed / "application-compose.yml").read_text())
    registrations = json.loads((fed / "trust-anchors.json").read_text())
    marks = json.loads((fed / "trust-mark-issuers.json").read_text())
    roles = [
        "rp",
        "op",
        "sector-a",
        "sector-b",
        "probe-op",
        "expired-op",
    ]
    for role in roles:
        intermediate = (
            "im-reg-sc" if role in {"rp", "sector-a", "sector-b"} else "im-reg-sc-op"
        )
        name = "tunnelbana-" + role
        public = key(directory, name)
        key(directory, name + "-sign")
        application["federation"]["keys"]["additional-keys"].append(
            {
                "name": name,
                "base64-encoded-public-jwk": base64.b64encode(
                    json.dumps(public).encode()
                ).decode(),
            }
        )
        subordinates = next(
            x["subordinates"]
            for x in registrations
            if x["entity-identifier"].endswith("/" + intermediate)
        )
        entry = copy.deepcopy(subordinates[0])
        old_id = entry["entity-identifier"]
        entry["entity-identifier"] = BASE + "/" + role
        entry["jwks"] = "public:" + name
        entry["policy"]["id"] = name
        for p in entry["policy"]["policy"].values():
            for field in p:
                if field.startswith(("display_name", "client_name")):
                    p[field]["value"] = "Tunnelbana " + role.upper()
        subordinates.append(entry)
        for issuer in marks:
            for mark in issuer["trust-marks"]:
                for grant in list(mark["trust-mark-subjects"]):
                    if grant["sub"] == old_id:
                        mark["trust-mark-subjects"].append(
                            dict(grant, sub=entry["entity-identifier"])
                        )
    (fed / "trust-anchors.json").write_text(json.dumps(registrations))
    (fed / "trust-mark-issuers.json").write_text(json.dumps(marks))
    (fed / "application-compose.yml").write_text(
        yaml.safe_dump(application, allow_unicode=True)
    )
    return ["docker", "compose", "-f", str(directory / "compose.yaml")]


def fetch(directory, url, *, quiet=False):
    from urllib.parse import urlsplit

    return subprocess.check_output(
        [
            "curl",
            "--silent",
            *([] if quiet else ["--show-error"]),
            "--fail",
            "--max-time",
            "8",
            "--cacert",
            directory / "config/common/tls.crt",
            "--resolve",
            f"{HOST}:{urlsplit(url).port}:127.0.0.1",
            url,
        ]
    )


def proxy_config(directory):
    """Use fixture TLS and freshly generated, distinct protocol and federation keys."""
    from urllib.parse import urlencode

    from cryptography.hazmat.primitives.serialization.pkcs12 import (
        load_key_and_certificates,
    )

    common = directory / "config/common"
    store = directory / "tls.p12"
    subprocess.run(
        [
            "keytool",
            "-importkeystore",
            "-srckeystore",
            common / "tls.jks",
            "-srcstorepass",
            "secret",
            "-deststoretype",
            "PKCS12",
            "-destkeystore",
            store,
            "-deststorepass",
            "secret",
            "-noprompt",
        ],
        check=True,
        capture_output=True,
    )
    private, _, _ = load_key_and_certificates(store.read_bytes(), b"secret")
    (directory / "tls.pem").write_bytes(
        private.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    key = json.loads((common / "oidf-trust-anchor.jwk").read_text())
    inline_key = "{ " + ", ".join(f"{k}={json.dumps(v)}" for k, v in key.items()) + " }"
    secret = secrets.token_urlsafe(40)
    cfg = f'''base_url = "{BASE}"
state_encryption_key = "{secret}"
[tls]
cert_path = "{common}/tls.crt"
key_path = "{directory}/tls.pem"

[[frontend]]
type = "oidc"
name = "service"
[frontend.config]
signing_jwk_path = "{directory}/tunnelbana-op-sign.jwk"
backend = "rp"
[[frontend.config.clients]]
client_id = "fixture"
token_endpoint_auth_method = "none"
redirect_uris = ["{BASE}/fixture-callback"]
'''
    info = "https://id.oidc.se/scope/naturalPersonInfo"
    number = "https://id.oidc.se/scope/naturalPersonNumber"
    approval = "https://id.oidc.se/scope/signApproval"
    for kind, role in [("frontend", "op"), ("backend", "rp")]:
        prefix = f"{kind}.config"
        cfg += f'''
[[{kind}]]
type = "oidc_federation"
name = "{role}"
[{prefix}]
profile = "sweden_connect"
signing_jwk_path = "{directory}/tunnelbana-{role}-sign.jwk"
redis_url = "redis://:supersecret@127.0.0.1:10900/"
'''
        if role == "op":
            cfg += f'''backend = "rp"
subject_secret = "{secret}"
approval_clients = ["https://{HOST}:11020/testmyeid", "{BASE}/sector-a"]
acr_values_supported = ["http://id.elegnamnden.se/loa/1.0/loa2", "http://id.elegnamnden.se/loa/1.0/loa3", "http://id.elegnamnden.se/loa/1.0/loa4"]
'''
        else:
            cfg += f"""environment = "local"
scope = "openid profile {info} {number} {approval}"
"""
        cfg += f'''[{prefix}.presentation]
contacts = ["test@example.invalid"]
logo_uri = "{BASE}/assets/tunnelbana.png"
client_uri = "{BASE}"
display_name = "Tunnelbana {role.upper()}"
"display_name#sv" = "Tunnelbana {role.upper()}"
"display_name#en" = "Tunnelbana {role.upper()}"
[{prefix}.federation]
signing_jwk_path = "{directory}/tunnelbana-{role}.jwk"
authority_hints = ["{ANCHOR.rsplit("/", 1)[0]}/im-reg-sc{"-op" if role == "op" else ""}"]
organization_name = "Tunnelbana local test"
'''
        for issuer in json.loads(
            (directory / "config/openid-federation/trust-mark-issuers.json").read_text()
        ):
            for mark in issuer["trust-marks"]:
                if any(
                    g["sub"] == f"{BASE}/{role}" for g in mark["trust-mark-subjects"]
                ):
                    kind_id = mark["trust-mark-type"]
                    query = urlencode(
                        {"trust_mark_type": kind_id, "sub": f"{BASE}/{role}"}
                    )
                    jwt = (
                        fetch(
                            directory,
                            issuer["entity-identifier"] + "/trust_mark?" + query,
                        )
                        .decode()
                        .strip()
                    )
                    cfg += f'[[{prefix}.federation.trust_marks]]\ntrust_mark_type = "{kind_id}"\ntrust_mark = "{jwt}"\n'
        cfg += f'[[{prefix}.federation.trust_anchor]]\nentity_id = "{ANCHOR}"\nkeys = [{inline_key}]\n'
    fixtures = HERE.parents[1] / "crates/tunnelbana-plugins/testdata"
    cfg += f"""
[[frontend]]
type = "saml2"
name = "saml"
[frontend.config]
backend = "rp"
idp_key_path = "{fixtures}/idp-key.pem"
idp_cert_path = "{fixtures}/idp-cert.pem"
[frontend.config.metadata]
local = ["{fixtures}/sp-metadata.xml"]
"""
    attributes = directory / "attributes.toml"
    names = [
        "name",
        "given_name",
        "family_name",
        "middle_name",
        "birthdate",
        "https://id.oidc.se/claim/personalIdentityNumber",
        "https://id.oidc.se/claim/coordinationNumber",
    ]
    attributes.write_text(
        "".join(
            f"[attributes.field{i}]\nopenid = [{json.dumps(name)}]\n"
            for i, name in enumerate(names)
        )
    )
    (directory / "proxy.toml").write_text(f'attributes = "{attributes}"\n' + cfg)
    (directory / "hosts").write_text(
        Path("/etc/hosts").read_text() + f"\n127.0.0.1 {HOST}\n"
    )


class ReplicaStartupError(RuntimeError):
    """Startup diagnostics containing only a port, exit status or fixture hostname."""


def proxy_command(directory, binary, config):
    if os.environ.get("SVERIGEID_RUNNER_HOSTS") == "1":
        # CI configures the fixture hostname on its disposable runner. Refuse
        # to send test traffic anywhere else if that setup was missed.
        addresses = {r[4][0] for r in socket.getaddrinfo(HOST, None)}
        if addresses != {"127.0.0.1"}:
            raise ReplicaStartupError("fixture hostname must resolve to IPv4 loopback")
        return [str(binary), str(config)]

    # Mount the fixture trust store and hosts file only in the proxy's process
    # namespace. No host-wide DNS or certificate configuration is changed.
    return [
        "bwrap",
        "--die-with-parent",
        "--bind",
        "/",
        "/",
        "--dev-bind",
        "/dev",
        "/dev",
        "--proc",
        "/proc",
        "--ro-bind",
        str(directory / "hosts"),
        "/etc/hosts",
        "--ro-bind",
        str(directory / "config/common/tls.crt"),
        "/etc/ssl/certs/ca-certificates.crt",
        "--",
        str(binary),
        str(config),
    ]


def replica_configs(directory):
    """Prepublish each replica's signing key before either accepts traffic."""
    first = directory / "proxy.toml"
    original = first.read_text()
    second = directory / "replica.toml"
    next_public = key(directory, "tunnelbana-op-next")
    current_public = json.loads((directory / "tunnelbana-op-sign.jwk").read_text())
    current_public.pop("d")

    def rotated(config, peer):
        jwk = dict(peer, use="sig", alg="ES256")
        inline = (
            "{ " + ", ".join(f"{k} = {json.dumps(v)}" for k, v in jwk.items()) + " }"
        )
        return config.replace(
            "approval_clients =",
            f"rotation.signing_public_jwks = [{inline}]\napproval_clients =",
        )

    first.write_text(rotated(original, next_public))
    # Only the federation OP rotates. The existing OIDC service retains its key.
    marker = 'profile = "sweden_connect"'
    before, after = original.split(marker, 1)
    after = after.replace("tunnelbana-op-sign.jwk", "tunnelbana-op-next.jwk", 1)
    second.write_text(rotated(before + marker + after, current_public))
    return [first, second]
