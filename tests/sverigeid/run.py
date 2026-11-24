# /// script
# requires-python = ">=3.11"
# dependencies = ["cryptography==50.0.2", "playwright==1.65.2", "PyJWT==2.15.1", "PyYAML==6.0.4", "jwcrypto==1.5.6"]
# ///
"""Run the local release gate and write only redacted evidence."""

import hashlib
import json
import os
import signal
import socket
import subprocess
import sys
import tempfile
import time
import tomllib
import traceback
from contextlib import ExitStack
from pathlib import Path

sys.dont_write_bytecode = True
from browser import (
    INFO,
    LOA,
    NUMBER,
    direct,
    eid,
    launch,
    readiness,
    reference_client,
    resolved_entity,
    saml,
)
from federation import (
    BASE,
    BASELINE,
    HERE,
    HOST,
    ReplicaStartupError,
    fetch,
    prepare,
    proxy_command,
    proxy_config,
    replica_configs,
)
from fixtures import Peers, transaction
from playwright.sync_api import sync_playwright
from replicas import balance

ROOT = HERE.parents[1]
REPORT = ROOT / "target/sverigeid-local-report.json"


def source_id(repo):
    def git(*args):
        return subprocess.check_output(["git", "-C", repo, *args])

    # Record tracked modifications and untracked inputs used by the build or
    # by the gate, including their paths. Exclude unrelated operator notes.
    sha = hashlib.sha256(git("diff", "--binary", "HEAD", "--", ".", ":(exclude)docs"))
    for path in sorted(
        git(
            "ls-files",
            "--others",
            "--exclude-standard",
            "-z",
            "--",
            ".",
            ":(exclude)docs",
        ).split(b"\0")
    ):
        if path.endswith((b".rs", b".toml", b".py", b".json")):
            sha.update(path + b"\0" + (repo / os.fsdecode(path)).read_bytes())
    return {
        "commit": git("rev-parse", "HEAD").decode().strip(),
        "local_inputs_sha256": sha.hexdigest(),
    }


def stop(process, port):
    if process.poll() is None:
        os.killpg(process.pid, signal.SIGTERM)
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait()
    # The namespace supervisor can exit before the old Actix listener closes.
    # Wait for its port so readiness cannot accidentally probe the old process.
    deadline = time.monotonic() + 15
    while True:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=1):
                pass
        except ConnectionRefusedError:
            return
        except ConnectionResetError:
            pass  # A closing listener can reset a probe before it refuses connections.
        if time.monotonic() >= deadline:
            raise TimeoutError("replica listener did not close")
        time.sleep(0.1)


def run():
    with (ROOT / "Cargo.lock").open("rb") as lockfile:
        packages = tomllib.load(lockfile)["package"]
    dependencies = {}
    for name in ("grindvakt", "jose-rs"):
        (package,) = (p for p in packages if p["name"] == name)
        dependencies[name] = {k: package[k] for k in ("version", "source", "checksum")}
    report = {
        "local_federation": BASELINE,
        "images": json.loads((HERE / "images.json").read_text()),
        "sources": {
            ROOT.name: source_id(ROOT),
            **dependencies,
        },
        "checks": {},
        "passed": False,
    }

    def check(name, func, *, required_for_next=True):
        try:
            value = func()
        except Exception as exc:
            # Playwright messages can include URLs, codes or synthetic identities.
            frame = traceback.extract_tb(exc.__traceback__)[-1]
            report["checks"][name] = (
                f"FAIL ({type(exc).__name__}, {Path(frame.filename).name} line {frame.lineno})"
            )
            print(name, report["checks"][name], flush=True)
            if isinstance(exc, ReplicaStartupError):
                print(str(exc), flush=True)
            if required_for_next:
                raise
            return None
        report["checks"][name] = "PASS"
        print(name, "PASS", flush=True)
        return value

    try:
        with (
            tempfile.TemporaryDirectory(prefix="sverigeid-") as tmp,
            ExitStack() as stack,
        ):
            directory = Path(tmp)
            compose = prepare(
                Path(
                    os.environ.get("LOCAL_FEDERATION", ROOT.parent / "local-federation")
                ),
                directory,
            )
            stack.callback(subprocess.run, compose + ["down", "--volumes"], check=True)
            check(
                "reference-stack",
                lambda: subprocess.run(
                    compose + ["up", "-d", "--wait", "--wait-timeout", "360"],
                    check=True,
                ),
            )
            proxy_config(directory)
            fixtures = Peers(directory)
            configs = replica_configs(directory)
            original = [p.read_text() for p in configs]
            procs = stack.enter_context(ExitStack())

            def restart(issuer=None, rotated=False):
                procs.close()
                for port, config, contents in zip([11051, 11052], configs, original):
                    if issuer:
                        contents = contents.replace(
                            'environment = "local"',
                            f'environment = "local"\nop_entity_id = "{BASE}/{issuer}"\nid_token_signed_response_alg = "ES256"',
                        )
                        ring = fixtures.encryption_config(rotated)
                        contents = contents.replace(
                            'environment = "local"', ring + '\nenvironment = "local"'
                        )
                    config.write_text(contents)
                    cmd = proxy_command(
                        directory,
                        Path(
                            os.environ.get(
                                "TUNNELBANA_TEST_BIN", ROOT / "target/debug/tunnelbana"
                            )
                        ).resolve(),
                        config,
                    )
                    proc = subprocess.Popen(
                        cmd,
                        env=dict(
                            os.environ,
                            TUNNELBANA_BIND=f"127.0.0.1:{port}",
                            SSL_CERT_FILE=str(directory / "config/common/tls.crt"),
                        ),
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                        start_new_session=True,
                    )
                    procs.callback(stop, proc, port)

                    deadline = time.monotonic() + 20
                    while proc.poll() is None:
                        try:
                            status = json.loads(
                                fetch(
                                    directory,
                                    f"https://{HOST}:{port}/health",
                                    quiet=True,
                                )
                            )
                            if status == {"status": "ok"}:
                                break
                        except subprocess.CalledProcessError:
                            pass
                        if time.monotonic() >= deadline:
                            raise ReplicaStartupError(
                                f"replica health endpoint on {port} did not become ready"
                            )
                        time.sleep(0.1)
                    if proc.poll() is not None:
                        # Exit status and port are safe to publish. Process output
                        # can include protocol data from the local fixtures.
                        raise ReplicaStartupError(
                            f"replica on {port} exited with status {proc.returncode}"
                        )

            check("replica-startup", restart)
            counts = stack.enter_context(balance(directory, fixtures))

            def wait_ready():
                deadline = time.monotonic() + 240
                while True:
                    try:
                        readiness(directory)
                        return
                    except Exception:
                        if time.monotonic() >= deadline:
                            raise
                        time.sleep(2)

            check("signed-registrations-and-discovery", wait_ready)
            check("registered-test-peer-metadata", fixtures.prepare_metadata)
            with sync_playwright() as pw:
                browser = launch(pw, directory)
                for level in ["4", "3"]:
                    check(
                        "service-oidc-loa" + level + "-concurrent-redemption",
                        lambda level=level: direct(browser, directory, LOA + level),
                    )
                scopes = f"openid {INFO} {NUMBER}"

                def rp(n, level, scope, key=0, method="get"):
                    return reference_client(
                        browser, directory, n, LOA + level, scope, key, method
                    )

                public = check("rp1-public-signed", lambda: rp(1, "4", scopes))
                check(
                    "rp1-coordination-number",
                    lambda: reference_client(
                        browser, directory, 1, LOA + "3", scopes, coordination=True
                    ),
                )

                def stable(func, expected):
                    assert func() == expected

                check(
                    "rp1-openid-privacy-stable",
                    lambda: stable(lambda: rp(1, "2", "openid"), public),
                )
                pair = check("rp2-rsa-encrypted", lambda: rp(2, "3", scopes))
                assert public != pair
                check(
                    "rp2-stable-pairwise",
                    lambda: stable(lambda: rp(2, "3", "openid"), pair),
                )
                for key in [0, 1]:
                    check(
                        f"rp3-ec-encrypted-signing-key-{key + 1}",
                        lambda key=key: rp(3, "2", "openid", key, "post"),
                    )
                for mode in ["approve", "cancel", "unknown-signer"]:
                    # Each eID flow uses a fresh browser page. Record failures
                    # and continue testing the independent SAML and replica flows.
                    check(
                        "test-my-eid-" + mode,
                        lambda mode=mode: eid(browser, directory, mode),
                        required_for_next=False,
                    )
                check("service-saml-signed-assurance", lambda: saml(browser, directory))
                restart("probe-op")

                def sectors():
                    a = transaction(fixtures, "sector-a")
                    b = transaction(fixtures, "sector-b")
                    assert a[0] is None and b[0] is None and a[1] != b[1]
                    assert transaction(fixtures, "sector-a") == a

                check("registered-sectors-and-original-auth-time", sectors)

                def rotate():
                    before = transaction(
                        fixtures,
                        "sector-a",
                        rollover=lambda: restart("probe-op", True),
                    )
                    assert (
                        before == transaction(fixtures, "sector-a")
                        and before[0] is None
                    )

                check("retired-recipient-key-in-flight-restart", rotate)

                def reject(mode):
                    fixtures.mode = mode
                    error, sub = transaction(
                        fixtures,
                        "sector-a",
                        approval=mode in {"wrong-signer", "ordinary-login"},
                    )
                    assert error and sub is None
                    if mode in {"unmet-acr", "wrong-signer"}:
                        assert error == "unmet_authentication_requirements"

                for mode in [
                    "wrong-issuer",
                    "wrong-audience",
                    "wrong-userinfo-sub",
                    "unmet-acr",
                    "wrong-signer",
                    "ordinary-login",
                    "unencrypted-id",
                    "unencrypted-userinfo",
                ]:
                    check("upstream-" + mode, lambda mode=mode: reject(mode))

                def withdrawn_mark():
                    role = "probe-op"
                    loa = "https://id.swedenconnect.se/loa/loa3"

                    def endorsed():
                        return {
                            m["trust_mark_type"]
                            for m in resolved_entity(directory, role)["trust_marks"]
                        }

                    assert loa in endorsed()
                    fixtures.withdraw_mark(role, loa)
                    subprocess.run(
                        compose + ["restart", "openid-federation"], check=True
                    )
                    deadline = time.monotonic() + 180
                    while True:
                        try:
                            if loa not in endorsed():
                                break
                        except (subprocess.CalledProcessError, KeyError):
                            pass
                        if time.monotonic() >= deadline:
                            raise TimeoutError("resolver did not observe withdrawal")
                        time.sleep(2)
                    restart(role)
                    fixtures.mode = "valid"
                    assert transaction(fixtures, "sector-a") == (
                        "unmet_authentication_requirements",
                        None,
                    )

                check("federation-withdrawn-loa", withdrawn_mark)
                restart("expired-op")

                def expired():
                    fixtures.verify_expired_leaf()
                    before = fixtures.auth_calls
                    reject("valid")
                    assert fixtures.auth_calls == before

                check("federation-expired-op", expired)
                browser.close()

            def routing():
                assert not fixtures.errors, fixtures.errors
                for port, path in [
                    (11051, "/op/authorization"),
                    (11052, "/rp/callback"),
                    (11051, "/op/token"),
                    (11052, "/op/userinfo"),
                ]:
                    assert counts[port, path] > 0

            check("redis-replica-code-and-signing-rollover", routing)
        report["passed"] = all(v == "PASS" for v in report["checks"].values())
    except Exception as exc:  # noqa: BLE001 -- keep protocol data out of reports
        report["error"] = type(exc).__name__
    finally:
        REPORT.parent.mkdir(exist_ok=True)
        REPORT.write_text(json.dumps(report, indent=2) + "\n")
        print(REPORT)
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    sys.exit(run())
