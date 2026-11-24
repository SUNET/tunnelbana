"""Route real federation traffic across two local Tunnelbana processes."""

import http.client
import ssl
import threading
from collections import Counter
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit


@contextmanager
def balance(directory, fixtures):
    # The reference containers connect through the host gateway. Both replicas
    # listen only on loopback. Preserve the registered public origin throughout.
    counters = Counter()
    ca = directory / "config/common/tls.crt"
    trust = ssl.create_default_context(cafile=str(ca))
    trust.check_hostname = False  # loopback backend, pinned test certificate
    hop = {"connection", "transfer-encoding", "keep-alive", "content-length"}

    class Handler(BaseHTTPRequestHandler):
        def forward(self):
            path = urlsplit(self.path).path
            from fixtures import KINDS

            parts = path.lstrip("/").split("/", 1)
            if len(parts) == 2 and parts[0] in KINDS:
                try:
                    return fixtures.serve(self, *parts)
                except Exception as exc:  # noqa: BLE001 -- handler failures must fail the gate
                    fixtures.errors.append(type(exc).__name__)
                    self.send_error(500)
                    return
            # Authorize and issue the code on different replicas. Redeem it on
            # the first, and serve signed UserInfo on the second.
            replica = (
                11052
                if path in {"/rp/callback", "/op/userinfo", "/service/token"}
                else 11051
            )
            counters[replica, path] += 1
            conn = http.client.HTTPSConnection(
                "127.0.0.1", replica, context=trust, timeout=30
            )
            try:
                length = int(self.headers.get("Content-Length", 0))
                data = self.rfile.read(length) if length else None
                headers = {
                    k: v for k, v in self.headers.items() if k.lower() not in hop
                }
                conn.request(self.command, self.path, data, headers)
                response = conn.getresponse()
                body = response.read()
                self.send_response(response.status)
                for key, value in response.getheaders():
                    if key.lower() not in hop:
                        self.send_header(key, value)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            except (ConnectionError, TimeoutError):
                self.send_error(503)
            finally:
                conn.close()

        do_GET = do_POST = forward

        def log_message(self, *args):
            pass  # Queries contain authorization codes.

    with ThreadingHTTPServer(("0.0.0.0", 11050), Handler) as server:
        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls.load_cert_chain(ca, directory / "tls.pem")
        server.socket = tls.wrap_socket(server.socket, server_side=True)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            yield counters
        finally:
            server.shutdown()
            thread.join()
