"""Optional Chromium smoke test over loopback TLS. Requires Playwright and OpenSSL."""

import base64
import hashlib
import http.client
import os
import pathlib
import socket
import ssl
import subprocess
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from playwright.sync_api import expect, sync_playwright


ROOT = pathlib.Path(__file__).resolve().parents[3]


def free_port():
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


def run(directory):
    (directory / "mode").write_text("enabled")
    (directory / "clock").write_text(str(int(time.time())))
    certificate, key = directory / "cert.pem", directory / "key.pem"
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
         "-subj", "/CN=127.0.0.1", "-addext", "subjectAltName=IP:127.0.0.1",
         "-keyout", key, "-out", certificate],
        check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    public_key = subprocess.check_output(["openssl", "x509", "-in", certificate, "-pubkey", "-noout"])
    der = subprocess.check_output(["openssl", "pkey", "-pubin", "-outform", "DER"], input=public_key)
    pin = base64.b64encode(hashlib.sha256(der).digest()).decode()
    backend = free_port()

    class Proxy(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass

        def forward(self):
            # A distinct site supplies the top-level navigation used to check SameSite=Lax.
            if self.headers["Host"].startswith("localhost:"):
                body = f'<a href="https://127.0.0.1:{self.server.server_port}/poc02/sessions">Continue</a>'.encode()
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                self.wfile.write(body)
                return
            connection = http.client.HTTPConnection("127.0.0.1", backend, timeout=5)
            try:
                length = int(self.headers.get("Content-Length", 0))
                headers = {key: value for key, value in self.headers.items()
                           if key.lower() in {"cookie", "content-type", "content-length", "host"}}
                connection.request(self.command, self.path, self.rfile.read(length), headers)
                response = connection.getresponse()
                self.send_response(response.status)
                for name, value in response.getheaders():
                    if name.lower() not in {"connection", "server", "date"}:
                        self.send_header(name, value)
                self.end_headers()
                self.wfile.write(response.read())
            finally:
                connection.close()

        do_GET = forward
        do_POST = forward

    class TlsTestServer(ThreadingHTTPServer):
        def handle_error(self, request, client_address):
            import sys

            if not isinstance(sys.exc_info()[1], (BrokenPipeError, ConnectionResetError)):
                super().handle_error(request, client_address)

    web = TlsTestServer(("127.0.0.1", 0), Proxy)
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.load_cert_chain(certificate, key)
    web.socket = tls.wrap_socket(web.socket, server_side=True)
    server = subprocess.Popen(
        [os.environ.get("POC02_PHP", "php"), "-S", f"127.0.0.1:{backend}", "-t", directory,
         ROOT / "tests/Support/Poc02/router.php"],
        cwd=ROOT, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        env=dict(os.environ, POC02_TEST_DIRECTORY=str(directory), DEBUG="0",
                 APP_FULL_BASE_URL="https://127.0.0.1", DATABASE_URL="sqlite:///:memory:",
                 DATABASE_TEST_URL="sqlite:///:memory:"),
    )
    worker = threading.Thread(target=web.serve_forever, daemon=True)
    worker.start()
    try:
        for _ in range(100):
            try:
                with socket.create_connection(("127.0.0.1", backend), timeout=0.2):
                    break
            except OSError:
                time.sleep(0.02)
        else:
            raise RuntimeError("Local PHP backend did not start")
        verify_browser(directory, web.server_port, pin)
    finally:
        web.shutdown()
        web.server_close()
        server.terminate()
        server.wait(timeout=5)


def verify_browser(directory, port, pin):
    url = f"https://127.0.0.1:{port}/poc02/sessions"
    args = [f"--ignore-certificate-errors-spki-list={pin}", "--no-proxy-server"]
    if os.geteuid() == 0:
        args.append("--no-sandbox")
    with sync_playwright() as playwright:
        def open_profile():
            context = playwright.chromium.launch_persistent_context(
                directory / "chromium", executable_path=os.environ.get("POC02_CHROMIUM", "/usr/bin/chromium"),
                args=args, headless=True,
            )
            context.route("https://cdn.jsdelivr.net/**", lambda route: route.abort())
            return context

        def active(page):
            return set(page.locator('[data-active="1"]').evaluate_all("(nodes) => nodes.map(n => n.dataset.kind)"))

        with open_profile() as context:
            page = context.new_page()
            assert page.goto(url).status == 200
            assert {cookie["name"] for cookie in context.cookies(url)} == {"__Host-poc02-csrf"}
            for kind, button in [("guest", "ゲストセッション開始"),
                                 ("member", "検証用ログイン"), ("admin", "検証用ログイン")]:
                page.locator(f'[data-kind="{kind}"]').get_by_role("button", name=button).click()
                page.get_by_role("link", name="全セッションの状態を表示").click()
            assert active(page) == {"guest", "member", "admin"}
            cookies = context.cookies(url)
            assert all(c["secure"] and c["httpOnly"] and c["sameSite"] == "Lax" for c in cookies)
            assert "__Host-poc02-" not in page.evaluate("document.cookie")
            expiry = {c["name"]: c["expires"] for c in cookies}
            assert expiry["__Host-poc02-admin"] == -1
            assert expiry["__Host-poc02-guest"] > time.time()
            assert expiry["__Host-poc02-member"] > time.time()
            page.get_by_role("button", name="ダミー回答を保存").click()
            expect(page.get_by_text("回答 1 件", exact=False)).to_be_visible()
            print("PASS Chromium/TLS three sessions, cookie attributes and guest save")
            page.goto(f"https://localhost:{port}/")
            page.get_by_role("link", name="Continue").click()
            assert active(page) == {"guest", "member", "admin"}
            print("PASS Chromium/TLS cross-site top-level GET with SameSite=Lax")
        with open_profile() as context:
            page = context.new_page()
            assert page.goto(url).status == 200
            actual = active(page)
            assert {"guest", "member"} <= actual, sorted(actual)
            expect(page.get_by_text("回答 1 件", exact=False)).to_be_visible()
            print("PASS Chromium/TLS browser restart retains guest and member")
            print("OBSERVED Chromium profile restart restored admin:", "admin" in actual)
            if "admin" in actual:
                clock = directory / "clock"
                clock.write_text(str(int(clock.read_text()) + 1800))
                assert page.reload().status == 200
                assert active(page) == {"guest", "member"}
                print("PASS Chromium/TLS restored admin expires at the server's 30-minute idle limit")
            else:
                print("SKIP Chromium/TLS restored admin expiry because the browser did not restore the cookie")


if __name__ == "__main__":
    with tempfile.TemporaryDirectory(prefix="poc02-browser-") as temporary:
        run(pathlib.Path(temporary))
