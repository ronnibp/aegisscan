"""Local test servers for AegisScan integration testing.

* HTTP  : http://127.0.0.1:8099  — intentionally insecure (missing headers, exposed .env/.git)
* HTTPS : https://127.0.0.1:8443 — self-signed certificate (tests TLS auditor)

Run:  python tests/run_test_servers.py   (Ctrl+C to stop)
"""
import http.server
import os
import ssl
import threading
import urllib.parse

HERE = os.path.dirname(os.path.abspath(__file__))

VULN_PAGE = b"""<!DOCTYPE html><html><head><title>Test App</title></head><body>
<h1>Internal Test App</h1>
<a href="/login.html">login</a>
<form action="/login" method="post"><input type="password" name="pw"><input type="submit"></form>
</body></html>"""

GIT_CONFIG = b"[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n"
ENV_FILE = b"DB_PASSWORD=SuperSecretTestPass123\nAPP_KEY=base64:AbCdEf123456=\n"


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"

    def do_GET(self):
        path = self.path.split("?")[0]
        if path == "/redirect":
            # vulnerable open redirect for scanner testing
            to = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query).get("to", [""])[0]
            self.send_response(302)
            self.send_header("Location", to)
            self.end_headers()
        elif path == "/.env":
            self.send_response(200)
            self.end_headers()
            self.wfile.write(ENV_FILE)
        elif path == "/.git/config":
            self.send_response(200)
            self.end_headers()
            self.wfile.write(GIT_CONFIG)
        elif path == "/evil":
            # reflect the q parameter unescaped (reflected XSS test)
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"<html><body>Hi " + self.path.encode() + b"</body></html>")
        elif path == "/":
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Server", "nginx/1.14.0 (Ubuntu)")
            self.end_headers()
            self.wfile.write(VULN_PAGE)
        else:
            self.send_response(404)
            self.end_headers()

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Allow", "GET, POST, OPTIONS, TRACE")
        self.end_headers()

    def log_message(self, *a):
        pass


def main():
    httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 8099), Handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    print("HTTP  test server : http://127.0.0.1:8099")

    httpsd = http.server.ThreadingHTTPServer(("127.0.0.1", 8443), Handler)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(os.path.join(HERE, "fixtures", "cert.pem"),
                        os.path.join(HERE, "fixtures", "key.pem"))
    httpsd.socket = ctx.wrap_socket(httpsd.socket, server_side=True)
    threading.Thread(target=httpsd.serve_forever, daemon=True).start()
    print("HTTPS test server : https://127.0.0.1:8443 (self-signed)")
    print("Press Ctrl+C to stop.")
    try:
        while True:
            import time
            time.sleep(1)
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
