"""Deliberately vulnerable local API. Never bind this lab publicly."""
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/api/redirect":
            self.send_response(302)
            self.send_header("Location", "/api/vulnerable/101")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        user = {"Bearer lab-alice": "alice", "Bearer lab-bob": "bob"}.get(self.headers.get("Authorization"))
        status, value = 401, {"error": "authentication required"}
        if self.path == "/api/me" and user:
            status, value = 200, {"user": user}
        elif self.path in ("/api/vulnerable/101", "/api/secure/101") and user:
            if self.path.startswith("/api/secure") and user != "alice":
                status, value = 403, {"error": "forbidden"}
            else:
                status, value = 200, {"id": 101, "owner": "alice", "private": "lab-only"}
        elif self.path == "/api/misleading/101" and user:
            status, value = 200, {"error": "forbidden"}
        body = json.dumps(value).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


if __name__ == "__main__":
    print("Laboratoire local : http://127.0.0.1:8770", flush=True)
    ThreadingHTTPServer(("127.0.0.1", 8770), Handler).serve_forever()
