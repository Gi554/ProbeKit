import argparse
from functools import partial
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import html
import json
from pathlib import Path
import re
import secrets
from urllib.parse import parse_qs, urlsplit

from .dashboard import dashboard, detail, page
from .jobs import Jobs
from .render import render_html
from .store import Store, decode_report
from .target import Target
from .authorization import audit_authorization, validate


class Handler(BaseHTTPRequestHandler):
    def __init__(self, *args, store: Store, jobs: Jobs, token: str, **kwargs):
        self.store, self.jobs, self.token = store, jobs, token
        super().__init__(*args, **kwargs)

    def allowed_host(self):
        try:
            hostname = urlsplit("http://" + self.headers.get("Host", "")).hostname
            return hostname in {"127.0.0.1", "localhost"}
        except ValueError:
            return False

    def send(self, content: str, status=200, content_type="text/html; charset=utf-8", download=None):
        data = content.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cache-Control", "no-store")
        if download:
            self.send_header("Content-Disposition", f'attachment; filename="{download}"')
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if not self.allowed_host():
            self.send("Hôte refusé.", 403); return
        path = urlsplit(self.path).path
        if path == "/":
            self.send(dashboard(self.store.recent(), self.token)); return
        match = re.fullmatch(r"/scans/([a-f0-9]{32})(?:/(report\.(?:html|json)))?", path)
        if not match or not (row := self.store.get(match.group(1))):
            self.send("Audit introuvable.", 404); return
        kind = match.group(2)
        if not kind:
            self.send(detail(row)); return
        if not row["report"]:
            self.send("Rapport indisponible.", 409); return
        report = decode_report(row["report"])
        if kind == "report.json":
            self.send(json.dumps(report.to_dict(), ensure_ascii=False, indent=2),
                      content_type="application/json; charset=utf-8", download="report.json")
        else:
            self.send(render_html(report), download="report.html")

    def do_POST(self):
        if not self.allowed_host():
            self.send("Hôte refusé.", 403); return
        if self.path != "/scans":
            self.send("Route introuvable.", 404); return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if not 0 < length <= 262144:
                raise ValueError("Formulaire trop volumineux ou vide.")
            values = parse_qs(self.rfile.read(length).decode("utf-8"), max_num_fields=10)
            token = values.get("csrf", [""])[0]
            if not secrets.compare_digest(token, self.token):
                self.send("Jeton de formulaire invalide.", 403); return
            project = values.get("project", [""])[0].strip()
            if not project or len(project) > 100:
                raise ValueError("Nom du projet requis, limité à 100 caractères.")
            if values.get("kind", [""])[0] == "authorization":
                manifest = json.loads(values.get("manifest", [""])[0])
                target, _ = validate(manifest)
                scan_id = self.jobs.submit(target, project, runner=audit_authorization, payload=manifest)
            else:
                target = Target.parse(values.get("target", [""])[0])
                scan_id = self.jobs.submit(target, project)
        except (ValueError, UnicodeError, KeyError, TypeError, AttributeError) as error:
            self.send(page(f'<h2>Audit non créé</h2><p>{html.escape(str(error))}</p><a href="/">Retour</a>'), 400)
            return
        self.send_response(303)
        self.send_header("Location", f"/scans/{scan_id}")
        self.send_header("Content-Length", "0")
        self.end_headers()


def main(argv=None):
    parser = argparse.ArgumentParser(description="Tableau de bord local ProbeKit")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--data", type=Path, default=Path("data/probekit.sqlite"))
    args = parser.parse_args(argv)
    if not 1 <= args.port <= 65535:
        parser.error("Port invalide.")
    store = Store(args.data)
    jobs = Jobs(store)
    token = secrets.token_hex(32)
    server = None
    try:
        server = ThreadingHTTPServer(("127.0.0.1", args.port), partial(Handler, store=store, jobs=jobs, token=token))
        store.recover()
        print(f"ProbeKit : http://127.0.0.1:{args.port}", flush=True)
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        if server:
            server.server_close()
        jobs.close()


if __name__ == "__main__":
    main()
