from functools import partial
from http.client import HTTPConnection
from http.server import ThreadingHTTPServer
import json
from pathlib import Path
import tempfile
import threading
import time
from urllib.parse import urlencode
import unittest
from unittest.mock import patch

from probekit.jobs import Jobs
from probekit.models import Report
from probekit.server import Handler
from probekit.store import Store


class ServerTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(dir=Path.cwd())
        self.store = Store(Path(self.temporary.name) / "test.sqlite")
        self.jobs = Jobs(self.store, lambda target: Report(target.url, status=200))
        handler = partial(Handler, store=self.store, jobs=self.jobs, token="test-token")
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()
        self.jobs.close()
        self.temporary.cleanup()

    def request(self, method, path, body=None, headers=None):
        connection = HTTPConnection("127.0.0.1", self.server.server_port, timeout=3)
        try:
            connection.request(method, path, body=body, headers=headers or {})
            response = connection.getresponse()
            return response.status, dict(response.getheaders()), response.read()
        finally:
            connection.close()

    def test_dashboard_headers_and_host_boundary(self):
        status, headers, body = self.request("GET", "/")
        self.assertEqual(status, 200)
        self.assertIn("frame-ancestors 'none'", headers["Content-Security-Policy"])
        self.assertIn(b"ProbeKit", body)
        self.assertEqual(self.request("GET", "/", headers={"Host": "evil.example"})[0], 403)

    def test_scan_form_requires_token_and_report_is_downloadable(self):
        body = urlencode({"project": "Demo", "target": "http://example.test/", "csrf": "bad"})
        self.assertEqual(self.request("POST", "/scans", body)[0], 403)
        body = urlencode({"project": "Demo", "target": "http://example.test/", "csrf": "test-token"})
        status, headers, _ = self.request("POST", "/scans", body)
        self.assertEqual(status, 303)
        report_path = headers["Location"] + "/report.json"
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            status, _, content = self.request("GET", report_path)
            if status == 200:
                break
            time.sleep(0.02)
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(content)["status"], 200)

    def test_authorization_form_dispatches_and_persists_matrix(self):
        manifest = json.loads((Path(__file__).resolve().parents[1] / "examples/authorization.json").read_text(encoding="utf-8"))
        report = Report(manifest["origin"], metrics={"authorization": {"cases": [{"outcome": "violation"}]}})
        with patch("probekit.server.audit_authorization", return_value=report) as runner:
            body = urlencode({"project": "API", "kind": "authorization", "manifest": json.dumps(manifest), "csrf": "test-token"})
            status, headers, _ = self.request("POST", "/scans", body)
            self.assertEqual(status, 303)
            self.jobs.close()
            row = self.store.get(headers["Location"].split("/")[-1])
            self.assertEqual(json.loads(row["report"])["metrics"]["authorization"]["cases"][0]["outcome"], "violation")
            runner.assert_called_once_with(manifest)
