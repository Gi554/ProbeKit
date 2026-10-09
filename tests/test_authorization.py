import copy
import importlib.util
import json
import os
from pathlib import Path
import threading
import unittest
from unittest.mock import patch
from http.server import ThreadingHTTPServer

from probekit.authorization import audit_authorization, pointer

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("lab", ROOT / "examples/lab.py")
lab = importlib.util.module_from_spec(spec)
spec.loader.exec_module(lab)


class AuthorizationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), lab.Handler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join()

    def run_manifest(self, mutate=None):
        manifest = json.loads((ROOT / "examples/authorization.json").read_text(encoding="utf-8"))
        manifest["origin"] = f"http://127.0.0.1:{self.server.server_port}"
        if mutate:
            mutate(manifest)
        with patch.dict(os.environ, PROBEKIT_ALICE="Bearer lab-alice", PROBEKIT_BOB="Bearer lab-bob"):
            return audit_authorization(manifest)

    def test_vulnerable_and_fixed_and_no_secrets(self):
        report = self.run_manifest()
        self.assertEqual(len(report.findings), 1)
        self.assertEqual([c["outcome"] for c in report.metrics["authorization"]["cases"]], ["violation", "passed"])
        self.assertEqual(report.errors, [])
        payload = json.dumps(report.to_dict())
        self.assertNotIn("Bearer", payload)
        self.assertNotIn("lab-only", payload)

    def test_200_error_is_not_a_vulnerability(self):
        report = self.run_manifest(lambda m: m["cases"][0].update(path="/api/misleading/101"))
        self.assertFalse(report.findings)
        self.assertTrue(report.errors)

    def test_unverified_identity_does_not_pass(self):
        report = self.run_manifest(lambda m: m["accounts"]["bob"].update(identity={"/user": "charlie"}))
        self.assertFalse(report.findings)
        self.assertEqual(report.metrics["authorization"]["cases"][1]["outcome"], "inconclusive")

    def test_outside_scope_never_passes(self):
        report = self.run_manifest(lambda m: m["cases"][0].update(path="https://example.com/api/101"))
        self.assertFalse(report.findings)
        self.assertEqual(report.metrics["authorization"]["cases"][0]["responses"], [])

    def test_pointer_escapes(self):
        self.assertEqual(pointer({"a/b": {"~": [9]}}, "/a~1b/~0/0"), 9)

    def test_duplicate_principals_rejected(self):
        with self.assertRaises(ValueError):
            self.run_manifest(lambda m: m["accounts"]["bob"].update(identity={"/user": "alice"}))

    def test_redirect_is_not_followed(self):
        report = self.run_manifest(lambda m: m["cases"][0].update(path="/api/redirect"))
        self.assertFalse(report.findings)
        self.assertEqual([r["status"] for r in report.metrics["authorization"]["cases"][0]["responses"]], [302, 302, 302])
