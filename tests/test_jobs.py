from pathlib import Path
import tempfile
import time
import unittest

from probekit.dashboard import dashboard, detail
from probekit.jobs import Jobs
from probekit.models import Finding, Report
from probekit.store import Store, decode_report
from probekit.target import Target


class JobsTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(dir=Path.cwd())
        self.store = Store(Path(self.temporary.name) / "test.sqlite")

    def tearDown(self):
        self.temporary.cleanup()

    def wait(self, scan_id):
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            row = self.store.get(scan_id)
            if row["state"] not in {"queued", "running"}:
                return row
            time.sleep(0.01)
        self.fail("Job did not finish")

    def test_job_persists_report_and_partial_collection_status(self):
        def runner(target):
            return Report(target.url, status=200, errors=["TLS unavailable"])
        jobs = Jobs(self.store, runner)
        try:
            scan_id = jobs.submit(Target.parse("http://example.test/"), "Project")
            row = self.wait(scan_id)
        finally:
            jobs.close()
        self.assertEqual(row["state"], "partial")
        self.assertEqual(decode_report(row["report"]).status, 200)

    def test_unexpected_failure_is_recorded(self):
        def runner(target):
            raise RuntimeError("test failure")
        jobs = Jobs(self.store, runner)
        try:
            scan_id = jobs.submit(Target.parse("http://example.test/"), "Project")
            row = self.wait(scan_id)
        finally:
            jobs.close()
        self.assertEqual(row["state"], "failed")
        self.assertIn("test failure", row["error"])

    def test_recovery_and_parameterized_lookup(self):
        scan_id = self.store.create("http://example.test/", "Project")
        self.store.recover()
        self.assertEqual(self.store.get(scan_id)["state"], "failed")
        self.assertIsNone(self.store.get("' OR 1=1 --"))

    def test_dashboard_escapes_project_and_report_content(self):
        scan_id = self.store.create("http://example.test/", "<script>alert(1)</script>")
        report = Report("http://example.test/", status=200, findings=[Finding("TEST", "info", "<img src=x>", "test", "test")])
        self.store.update(scan_id, "done", report)
        row = self.store.get(scan_id)
        for document in (dashboard([row], "test-token"), detail(row)):
            self.assertNotIn("<script>", document)
            self.assertNotIn("<img src=x>", document)
