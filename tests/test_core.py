from email.message import Message
import json
from pathlib import Path
import tempfile
import unittest

from probekit.checks import cookie_findings, header_findings
from probekit.models import Finding, Report
from probekit.render import save_reports
from probekit.target import Target


class TargetTests(unittest.TestCase):
    def test_unicode_host_and_ipv6(self):
        self.assertEqual(Target.parse("https://été.example").host, "xn--t-9fab.example")
        self.assertEqual(Target.parse("http://[::1]:8000").url, "http://[::1]:8000/")

    def test_origin_is_preserved(self):
        target = Target.parse("https://example.test/a")
        self.assertTrue(target.accepts_redirect("https://example.test/b"))
        self.assertFalse(target.accepts_redirect("https://other.test/"))
        self.assertFalse(target.accepts_redirect("http://example.test/"))
        self.assertFalse(target.accepts_redirect("https://example.test:444/"))

    def test_invalid_inputs(self):
        for url in ("file:///etc/passwd", "https://user:pass@example.test", "https://x:70000", "https://x:0", "http://-bad.test", "http://example.test/\r\n"):
            with self.subTest(url=url), self.assertRaises(ValueError):
                Target.parse(url)


class CheckTests(unittest.TestCase):
    def test_api_is_not_flagged_for_missing_html_policies(self):
        headers = Message()
        headers["Content-Type"] = "application/json"
        codes = {finding.code for finding in header_findings(headers, True)}
        self.assertNotIn("WEB-CSP", codes)
        self.assertNotIn("WEB-FRAME", codes)

    def test_html_and_disabled_hsts(self):
        headers = Message()
        headers["Content-Type"] = "text/html; charset=utf-8"
        headers["Strict-Transport-Security"] = "max-age=0"
        codes = {finding.code for finding in header_findings(headers, True)}
        self.assertTrue({"WEB-HSTS", "WEB-CSP", "WEB-FRAME"}.issubset(codes))

    def test_configured_headers(self):
        headers = Message()
        headers["Content-Type"] = "text/html"
        headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        headers["Content-Security-Policy"] = "default-src 'self'; frame-ancestors 'none'"
        headers["X-Content-Type-Options"] = "nosniff"
        self.assertEqual(header_findings(headers, True), [])

    def test_cookie_values_are_not_exposed(self):
        headers = Message()
        headers["Set-Cookie"] = "session=supersecret; Path=/; SameSite=None"
        findings = cookie_findings(headers, True)
        self.assertEqual(len(findings), 1)
        self.assertNotIn("supersecret", str(findings))
        self.assertIn("Secure", findings[0].evidence)

    def test_secure_cookie(self):
        headers = Message()
        headers["Set-Cookie"] = "session=x; Secure; HttpOnly; SameSite=Lax"
        self.assertEqual(cookie_findings(headers, True), [])


class ReportTests(unittest.TestCase):
    def test_html_escapes_untrusted_content_and_json_roundtrip(self):
        report = Report("https://example.test/")
        report.findings.append(Finding("TEST", "info", "<script>alert(1)</script>", "a & b", "test"))
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as folder:
            save_reports(report, Path(folder))
            html = (Path(folder) / "report.html").read_text(encoding="utf-8")
            self.assertNotIn("<script>", html)
            self.assertIn("&lt;script&gt;", html)
            data = json.loads((Path(folder) / "report.json").read_text(encoding="utf-8"))
            self.assertEqual(data["findings"][0]["code"], "TEST")


if __name__ == "__main__":
    unittest.main()
