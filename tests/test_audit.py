from email.message import Message
from urllib.error import HTTPError, URLError
from urllib.request import Request
import unittest
from unittest.mock import MagicMock, patch

from probekit.audit import ScopeRedirect, audit
from probekit.checks import header_findings
from probekit.target import Target


class AuditTests(unittest.TestCase):
    def test_http_errors_preserve_headers(self):
        headers = Message()
        headers["Content-Type"] = "text/html"
        with patch("probekit.audit.build_opener") as opener:
            opener.return_value.open.side_effect = HTTPError("http://example.test/", 403, "Forbidden", headers, None)
            report = audit(Target.parse("http://example.test/"))
        self.assertEqual(report.status, 403)
        self.assertIn("WEB-CSP", {item.code for item in report.findings})

    def test_collection_failure_is_not_a_clean_scan(self):
        with patch("probekit.audit.build_opener") as opener:
            opener.return_value.open.side_effect = URLError("unreachable")
            report = audit(Target.parse("http://example.test/"))
        self.assertIsNone(report.status)
        self.assertEqual(len(report.errors), 1)

    def test_cookie_values_not_in_collected_report(self):
        headers = Message()
        headers["Set-Cookie"] = "session=private-value; Path=/"
        response = MagicMock()
        response.status = 200
        response.headers = headers
        with patch("probekit.audit.build_opener") as opener:
            opener.return_value.open.return_value = response
            report = audit(Target.parse("http://example.test/"))
        self.assertNotIn("private-value", str(report.to_dict()))

    def test_redirect_outside_origin_is_blocked_before_next_request(self):
        target = Target.parse("https://example.test/")
        handler = ScopeRedirect(target)
        with self.assertRaises(HTTPError):
            handler.redirect_request(Request(target.url), None, 302, "Found", Message(), "https://other.test/")

    def test_frame_wildcard_does_not_protect_even_with_xframe(self):
        headers = Message()
        headers["Content-Type"] = "text/html"
        headers["Content-Security-Policy"] = "frame-ancestors *"
        headers["X-Frame-Options"] = "DENY"
        self.assertIn("WEB-FRAME", {item.code for item in header_findings(headers, True)})
