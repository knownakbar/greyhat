import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from automation.recon import HostRecon, PortResult
from automation.webcheck import WebCheckResult, TlsInfo
from automation.vuln_rules import evaluate_recon, evaluate_web


class TestReconRules(unittest.TestCase):
    def test_resolve_failure_produces_info_finding(self):
        recon = HostRecon(host="doesnotexist.invalid", resolve_error="Name or service not known")
        findings = evaluate_recon(recon)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "info")

    def test_risky_plaintext_port_flagged(self):
        recon = HostRecon(host="10.0.0.5", resolved_ip="10.0.0.5",
                           ports=[PortResult(port=21, open=True, banner="220 FTP ready")])
        findings = evaluate_recon(recon)
        titles = [f.title for f in findings]
        self.assertTrue(any("port 21" in t for t in titles))

    def test_closed_ports_produce_no_findings(self):
        recon = HostRecon(host="10.0.0.5", resolved_ip="10.0.0.5",
                           ports=[PortResult(port=21, open=False)])
        self.assertEqual(evaluate_recon(recon), [])


class TestWebRules(unittest.TestCase):
    def test_missing_headers_flagged(self):
        check = WebCheckResult(host="app.internal", port=80, scheme="http",
                                status_code=200, headers={"Server": "nginx/1.18.0"},
                                missing_security_headers=[
                                    "Strict-Transport-Security", "Content-Security-Policy",
                                    "X-Content-Type-Options", "X-Frame-Options",
                                    "Referrer-Policy", "Permissions-Policy",
                                ])
        findings = evaluate_web(check)
        titles = [f.title for f in findings]
        self.assertIn("Missing recommended security headers", titles)
        self.assertIn("Server header discloses version information", titles)
        self.assertIn("Plaintext HTTP endpoint reachable", titles)

    def test_cookie_flags_flagged(self):
        check = WebCheckResult(host="app.internal", port=443, scheme="https",
                                status_code=200, headers={}, set_cookie_issues=[
                                    "Cookie 'session' missing: Secure, HttpOnly"])
        findings = evaluate_web(check)
        self.assertTrue(any("Cookie" in f.title for f in findings))

    def test_weak_tls_flagged(self):
        check = WebCheckResult(host="app.internal", port=443, scheme="https",
                                status_code=200, headers={
                                    "Strict-Transport-Security": "max-age=1",
                                    "Content-Security-Policy": "default-src 'self'",
                                    "X-Content-Type-Options": "nosniff",
                                    "X-Frame-Options": "DENY",
                                    "Referrer-Policy": "no-referrer",
                                    "Permissions-Policy": "geolocation=()",
                                },
                                tls=TlsInfo(negotiated_version="TLSv1"))
        findings = evaluate_web(check)
        self.assertTrue(any("Weak TLS" in f.title for f in findings))

    def test_clean_response_yields_minimal_findings(self):
        check = WebCheckResult(host="app.internal", port=443, scheme="https",
                                status_code=200, headers={
                                    "Strict-Transport-Security": "max-age=1",
                                    "Content-Security-Policy": "default-src 'self'",
                                    "X-Content-Type-Options": "nosniff",
                                    "X-Frame-Options": "DENY",
                                    "Referrer-Policy": "no-referrer",
                                    "Permissions-Policy": "geolocation=()",
                                },
                                tls=TlsInfo(negotiated_version="TLSv1.3"))
        findings = evaluate_web(check)
        self.assertEqual(findings, [])


if __name__ == "__main__":
    unittest.main()
