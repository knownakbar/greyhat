"""
Rule-based, non-exploitative findings.

These rules flag *configuration hygiene* issues (missing headers, weak
TLS, risky open ports, cookie flags, banner disclosure) — the kind of
thing you'd want triaged in an internal assessment. There is
deliberately no exploit/PoC code here: this module never attempts to
confirm a vulnerability is exploitable, only that a risky
configuration is observable from the outside.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional

from .recon import HostRecon
from .webcheck import WebCheckResult, WEAK_TLS_VERSIONS

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

RISKY_PLAINTEXT_PORTS = {
    21: "FTP (unencrypted)",
    23: "Telnet (unencrypted)",
    25: "SMTP (check STARTTLS enforcement)",
    110: "POP3 (unencrypted)",
    143: "IMAP (unencrypted)",
    6379: "Redis (verify auth is enabled, bind address restricted)",
    27017: "MongoDB (verify auth is enabled, bind address restricted)",
    3306: "MySQL exposed beyond expected network segment?",
    5432: "PostgreSQL exposed beyond expected network segment?",
    9200: "Elasticsearch (verify auth is enabled)",
}


@dataclass
class Finding:
    target: str
    severity: str  # critical/high/medium/low/info
    title: str
    description: str
    evidence: str = ""
    recommendation: str = ""

    def sort_key(self):
        return SEVERITY_ORDER.get(self.severity, 9)


def evaluate_recon(recon: HostRecon) -> List[Finding]:
    findings: List[Finding] = []

    if recon.resolve_error:
        findings.append(Finding(
            target=recon.host, severity="info",
            title="DNS resolution failed",
            description=f"Could not resolve '{recon.host}': {recon.resolve_error}",
            recommendation="Confirm the hostname is correct and reachable from the scan host.",
        ))
        return findings

    for p in recon.open_ports:
        if p.port in RISKY_PLAINTEXT_PORTS:
            findings.append(Finding(
                target=recon.host, severity="medium",
                title=f"Potentially sensitive service exposed on port {p.port}",
                description=RISKY_PLAINTEXT_PORTS[p.port],
                evidence=f"Port {p.port} open" + (f", banner: {p.banner}" if p.banner else ""),
                recommendation="Confirm this service is intended to be reachable from this "
                               "network segment, that authentication is enforced, and that "
                               "traffic is encrypted where possible (e.g. FTPS/SFTP instead of FTP).",
            ))
        if p.banner and any(v in p.banner for v in ("Server:", "SSH-", "220 ", "OpenSSH")):
            findings.append(Finding(
                target=recon.host, severity="low",
                title=f"Service banner disclosed on port {p.port}",
                description="The service reveals version/product information in its banner, "
                             "which can help an attacker fingerprint known vulnerabilities.",
                evidence=p.banner,
                recommendation="Suppress or generalize version banners where feasible.",
            ))
    return findings


def evaluate_web(check: WebCheckResult) -> List[Finding]:
    findings: List[Finding] = []
    target = f"{check.host}:{check.port}"

    if check.error:
        findings.append(Finding(
            target=target, severity="info",
            title="Web check could not complete",
            description=check.error,
        ))
        return findings

    if check.missing_security_headers:
        sev = "medium" if "Content-Security-Policy" in check.missing_security_headers else "low"
        findings.append(Finding(
            target=target, severity=sev,
            title="Missing recommended security headers",
            description="Response is missing: " + ", ".join(check.missing_security_headers),
            evidence=f"HTTP {check.status_code}",
            recommendation="Add the missing headers appropriate to the application "
                           "(HSTS, CSP, X-Content-Type-Options, X-Frame-Options, "
                           "Referrer-Policy, Permissions-Policy).",
        ))

    server_header = check.headers.get("Server")
    if server_header and any(c.isdigit() for c in server_header):
        findings.append(Finding(
            target=target, severity="low",
            title="Server header discloses version information",
            description=f"Server header: {server_header}",
            recommendation="Remove or generalize version numbers in the Server header.",
        ))

    for issue in check.set_cookie_issues:
        findings.append(Finding(
            target=target, severity="medium",
            title="Cookie missing recommended security flags",
            description=issue,
            recommendation="Set Secure, HttpOnly, and an appropriate SameSite value on "
                           "session/auth cookies.",
        ))

    if check.scheme == "http":
        findings.append(Finding(
            target=target, severity="medium",
            title="Plaintext HTTP endpoint reachable",
            description="The endpoint responded over HTTP without TLS.",
            recommendation="Redirect all HTTP traffic to HTTPS and consider HSTS preload.",
        ))

    if check.tls:
        if check.tls.error:
            findings.append(Finding(
                target=target, severity="info",
                title="TLS check could not complete",
                description=check.tls.error,
            ))
        elif check.tls.negotiated_version in WEAK_TLS_VERSIONS:
            findings.append(Finding(
                target=target, severity="high",
                title=f"Weak TLS version negotiated: {check.tls.negotiated_version}",
                description="Server accepted a deprecated/insecure TLS protocol version.",
                recommendation="Disable TLS 1.0/1.1/SSLv2/SSLv3; require TLS 1.2+.",
            ))

    return findings
