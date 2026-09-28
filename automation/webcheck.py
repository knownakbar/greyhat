"""
Read-only HTTP/TLS hygiene checks.

Everything here is a single GET/HEAD request or a TLS handshake —
the same thing a browser does when it loads the page. No fuzzing,
no injection, no auth bypass attempts.
"""
from __future__ import annotations

import http.client
import socket
import ssl
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional

SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "Referrer-Policy",
    "Permissions-Policy",
]

WEAK_TLS_VERSIONS = {"TLSv1", "TLSv1.1", "SSLv2", "SSLv3"}


@dataclass
class TlsInfo:
    negotiated_version: Optional[str] = None
    cipher: Optional[str] = None
    cert_subject: Optional[str] = None
    cert_not_after: Optional[str] = None
    error: Optional[str] = None


@dataclass
class WebCheckResult:
    host: str
    port: int
    scheme: str
    status_code: Optional[int] = None
    headers: Dict[str, str] = field(default_factory=dict)
    missing_security_headers: List[str] = field(default_factory=list)
    set_cookie_issues: List[str] = field(default_factory=list)
    tls: Optional[TlsInfo] = None
    error: Optional[str] = None


def _check_tls(host: str, port: int, timeout: float = 4.0) -> TlsInfo:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE  # we're reporting on config, not trusting it
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls_sock:
                cert = tls_sock.getpeercert()
                subject = None
                not_after = None
                if cert:
                    subj_fields = cert.get("subject", [])
                    subject = ", ".join(f"{k}={v}" for pair in subj_fields for (k, v) in pair)
                    not_after = cert.get("notAfter")
                return TlsInfo(
                    negotiated_version=tls_sock.version(),
                    cipher=(tls_sock.cipher() or [None])[0],
                    cert_subject=subject,
                    cert_not_after=not_after,
                )
    except Exception as exc:  # noqa: BLE001 - report, don't crash the pipeline
        return TlsInfo(error=str(exc))


def _cookie_issues(set_cookie_values: List[str]) -> List[str]:
    issues = []
    for raw in set_cookie_values:
        name = raw.split("=", 1)[0].strip()
        lowered = raw.lower()
        flags_missing = []
        if "secure" not in lowered:
            flags_missing.append("Secure")
        if "httponly" not in lowered:
            flags_missing.append("HttpOnly")
        if "samesite" not in lowered:
            flags_missing.append("SameSite")
        if flags_missing:
            issues.append(f"Cookie '{name}' missing: {', '.join(flags_missing)}")
    return issues


def check_web_endpoint(host: str, port: int, use_tls: bool, timeout: float = 4.0) -> WebCheckResult:
    scheme = "https" if use_tls else "http"
    result = WebCheckResult(host=host, port=port, scheme=scheme)

    try:
        conn_cls = http.client.HTTPSConnection if use_tls else http.client.HTTPConnection
        if use_tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            conn = conn_cls(host, port, timeout=timeout, context=ctx)
        else:
            conn = conn_cls(host, port, timeout=timeout)

        conn.request("GET", "/", headers={"User-Agent": "greyhat-internal-scan/0.1 (authorized)"})
        resp = conn.getresponse()
        result.status_code = resp.status
        headers = {k: v for k, v in resp.getheaders()}
        result.headers = headers
        resp.read(4096)  # drain a bit, don't hang the connection
        conn.close()

        result.missing_security_headers = [
            h for h in SECURITY_HEADERS if h not in headers
        ]

        set_cookie_raw = [v for k, v in resp.getheaders() if k.lower() == "set-cookie"]
        result.set_cookie_issues = _cookie_issues(set_cookie_raw)

    except Exception as exc:  # noqa: BLE001
        result.error = str(exc)
        return result

    if use_tls:
        result.tls = _check_tls(host, port, timeout=timeout)

    return result
