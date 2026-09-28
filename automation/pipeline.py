"""
Wire scope enforcement + recon + web checks + triage + reporting into
one command.

    python3 -m automation.cli run --scope config/scope.json
"""
from __future__ import annotations

import logging
from dataclasses import asdict
from pathlib import Path
from typing import List

from .scope import Scope, load_scope
from .recon import run_host_recon, HostRecon
from .webcheck import check_web_endpoint, WebCheckResult
from .vuln_rules import Finding, evaluate_recon, evaluate_web
from .triage import triage
from .report import write_report

logger = logging.getLogger("greyhat.pipeline")

# Ports we treat as "probably HTTP" / "probably HTTPS" for the web-check
# stage. Anything else discovered open just gets the port-level recon
# findings (see vuln_rules.evaluate_recon).
HTTP_PORTS = {80, 8000, 8080}
HTTPS_PORTS = {443, 8443}


def run_pipeline(scope_path: str | Path, out_dir: str | Path = "reports") -> Path:
    scope = load_scope(scope_path)
    scope.require_active()  # raises AuthorizationExpired if outside the window

    targets = scope.targets[: scope.max_targets]
    if len(scope.targets) > scope.max_targets:
        logger.warning(
            "Scope lists %d targets but max_targets=%d; only scanning the first %d.",
            len(scope.targets), scope.max_targets, scope.max_targets,
        )

    all_findings: List[Finding] = []
    raw_evidence = {"engagement_id": scope.engagement_id, "hosts": []}

    for target in targets:
        host = target.host
        logger.info("Running recon against authorized host: %s", host)
        recon: HostRecon = run_host_recon(host, ports=target.allowed_ports)
        all_findings.extend(evaluate_recon(recon))

        web_checks: List[WebCheckResult] = []
        for p in recon.open_ports:
            looks_like_http_banner = bool(p.banner) and p.banner.upper().startswith("HTTP/")
            if p.port in HTTPS_PORTS:
                web_checks.append(check_web_endpoint(host, p.port, use_tls=True))
            elif p.port in HTTP_PORTS or looks_like_http_banner:
                web_checks.append(check_web_endpoint(host, p.port, use_tls=False))

        for wc in web_checks:
            all_findings.extend(evaluate_web(wc))

        raw_evidence["hosts"].append({
            "host": host,
            "recon": asdict(recon),
            "web_checks": [asdict(w) for w in web_checks],
        })

    findings = triage(all_findings)
    report_path = write_report(scope, findings, raw_evidence, out_dir=out_dir)
    return report_path
