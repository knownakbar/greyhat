# greyhat automation — recon → triage → report

A dependency-free Python pipeline for automating the repetitive parts of
**internal, authorized** security assessments: enumerate what's open,
run passive/non-intrusive hygiene checks against it, prioritize the
results, and generate an audit-ready report. It is deliberately **not**
an exploitation framework — there is no exploit/PoC/brute-force code in
this repo, by design.

## Why it's safe to point at real infrastructure

1. **Hard scope gate.** Every scan is driven by a JSON "authorization
   file" (`config/scope.json`, gitignored — only `scope.example.json`
   ships in the repo). The pipeline will not touch any host that isn't
   listed there, full stop (`automation/scope.py`).
2. **Time-boxed.** The authorization file has a `start_date`/`end_date`.
   Outside that window the CLI refuses to run (exit code 3) instead of
   scanning anything.
3. **Passive by default.** Checks are TCP connect scans, read-only
   banner reads, a single HTTP GET, and a TLS handshake — the same
   things a normal client does. No fuzzing, no auth bypass attempts, no
   brute forcing, no payloads. `safe_mode` is on by default in the
   scope file as a reminder of that contract.
4. **Full audit trail.** Every run writes raw evidence
   (`evidence.json`), structured findings (`findings.json`), and a
   human-readable `report.md` under `reports/<engagement_id>/<timestamp>/`.

## Quick start

```bash
# 1. Copy the example scope and fill in your real, authorized targets
cp config/scope.example.json config/scope.json
$EDITOR config/scope.json   # engagement_id, authorized_by, dates, targets

# 2. Sanity-check what's authorized (does not touch the network)
python3 -m automation.cli list-scope --scope config/scope.json

# 3. Run the pipeline
python3 -m automation.cli run --scope config/scope.json --out reports/
```

Output:

```
reports/<engagement_id>/<timestamp>/
├── report.md        # human-readable findings + summary + recommendations
├── findings.json     # structured findings for ticketing/SIEM ingestion
└── evidence.json      # raw recon/webcheck data for the audit trail
```

## What it checks today

- **Recon** (`automation/recon.py`): DNS resolution, TCP connect scan
  across a configurable port list (or `allowed_ports` per target),
  best-effort banner grabbing.
- **Web hygiene** (`automation/webcheck.py`): missing security headers
  (HSTS/CSP/X-Frame-Options/etc.), cookie flag issues (Secure/HttpOnly/
  SameSite), TLS version/cipher/cert metadata, server banner disclosure.
- **Rules** (`automation/vuln_rules.py`): turns the raw signal above
  into severity-tagged findings with a recommendation. These are
  *configuration hygiene* findings, not confirmed exploitable
  vulnerabilities — validate before treating them as such.

## Extending it with real tooling

The framework has clean seams to shell out to industry-standard tools
once you have them installed in your own environment (they are **not**
bundled or auto-installed here):

- `automation/recon.py::nmap_service_scan()` already shows the pattern
  for wrapping `nmap -Pn -sV` — add similar wrappers for `subfinder`,
  `httpx`, `naabu`, etc., gated the same way behind the scope check.
- Add a new `automation/vuln_rules_*.py` module to parse a scanner's
  output (e.g. `nuclei -json`) into the same `Finding` shape so it
  flows through `triage.py` and `report.py` unchanged.
- Keep any new integration **read-only/non-intrusive by default**, and
  make anything more active (auth testing, exploitation) an explicit,
  separately-gated opt-in — never the default path.

## Running the tests

```bash
python3 -m unittest discover -s tests -v
```

## Ethics / legal reminder

Only point this at systems you own or have **explicit, documented
authorization** to test (a signed scope-of-work, a bug bounty program's
published scope, or your org's internal change/security approval).
Scanning systems without authorization is illegal in most
jurisdictions and against the terms of virtually every hosting/cloud
provider. This tool's scope gate is a safety net, not a substitute for
getting real sign-off first.
