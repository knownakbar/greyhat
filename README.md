# greyhat

An authorized-only security workspace.

- `index.html` / `app.js` / `styles.css` — a front-end preview of a
  scoped, safe-mode "control room" UI for reviewing findings.
- `automation/` — a real, dependency-free recon → triage → report
  pipeline for automating internal, authorized security assessments.
  See **[AUTOMATION.md](./AUTOMATION.md)** for usage, safety
  guardrails, and how to extend it with tools like nmap/nuclei.

Everything in this repo is scoped around explicit authorization:
nothing scans or reports on a target that isn't declared in a signed
engagement/scope file with an active date window.
