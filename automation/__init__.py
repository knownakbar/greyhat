"""
greyhat.automation
==================

A small, dependency-free automation framework for INTERNAL, AUTHORIZED
security assessments (recon -> triage -> report).

Hard rules baked into this package (see scope.py):
  1. Nothing is scanned unless it is explicitly listed in a signed-off
     authorization file (config/scope.json or similar).
  2. Authorization has a start/end date. Expired or not-yet-started
     authorization blocks every scan.
  3. Default checks are passive/non-intrusive only: TCP connect scans,
     banner/header reads, TLS metadata, DNS lookups. No exploitation,
     no brute force, no payload injection is implemented here.

This is a framework for YOUR OWN infrastructure / engagements you are
contractually or organizationally authorized to test. It is not a
weaponized attack tool and intentionally does not include exploit code.
"""

__version__ = "0.1.0"
