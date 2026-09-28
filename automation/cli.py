"""
Command-line entry point.

Examples
--------
Show what a scope file authorizes without scanning anything:
    python3 -m automation.cli list-scope --scope config/scope.json

Run the full recon -> triage -> report pipeline:
    python3 -m automation.cli run --scope config/scope.json --out reports/
"""
from __future__ import annotations

import argparse
import logging
import sys

from .pipeline import run_pipeline
from .scope import load_scope, ScopeError, AuthorizationExpired


def _cmd_list_scope(args: argparse.Namespace) -> int:
    try:
        scope = load_scope(args.scope)
    except ScopeError as exc:
        print(f"Scope error: {exc}", file=sys.stderr)
        return 2

    active = scope.is_within_window()
    print(f"Engagement: {scope.engagement_id}")
    print(f"Authorized by: {scope.authorized_by}")
    print(f"Window: {scope.start_date} -> {scope.end_date}  "
          f"({'ACTIVE' if active else 'NOT ACTIVE'})")
    print(f"Safe mode: {scope.safe_mode}")
    print(f"Targets ({len(scope.targets)}):")
    for t in scope.targets:
        print(f"  - {t.host}  {('# ' + t.description) if t.description else ''}")
    return 0


def _cmd_run(args: argparse.Namespace) -> int:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
    )
    try:
        report_path = run_pipeline(args.scope, out_dir=args.out)
    except AuthorizationExpired as exc:
        print(f"BLOCKED: {exc}", file=sys.stderr)
        return 3
    except ScopeError as exc:
        print(f"Scope error: {exc}", file=sys.stderr)
        return 2

    print(f"Report written to: {report_path}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="greyhat-automation",
        description="Authorized-scope-only recon/triage/report pipeline for internal "
                    "security assessments.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_list = sub.add_parser("list-scope", help="Show what a scope file authorizes (no scanning).")
    p_list.add_argument("--scope", required=True, help="Path to the scope/authorization JSON file.")
    p_list.set_defaults(func=_cmd_list_scope)

    p_run = sub.add_parser("run", help="Run the full pipeline against every target in scope.")
    p_run.add_argument("--scope", required=True, help="Path to the scope/authorization JSON file.")
    p_run.add_argument("--out", default="reports", help="Directory to write the report bundle into.")
    p_run.set_defaults(func=_cmd_run)

    return parser


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
