"""
Scope & authorization enforcement.

Every target the pipeline touches must:
  - appear in the authorization file's `targets` list, AND
  - fall within the engagement's start_date/end_date window.

This module has no side effects beyond reading a JSON file and doing
local matching. It never contacts a network.
"""
from __future__ import annotations

import ipaddress
import json
import fnmatch
from dataclasses import dataclass, field
from datetime import datetime, date
from pathlib import Path
from typing import List, Optional


class ScopeError(Exception):
    """Raised for malformed or invalid scope/authorization files."""


class AuthorizationExpired(Exception):
    """Raised when the engagement window does not cover 'now'."""


@dataclass
class Target:
    host: str  # hostname, wildcard (*.example.com), IP, or CIDR
    description: str = ""
    allowed_ports: Optional[List[int]] = None  # None = use pipeline default
    notes: str = ""

    def matches(self, candidate: str) -> bool:
        """Return True if `candidate` (hostname or IP) is covered by this target entry."""
        candidate = candidate.strip().lower()
        pattern = self.host.strip().lower()

        # CIDR / IP range match
        try:
            network = ipaddress.ip_network(pattern, strict=False)
            try:
                ip = ipaddress.ip_address(candidate)
                return ip in network
            except ValueError:
                return False
        except ValueError:
            pass  # not an IP/CIDR, fall through to hostname matching

        # Exact or wildcard hostname match (e.g. *.internal.corp)
        return fnmatch.fnmatch(candidate, pattern)


@dataclass
class Scope:
    engagement_id: str
    authorized_by: str
    start_date: date
    end_date: date
    targets: List[Target] = field(default_factory=list)
    max_targets: int = 50
    safe_mode: bool = True  # when True, only passive/non-intrusive checks run
    notes: str = ""

    def is_within_window(self, when: Optional[datetime] = None) -> bool:
        when = when or datetime.now()
        today = when.date()
        return self.start_date <= today <= self.end_date

    def require_active(self) -> None:
        if not self.is_within_window():
            raise AuthorizationExpired(
                f"Engagement '{self.engagement_id}' authorization window is "
                f"{self.start_date} -> {self.end_date}; today is outside that range. "
                f"Refusing to run."
            )

    def is_host_authorized(self, host: str) -> bool:
        return any(t.matches(host) for t in self.targets)

    def filter_authorized(self, hosts: List[str]) -> List[str]:
        return [h for h in hosts if self.is_host_authorized(h)]


def _parse_date(value: str) -> date:
    try:
        return datetime.strptime(value, "%Y-%m-%d").date()
    except ValueError as exc:
        raise ScopeError(f"Invalid date '{value}', expected YYYY-MM-DD") from exc


def load_scope(path: str | Path) -> Scope:
    path = Path(path)
    if not path.exists():
        raise ScopeError(f"Scope/authorization file not found: {path}")

    try:
        data = json.loads(path.read_text())
    except json.JSONDecodeError as exc:
        raise ScopeError(f"Scope file is not valid JSON: {exc}") from exc

    required = ["engagement_id", "authorized_by", "start_date", "end_date", "targets"]
    missing = [k for k in required if k not in data]
    if missing:
        raise ScopeError(f"Scope file missing required field(s): {', '.join(missing)}")

    if not data["targets"]:
        raise ScopeError("Scope file lists zero targets; nothing is authorized.")

    targets = [
        Target(
            host=t["host"],
            description=t.get("description", ""),
            allowed_ports=t.get("allowed_ports"),
            notes=t.get("notes", ""),
        )
        for t in data["targets"]
    ]

    return Scope(
        engagement_id=data["engagement_id"],
        authorized_by=data["authorized_by"],
        start_date=_parse_date(data["start_date"]),
        end_date=_parse_date(data["end_date"]),
        targets=targets,
        max_targets=int(data.get("max_targets", 50)),
        safe_mode=bool(data.get("safe_mode", True)),
        notes=data.get("notes", ""),
    )
