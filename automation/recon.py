"""
Passive/non-intrusive recon primitives.

Everything here is a TCP connect + read-only banner grab, or a DNS
lookup. Nothing sends exploit payloads, brute forces credentials, or
performs any write/destructive action. If `nmap` is available on PATH
it can optionally be used for richer service fingerprinting, but the
pipeline works fully without it.
"""
from __future__ import annotations

import shutil
import socket
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import List, Optional

DEFAULT_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 587, 993, 995,
                  3306, 3389, 5432, 6379, 8000, 8080, 8443, 9200, 27017]


@dataclass
class PortResult:
    port: int
    open: bool
    banner: Optional[str] = None


@dataclass
class HostRecon:
    host: str
    resolved_ip: Optional[str] = None
    resolve_error: Optional[str] = None
    ports: List[PortResult] = field(default_factory=list)

    @property
    def open_ports(self) -> List[PortResult]:
        return [p for p in self.ports if p.open]


def resolve_host(host: str) -> tuple[Optional[str], Optional[str]]:
    """Resolve a hostname to an IP. Returns (ip, error)."""
    try:
        return socket.gethostbyname(host), None
    except socket.gaierror as exc:
        return None, str(exc)


def _grab_banner(sock: socket.socket, port: int) -> Optional[str]:
    """Best-effort, read-only banner grab.

    First tries a purely passive read (many services — SSH, FTP, SMTP —
    greet you unprompted). If nothing arrives, falls back to sending a
    single, harmless HTTP HEAD request so plaintext web services on
    non-standard ports still identify themselves. This never attempts
    auth, never sends more than one request, and never retries."""
    try:
        sock.settimeout(1.0)
        data = sock.recv(256)
    except (socket.timeout, OSError):
        data = b""

    if not data:
        try:
            sock.sendall(b"HEAD / HTTP/1.0\r\nHost: banner-check\r\n\r\n")
            sock.settimeout(1.0)
            data = sock.recv(256)
        except (socket.timeout, OSError):
            data = b""

    return data.decode(errors="replace").strip().split("\n")[0][:200] if data else None


def tcp_connect_scan(
    host: str,
    ip: str,
    ports: List[int] = None,
    timeout: float = 1.0,
    max_workers: int = 25,
    grab_banners: bool = True,
) -> List[PortResult]:
    """Non-intrusive TCP connect scan. No SYN stealth, no fragmentation
    tricks — just a normal connect(), which is what any regular client
    does. Safe for internal, authorized targets."""
    ports = ports or DEFAULT_PORTS
    results: List[PortResult] = []

    def check(port: int) -> PortResult:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        try:
            rc = s.connect_ex((ip, port))
            if rc != 0:
                return PortResult(port=port, open=False)
            banner = _grab_banner(s, port) if grab_banners else None
            return PortResult(port=port, open=True, banner=banner)
        finally:
            s.close()

    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {pool.submit(check, p): p for p in ports}
        for fut in as_completed(futures):
            results.append(fut.result())

    return sorted(results, key=lambda r: r.port)


def nmap_available() -> bool:
    return shutil.which("nmap") is not None


def nmap_service_scan(ip: str, ports: List[int], timeout: int = 60) -> Optional[str]:
    """Optional richer fingerprinting if the operator has nmap installed.
    Uses -sV (version detection) and -Pn (skip host discovery, since we
    already know the host answers) against explicitly authorized IPs
    only. Returns raw nmap text output, or None if nmap isn't present.
    """
    if not nmap_available():
        return None
    port_arg = ",".join(str(p) for p in ports)
    try:
        proc = subprocess.run(
            ["nmap", "-Pn", "-sV", "-p", port_arg, ip],
            capture_output=True, text=True, timeout=timeout, check=False,
        )
        return proc.stdout
    except (subprocess.TimeoutExpired, OSError) as exc:
        return f"nmap invocation failed: {exc}"


def run_host_recon(host: str, ports: List[int] = None) -> HostRecon:
    ip, err = resolve_host(host)
    recon = HostRecon(host=host, resolved_ip=ip, resolve_error=err)
    if ip:
        recon.ports = tcp_connect_scan(host, ip, ports=ports)
    return recon
