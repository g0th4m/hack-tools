"""Nmap scan tasks."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

from oscp_scan import hosts
from oscp_scan.parsers import nmap as nmap_parser
from oscp_scan.state import ScanState
from oscp_scan.ui import C, c, print_cmd


def _require_nmap() -> bool:
    if shutil.which("nmap"):
        return True
    print(c("[!] nmap not found in PATH.", C.RED))
    return False


def _run(cmd: list[str]) -> int:
    print_cmd(cmd)
    print()
    return subprocess.run(cmd).returncode


def run_full_tcp(state: ScanState) -> bool:
    if not _require_nmap():
        return False

    prefix = str(state.full_prefix)
    cmd = ["nmap", "-p-", "--min-rate", "5000", "-oA", prefix, state.target]
    print(c("[+] Full TCP port scan", C.YELLOW, C.BOLD))
    if _run(cmd) != 0:
        return False

    state.ports_tcp = nmap_parser.extract_open_ports(Path(f"{prefix}.gnmap"))
    state.mark_task("full_tcp")

    if state.ports_tcp:
        ports = ",".join(str(p) for p in state.ports_tcp)
        print(c(f"[+] Open TCP ports: {ports}", C.GREEN))
    else:
        print(c("[!] No open TCP ports.", C.YELLOW))
    return True


def run_detail_tcp(state: ScanState) -> bool:
    if not _require_nmap():
        return False

    if not state.ports_tcp:
        gnmap = Path(f"{state.full_prefix}.gnmap")
        state.ports_tcp = nmap_parser.extract_open_ports(gnmap)

    if not state.ports_tcp:
        print(c("[!] No known TCP ports. Run the full scan first.", C.RED))
        return False

    ports = ",".join(str(p) for p in state.ports_tcp)
    prefix = str(state.detail_prefix)
    cmd = ["nmap", "-sCV", "-p", ports, "-oA", prefix, state.target]
    print(c("[+] Detailed TCP scan (-sCV)", C.YELLOW, C.BOLD))
    if _run(cmd) != 0:
        return False

    state.mark_task("detail_tcp")
    update_domain_from_nmap(state)
    return True


def run_udp(state: ScanState, *, background: bool = False) -> bool:
    if not _require_nmap():
        return False

    prefix = str(state.udp_prefix)
    log_file = state.path / "udp.log"
    cmd = ["nmap", "-sU", "--top-ports", "100", "-oA", prefix, state.target]
    print(c("[+] UDP top-100 scan", C.YELLOW, C.BOLD))

    if background:
        print_cmd(cmd)
        print(c(f"    Log: {log_file}", C.CYAN))
        print()
        with log_file.open("w", encoding="utf-8") as log:
            proc = subprocess.Popen(cmd, stdout=log, stderr=subprocess.STDOUT)
        print(c(f"[+] UDP running in background (PID {proc.pid})", C.GREEN))
        state.mark_task("udp_bg_started")
        return True

    if _run(cmd) != 0:
        return False

    state.ports_udp = nmap_parser.extract_open_ports(Path(f"{prefix}.gnmap"), "udp")
    state.mark_task("udp")
    if state.ports_udp:
        ports = ",".join(str(p) for p in state.ports_udp)
        print(c(f"[+] Open UDP ports: {ports}", C.GREEN))
    else:
        print(c("[!] No open UDP ports (top-100).", C.YELLOW))
    return True


def update_domain_from_nmap(state: ScanState, *, offer_hosts: bool = False) -> None:
    detail_nmap = Path(f"{state.detail_prefix}.nmap")
    full_nmap = Path(f"{state.full_prefix}.nmap")
    gnmap = Path(f"{state.detail_prefix}.gnmap")

    source = detail_nmap if detail_nmap.exists() else full_nmap
    if not source.exists():
        print(c("[!] No nmap output to parse.", C.YELLOW))
        return

    domains = nmap_parser.extract_domains_from_nmap(source, state.target)
    state.all_domains = domains
    state.detected_domain = nmap_parser.pick_base_domain(domains)
    state.web_url = nmap_parser.extract_web_endpoint(gnmap, state.target)
    if not state.web_url:
        state.web_url = f"http://{state.target}"
    state.mark_task("domain_extracted")
    print_domain_detection(state, source)
    if offer_hosts:
        hosts.offer_hosts_update(state)


def print_domain_detection(state: ScanState, nmap_file: Path) -> None:
    print()
    print(c("=" * 50, C.GREEN, C.BOLD))

    if state.detected_domain:
        sources = nmap_parser.get_domain_sources(nmap_file, state.detected_domain)
        print(
            c("  Domain detected from nmap:", C.GREEN, C.BOLD),
            c(state.detected_domain, C.MAGENTA, C.BOLD),
        )
        if sources:
            print(c("  Source:", C.GREEN, C.BOLD), c(", ".join(sources), C.CYAN))
        others = [d for d in state.all_domains if d != state.detected_domain]
        if others:
            print(c("  Other hostnames found:", C.GREEN, C.BOLD))
            for host in others:
                print(c(f"    {host}", C.BLUE))
        if state.web_url:
            print(c("  Web endpoint:", C.GREEN, C.BOLD), c(state.web_url, C.CYAN))
    else:
        print(c("  No domain detected from nmap", C.YELLOW, C.BOLD))
        print(c("  You will need to enter it manually for ffuf.", C.YELLOW))

    print(c("=" * 50, C.GREEN, C.BOLD))
    print()
