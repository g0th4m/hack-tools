"""LFT traceroute task (menu integration)."""

from __future__ import annotations

import shutil

from oscp_scan.commands import cmd_to_string, confirm_command
from oscp_scan.lft import build_lft_cmd, default_port, run_lft_streaming
from oscp_scan.state import ScanState
from oscp_scan.ui import C, ask, ask_yes_no, c, print_cmd


def run_lft_trace(state: ScanState) -> bool:
    if not shutil.which("lft"):
        print(c("[!] lft not found in PATH.", C.RED))
        return False

    suggested = default_port(state.ports_tcp)
    if state.ports_tcp:
        ports = ",".join(str(p) for p in state.ports_tcp)
        print(c(f"[+] Open TCP ports from scan: {ports}", C.CYAN))

    port_str = ask("Destination port (-d)", str(suggested))
    if not port_str.isdigit() or not (1 <= int(port_str) <= 65535):
        print(c("[!] Invalid port.", C.RED))
        return False
    dport = int(port_str)

    udp = ask_yes_no("Use UDP probes (-u)?", default=False)
    adaptive = ask_yes_no("Use adaptive mode (-E)?", default=True)

    log_file = state.path / f"lft_{state.target}_{dport}.log"
    cmd = build_lft_cmd(
        state.target,
        dport=dport,
        adaptive=adaptive,
        udp=udp,
    )

    print()
    print(c(f"[+] LFT traceroute to {state.target}:{dport}", C.GREEN, C.BOLD))

    confirmed = confirm_command(cmd)
    if confirmed is None:
        return False

    cmd = confirmed
    command_str = cmd_to_string(cmd)
    print()
    print_cmd(cmd)
    print(c(f"    Log: {log_file}", C.CYAN))
    print()

    returncode = run_lft_streaming(cmd, log_file)
    state.log_command("lft", command_str, success=returncode == 0)

    print()
    print(c(f"[+] Log: {log_file}", C.GREEN))
    if returncode == 0:
        state.mark_task("lft", command=command_str)
    return returncode == 0
