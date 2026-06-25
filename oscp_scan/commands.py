"""Confirm, edit, and execute shell commands with audit logging."""

from __future__ import annotations

import shlex
import subprocess
from pathlib import Path

from oscp_scan.state import ScanState
from oscp_scan.ui import C, c, print_cmd


def cmd_to_string(cmd: list[str]) -> str:
    return shlex.join(cmd)


def parse_command_line(line: str) -> list[str]:
    return shlex.split(line)


def confirm_command(cmd: list[str]) -> list[str] | None:
    proposed = cmd_to_string(cmd)
    print()
    print(c("Proposed command:", C.CYAN, C.BOLD))
    print(c(f"  {proposed}", C.BLUE))
    print()
    print(c("  [Enter] Run   |   e Edit   |   c Cancel", C.YELLOW))
    choice = input(c("> ", C.YELLOW)).strip().lower()

    if choice in ("c", "cancel", "n", "no"):
        print(c("[!] Command cancelled.", C.YELLOW))
        return None

    if choice in ("e", "edit"):
        print(c("Edit command (single line):", C.YELLOW))
        edited = input(c("$ ", C.BLUE)).strip() or proposed
        try:
            parsed = parse_command_line(edited)
        except ValueError:
            print(c("[!] Invalid command syntax.", C.RED))
            return None
        if not parsed:
            print(c("[!] Empty command.", C.RED))
            return None
        print(c(f"[+] Using: {cmd_to_string(parsed)}", C.GREEN))
        return parsed

    return list(cmd)


def run_confirmed(
    state: ScanState,
    task_id: str,
    cmd: list[str],
) -> tuple[int, str | None]:
    """Confirm, run, and log a command. Returns (exit code, command string)."""
    confirmed = confirm_command(cmd)
    if confirmed is None:
        return -1, None

    command_str = cmd_to_string(confirmed)
    print()
    print_cmd(confirmed)
    print()

    returncode = subprocess.run(confirmed).returncode
    state.log_command(task_id, command_str, success=returncode == 0)
    if returncode != 0:
        print(c(f"[!] Command exited with code {returncode}.", C.RED))

    return returncode, command_str


def run_confirmed_background(
    state: ScanState,
    task_id: str,
    cmd: list[str],
    log_file: Path,
) -> tuple[subprocess.Popen[str] | None, str | None]:
    confirmed = confirm_command(cmd)
    if confirmed is None:
        return None, None

    command_str = cmd_to_string(confirmed)
    print()
    print_cmd(confirmed)
    print(c(f"    Log: {log_file}", C.CYAN))
    print()

    with log_file.open("w", encoding="utf-8") as log:
        proc = subprocess.Popen(confirmed, stdout=log, stderr=subprocess.STDOUT)

    state.log_command(task_id, command_str, success=True)
    return proc, command_str
