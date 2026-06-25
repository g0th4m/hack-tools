"""Feroxbuster directory and file enumeration."""

from __future__ import annotations

import json
import re
import shutil
from pathlib import Path
from urllib.parse import urlparse

from oscp_scan.commands import cmd_to_string, confirm_command
from oscp_scan.feroxbuster_runner import run_feroxbuster_streaming
from oscp_scan.state import ScanState
from oscp_scan.ui import C, ask, ask_yes_no, c
from oscp_scan.wordlists import count_wordlist_lines, pick_wordlist

DEFAULT_WORDLIST = "/usr/share/seclists/Discovery/Web-Content/common.txt"
HIT_LINE_RE = re.compile(r"^(\d{3})\s+\S+\s+.*?(https?://\S+)", re.I)


def _target_slug(state: ScanState, url: str) -> str:
    host = urlparse(url).hostname or state.target
    return host.replace(".", "_").replace(":", "_")


def show_results(json_file: Path, log_file: Path) -> None:
    print(c("[+] Paths discovered:", C.GREEN))
    found: set[str] = set()

    if json_file.is_file() and json_file.stat().st_size > 0:
        for line in json_file.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue
            url = entry.get("url") or entry.get("original_url")
            status = entry.get("status") or entry.get("status_code") or "?"
            if url:
                found.add(f"{url} [{status}]")

    if log_file.is_file():
        for line in log_file.read_text(encoding="utf-8", errors="replace").splitlines():
            match = HIT_LINE_RE.search(line)
            if match:
                found.add(f"{match.group(2)} [{match.group(1)}]")

    if found:
        for entry in sorted(found):
            print(c(f"    {entry}", C.MAGENTA, C.BOLD))
    else:
        print(c("    (none)", C.YELLOW))


def _build_url(state: ScanState, domain: str | None) -> str:
    if state.web_url:
        return state.web_url.rstrip("/")
    if domain:
        return f"http://{domain}"
    return f"http://{state.target}"


def run_feroxbuster(
    state: ScanState,
    *,
    target_url: str | None = None,
    wordlist: str | None = None,
    wordlist_lines: int = 0,
    mode: str | None = None,
) -> bool:
    if not shutil.which("feroxbuster"):
        print(c("[!] feroxbuster not found in PATH.", C.RED))
        return False

    domain = state.detected_domain
    base_url = target_url or _build_url(state, domain)

    if not wordlist:
        wl_default = DEFAULT_WORDLIST if Path(DEFAULT_WORDLIST).is_file() else None
        picked = pick_wordlist(default_path=wl_default, default_filter="web-content")
        if not picked:
            print(c("[!] No wordlist selected.", C.RED))
            return False
        wordlist, wordlist_lines = picked

    if not wordlist or not Path(wordlist).is_file():
        print(c(f"[!] Wordlist not found: {wordlist}", C.RED))
        return False

    if wordlist_lines <= 0:
        wordlist_lines = count_wordlist_lines(wordlist)

    custom_url = ask("Target URL", base_url)
    if not custom_url:
        print(c("[!] No target URL specified.", C.YELLOW))
        return False

    slug = _target_slug(state, custom_url)
    out_json = state.path / f"feroxbuster_{slug}.json"
    out_log = state.path / f"feroxbuster_{slug}.log"

    if mode is None and domain:
        print(c("Feroxbuster mode:", C.CYAN))
        print(c(f"  1) URL {custom_url}", C.BOLD))
        print(c(f"  2) vhost on IP with Host: {domain} ({state.web_url or f'http://{state.target}'})", C.BOLD))
        choice = ask("Choose mode", "1")
        mode = "vhost" if choice == "2" else "direct"
    else:
        mode = mode or "direct"

    cmd = [
        "feroxbuster",
        "-u", custom_url if mode == "direct" else (state.web_url or f"http://{state.target}"),
        "-w", wordlist,
        "-t", "50",
        "-k",
        "--no-state",
        "--json",
        "-o", str(out_json),
    ]

    if mode == "vhost" and domain:
        cmd.extend(["-H", f"Host: {domain}"])

    recursion = ask_yes_no("Enable recursion?", default=True)
    if not recursion:
        cmd.append("-n")

    print()
    print(c(f"[+] Starting feroxbuster on: {custom_url}", C.GREEN, C.BOLD))
    print(c(f"[+] Wordlist: {wordlist} ({wordlist_lines:,} lines)", C.CYAN))

    confirmed = confirm_command(cmd)
    if confirmed is None:
        return False

    cmd = confirmed
    print()

    returncode = run_feroxbuster_streaming(cmd, out_log, wordlist_lines=wordlist_lines)
    command_str = cmd_to_string(cmd)
    state.log_command("feroxbuster", command_str, success=returncode == 0)

    print()
    show_results(out_json, out_log)
    print(c(f"[+] Output: {out_json}", C.GREEN))
    print(c(f"[+] Log: {out_log}", C.GREEN))
    if returncode == 0:
        state.mark_task("feroxbuster", command=command_str)
    return returncode == 0
