"""FFuf subdomain / vhost enumeration."""

from __future__ import annotations

import json
import re
import shutil
from pathlib import Path

from oscp_scan.commands import cmd_to_string, confirm_command
from oscp_scan.ffuf_runner import run_ffuf_with_progress
from oscp_scan.state import ScanState
from oscp_scan.ui import C, ask, c
from oscp_scan.wordlists import count_wordlist_lines, pick_wordlist


def _full_host(fuzz: str, domain: str) -> str:
    return fuzz if domain in fuzz else f"{fuzz}.{domain}"


def show_results(json_file: Path, log_file: Path, domain: str) -> None:
    print(c("[+] Subdomains / vhosts found:", C.GREEN))
    found: set[str] = set()

    if json_file.is_file() and json_file.stat().st_size > 0:
        try:
            data = json.loads(json_file.read_text(encoding="utf-8"))
            for result in data.get("results", []):
                fuzz = (result.get("input") or {}).get("FUZZ", "")
                if not fuzz:
                    continue
                host = _full_host(fuzz, domain)
                status = result.get("status", "?")
                length = result.get("length", "?")
                found.add(f"{host} [{status}] {length}b")
        except json.JSONDecodeError:
            pass

    if log_file.is_file():
        for line in log_file.read_text(encoding="utf-8", errors="replace").splitlines():
            match = re.search(r"\* FUZZ:\s*(\S+)", line)
            if match:
                found.add(_full_host(match.group(1), domain))

    if found:
        for entry in sorted(found):
            print(c(f"    {entry}", C.MAGENTA, C.BOLD))
    else:
        print(c("    (none)", C.YELLOW))


def run_ffuf(
    state: ScanState,
    *,
    domain: str | None = None,
    wordlist: str | None = None,
    wordlist_lines: int = 0,
    mode: str | None = None,
) -> bool:
    if not shutil.which("ffuf"):
        print(c("[!] ffuf not found in PATH.", C.RED))
        return False

    domain = domain or state.detected_domain
    if not domain:
        domain = ask("Enter base domain (e.g. target.htb)")
    if not domain:
        print(c("[!] No domain specified.", C.YELLOW))
        return False

    if not wordlist:
        wl_default = (
            "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt"
            if Path("/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt").is_file()
            else None
        )
        picked = pick_wordlist(default_path=wl_default)
        if not picked:
            print(c("[!] No wordlist selected.", C.RED))
            return False
        wordlist, wordlist_lines = picked

    if not wordlist or not Path(wordlist).is_file():
        print(c(f"[!] Wordlist not found: {wordlist}", C.RED))
        return False

    if wordlist_lines <= 0:
        wordlist_lines = count_wordlist_lines(wordlist)

    ffuf_url = state.web_url or f"http://{state.target}"
    safe_name = domain.replace(".", "_")
    out_json = state.path / f"ffuf_{safe_name}.json"
    out_log = state.path / f"ffuf_{safe_name}.log"

    if mode is None:
        print(c("FFuf mode:", C.CYAN))
        print(c(f"  1) vhost on {ffuf_url} (Host: FUZZ.{domain})", C.BOLD))
        print(c(f"  2) direct DNS (http://FUZZ.{domain})", C.BOLD))
        choice = ask("Choose mode", "1")
        mode = "direct" if choice == "2" else "vhost"

    if mode == "vhost":
        cmd = [
            "ffuf", "-w", wordlist, "-u", ffuf_url,
            "-H", f"Host: FUZZ.{domain}",
            "-ac", "-t", "40", "-v",
            "-o", str(out_json), "-of", "json",
        ]
    else:
        cmd = [
            "ffuf", "-w", wordlist, "-u", f"http://FUZZ.{domain}",
            "-ac", "-t", "40", "-v",
            "-o", str(out_json), "-of", "json",
        ]

    print()
    print(c(f"[+] Starting ffuf on domain: {domain}", C.GREEN, C.BOLD))
    print(c(f"[+] Wordlist: {wordlist} ({wordlist_lines:,} lines)", C.CYAN))

    confirmed = confirm_command(cmd)
    if confirmed is None:
        return False

    cmd = confirmed
    print()

    returncode = run_ffuf_with_progress(
        cmd,
        out_log,
        wordlist_lines=wordlist_lines,
    )

    command_str = cmd_to_string(cmd)
    state.log_command("ffuf", command_str, success=returncode == 0)

    print()
    show_results(out_json, out_log, domain)
    print(c(f"[+] Output: {out_json}", C.GREEN))
    print(c(f"[+] Log: {out_log}", C.GREEN))
    if returncode == 0:
        state.mark_task("ffuf", command=command_str)
    return returncode == 0
