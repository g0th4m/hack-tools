"""FFuf subdomain / vhost enumeration."""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from pathlib import Path

from oscp_scan.state import ScanState
from oscp_scan.ui import C, ask, c, print_cmd

WORDLIST_CANDIDATES = [
    "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
    "/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
    "/usr/share/wordlists/dirb/common.txt",
]


def default_wordlist() -> str | None:
    for path in WORDLIST_CANDIDATES:
        if Path(path).is_file():
            return path
    return None


def _full_host(fuzz: str, domain: str) -> str:
    return fuzz if domain in fuzz else f"{fuzz}.{domain}"


def show_results(json_file: Path, log_file: Path, domain: str) -> None:
    print(c("[+] Subdomains / vhosts trovati:", C.GREEN))
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
        print(c("    (nessuno)", C.YELLOW))


def run_ffuf(
    state: ScanState,
    *,
    domain: str | None = None,
    wordlist: str | None = None,
    mode: str | None = None,
) -> bool:
    if not shutil.which("ffuf"):
        print(c("[!] ffuf non trovato in PATH.", C.RED))
        return False

    domain = domain or state.detected_domain
    if not domain:
        domain = ask("Inserisci il dominio base (es. target.htb)")
    if not domain:
        print(c("[!] Dominio non specificato.", C.YELLOW))
        return False

    wl_default = default_wordlist() or ""
    wordlist = wordlist or ask("Wordlist", wl_default)
    if not wordlist or not Path(wordlist).is_file():
        print(c(f"[!] Wordlist non trovata: {wordlist}", C.RED))
        return False

    ffuf_url = state.web_url or f"http://{state.target}"
    safe_name = domain.replace(".", "_")
    out_json = state.path / f"ffuf_{safe_name}.json"
    out_log = state.path / f"ffuf_{safe_name}.log"

    if mode is None:
        print(c("Modalità ffuf:", C.CYAN))
        print(c(f"  1) vhost su {ffuf_url} (Host: FUZZ.{domain})", C.BOLD))
        print(c(f"  2) DNS diretto (http://FUZZ.{domain})", C.BOLD))
        choice = ask("Scegli modalità", "1")
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
    print(c(f"[+] Avvio ffuf su dominio: {domain}", C.GREEN, C.BOLD))
    print_cmd(cmd)
    print()

    with out_log.open("w", encoding="utf-8") as log:
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        log.write(proc.stdout)
        print(proc.stdout, end="")

    print()
    show_results(out_json, out_log, domain)
    print(c(f"[+] Output: {out_json}", C.GREEN))
    print(c(f"[+] Log: {out_log}", C.GREEN))
    state.mark_task("ffuf")
    return proc.returncode == 0
