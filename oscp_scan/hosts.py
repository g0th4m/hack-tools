"""Manage /etc/hosts entries for discovered domains."""

from __future__ import annotations

import subprocess
import tempfile
from pathlib import Path

from oscp_scan.state import ScanState
from oscp_scan.ui import C, ask_yes_no, c

HOSTS_PATH = Path("/etc/hosts")
MARKER_PREFIX = "# hack-tools:"


def read_hosts() -> str:
    if not HOSTS_PATH.is_file():
        return ""
    return HOSTS_PATH.read_text(encoding="utf-8")


def preview_hosts(*, title: str = "/etc/hosts") -> None:
    print()
    print(c(f"[+] Preview {title}", C.GREEN, C.BOLD))
    print(c("─" * 50, C.CYAN))
    try:
        content = read_hosts()
    except PermissionError:
        print(c("[!] Impossibile leggere /etc/hosts.", C.RED))
        return

    if not content.strip():
        print(c("(file vuoto o non leggibile)", C.YELLOW))
    else:
        for i, line in enumerate(content.splitlines(), 1):
            styled = line
            if line.strip().startswith(MARKER_PREFIX):
                styled = c(line, C.CYAN, C.BOLD)
            elif not line.strip().startswith("#") and line.strip():
                styled = c(line, C.BLUE)
            print(f"{c(f'{i:>4}', C.CYAN)}  {styled}")
    print(c("─" * 50, C.CYAN))
    print()


def _remove_hacktools_block(lines: list[str], ip: str) -> list[str]:
    marker = f"{MARKER_PREFIX} {ip}"
    result: list[str] = []
    i = 0
    while i < len(lines):
        if lines[i].strip() == marker:
            i += 2
            continue
        result.append(lines[i])
        i += 1
    return result


def build_hosts_content(current: str, ip: str, domains: list[str]) -> str:
    domains = sorted(set(d.strip().lower() for d in domains if d.strip()))
    if not domains:
        return current

    lines = current.splitlines()
    while lines and not lines[-1].strip():
        lines.pop()

    lines = _remove_hacktools_block(lines, ip)
    marker = f"{MARKER_PREFIX} {ip}"
    entry = f"{ip} {' '.join(domains)}"

    if lines:
        lines.append("")
    lines.extend([marker, entry])

    return "\n".join(lines) + "\n"


def _write_hosts(content: str) -> bool:
    try:
        HOSTS_PATH.write_text(content, encoding="utf-8")
        print(c("[+] /etc/hosts aggiornato.", C.GREEN))
        return True
    except PermissionError:
        pass

    print(c("[!] Servono permessi root per scrivere /etc/hosts.", C.YELLOW))
    if not ask_yes_no("Usare sudo?", default=True):
        return False

    with tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False, suffix=".hosts") as tmp:
        tmp.write(content)
        tmp_path = tmp.name

    result = subprocess.run(
        ["sudo", "cp", tmp_path, str(HOSTS_PATH)],
        capture_output=True,
        text=True,
    )
    Path(tmp_path).unlink(missing_ok=True)

    if result.returncode != 0:
        err = result.stderr.strip() or "errore sconosciuto"
        print(c(f"[!] Scrittura fallita: {err}", C.RED))
        return False

    print(c("[+] /etc/hosts aggiornato con sudo.", C.GREEN))
    return True


def offer_hosts_update(state: ScanState) -> None:
    preview_hosts()

    domains = list(state.all_domains)
    if not domains and state.detected_domain:
        domains = [state.detected_domain]

    if not domains:
        print(c("[!] Nessun dominio da aggiungere a /etc/hosts.", C.YELLOW))
        return

    new_content = build_hosts_content(read_hosts(), state.target, domains)
    marker = f"{MARKER_PREFIX} {state.target}"
    entry_line = f"{state.target} {' '.join(sorted(set(domains)))}"

    print(c("[+] Voci proposte per /etc/hosts:", C.GREEN, C.BOLD))
    print(c(f"    {marker}", C.CYAN))
    print(c(f"    {entry_line}", C.MAGENTA, C.BOLD))
    print()

    if not ask_yes_no(f"Aggiungere {len(domains)} dominio/i per {state.target}?", default=True):
        print(c("[!] /etc/hosts non modificato.", C.YELLOW))
        return

    if _write_hosts(new_content):
        state.mark_task("hosts_updated")
        preview_hosts(title="/etc/hosts (aggiornato)")
