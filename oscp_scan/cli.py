"""Interactive CLI menu."""

from __future__ import annotations

import sys
from pathlib import Path

from oscp_scan.state import ScanState
from oscp_scan.tasks import ffuf, nmap, pipeline
from oscp_scan.ui import C, ask, ask_yes_no, c, pause


def _banner() -> None:
    print()
    print(c("╔══════════════════════════════════════════╗", C.CYAN, C.BOLD))
    print(c("║         hack-tools · OSCP Scanner        ║", C.CYAN, C.BOLD))
    print(c("╚══════════════════════════════════════════╝", C.CYAN, C.BOLD))
    print()


def _status_line(state: ScanState) -> None:
    tcp = ",".join(str(p) for p in state.ports_tcp) or "-"
    udp = ",".join(str(p) for p in state.ports_udp) or "-"
    domain = state.detected_domain or "-"
    done = ", ".join(state.tasks_done) or "-"
    print(c(f"Target: {state.target}", C.GREEN, C.BOLD))
    print(c(f"Output: {state.outdir}", C.BLUE))
    print(c(f"Dominio: {domain}  |  TCP: {tcp}  |  UDP: {udp}", C.CYAN))
    print(c(f"Task completati: {done}", C.CYAN))
    print()


def _show_files(state: ScanState) -> None:
    print(c("[+] File generati:", C.GREEN))
    if not state.path.exists():
        print(c("    (nessun file)", C.YELLOW))
        return
    for path in sorted(state.path.rglob("*")):
        if path.is_file():
            print(c(f"    {path}", C.BLUE))


def _pick_existing_scan() -> ScanState | None:
    scans = ScanState.find_existing()
    if not scans:
        print(c("[!] Nessuno scan esistente nella directory corrente.", C.YELLOW))
        return None

    print(c("[+] Scan esistenti:", C.GREEN))
    for i, scan in enumerate(scans, 1):
        domain = scan.detected_domain or "-"
        tcp = ",".join(str(p) for p in scan.ports_tcp) or "-"
        print(c(f"  {i}) {scan.target}  dominio={domain}  tcp={tcp}", C.BLUE))

    choice = ask("Seleziona numero")
    if not choice.isdigit() or not (1 <= int(choice) <= len(scans)):
        print(c("[!] Selezione non valida.", C.RED))
        return None
    return scans[int(choice) - 1]


def _pick_target(target: str | None = None) -> ScanState | None:
    if target:
        outdir = Path(f"oscp_scan_{target}")
        return ScanState.load(outdir) if outdir.exists() else ScanState.new(target)

    print()
    print(c("  1) Nuovo target", C.BOLD))
    print(c("  2) Carica scan esistente", C.BOLD))
    print()
    mode = ask("Scelta", "1")
    if mode == "2":
        return _pick_existing_scan()
    target = ask("Inserisci IP target")
    if not target:
        print(c("[!] IP non valido.", C.RED))
        return None
    state = ScanState.new(target)
    print(c(f"[+] Nuovo scan: {state.outdir}", C.GREEN))
    return state


def run_menu(state: ScanState) -> ScanState | None:
    actions = {
        "1": ("Full TCP scan (-p-)", lambda: nmap.run_full_tcp(state)),
        "2": ("Detail scan (-sCV)", lambda: nmap.run_detail_tcp(state)),
        "3": ("UDP top-100 (foreground)", lambda: nmap.run_udp(state, background=False)),
        "4": ("UDP top-100 (background)", lambda: nmap.run_udp(state, background=True)),
        "5": ("Estrai dominio da nmap + /etc/hosts", lambda: nmap.update_domain_from_nmap(state, offer_hosts=True) or True),
        "6": ("FFuf subdomains", lambda: ffuf.run_ffuf(state)),
        "7": ("Pipeline completa", lambda: pipeline.run_pipeline(state) or True),
        "8": ("Mostra file generati", lambda: _show_files(state) or True),
    }

    while True:
        _banner()
        _status_line(state)
        print(c("  1) Full TCP scan (-p-)", C.BOLD))
        print(c("  2) Detail scan (-sCV)", C.BOLD))
        print(c("  3) UDP top-100 (foreground)", C.BOLD))
        print(c("  4) UDP top-100 (background)", C.BOLD))
        print(c("  5) Estrai dominio da nmap + /etc/hosts", C.BOLD))
        print(c("  6) FFuf subdomains", C.BOLD))
        print(c("  7) Pipeline completa", C.BOLD))
        print(c("  8) Mostra file generati", C.BOLD))
        print(c("  9) Cambia target", C.BOLD))
        print(c("  0) Esci", C.BOLD))
        print()

        choice = ask("Scelta", "7")
        if choice == "0":
            print(c("Bye.", C.GREEN))
            return None
        if choice == "9":
            new_state = _pick_target()
            if new_state:
                return new_state
            pause()
            continue
        if choice in actions:
            label, fn = actions[choice]
            print()
            print(c(f"── {label} ──", C.YELLOW, C.BOLD))
            try:
                fn()
            except KeyboardInterrupt:
                print(c("\n[!] Interrotto.", C.YELLOW))
            pause()
            continue
        print(c("[!] Scelta non valida.", C.RED))
        pause()


def main(argv: list[str] | None = None) -> None:
    argv = argv if argv is not None else sys.argv[1:]
    target = argv[0] if argv else None
    state = _pick_target(target)
    if state is None:
        return

    while state is not None:
        state = run_menu(state)


if __name__ == "__main__":
    main()
