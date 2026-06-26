"""Interactive CLI menu."""

from __future__ import annotations

import sys
from pathlib import Path

from oscp_scan.state import TASK_LABELS, ScanState
from oscp_scan.tasks import cleanup, feroxbuster, ffuf, lft, nmap, pipeline
from oscp_scan.ui import C, ask, ask_yes_no, c, pause

MENU_ITEMS: list[tuple[str, str, tuple[str, ...]]] = [
    ("1", "Full TCP scan (-p-)", ("full_tcp",)),
    ("2", "Detail scan (-sCV)", ("detail_tcp",)),
    ("3", "UDP top-100 (foreground)", ("udp",)),
    ("4", "UDP top-100 (background)", ("udp_bg_started", "udp")),
    ("5", "Extract domain + update /etc/hosts", ("domain_extracted",)),
    ("6", "FFuf subdomains", ("ffuf",)),
    ("7", "Full pipeline", ("pipeline",)),
    ("11", "Feroxbuster directories", ("feroxbuster",)),
    ("12", "LFT traceroute", ("lft",)),
    ("8", "Show files & command history", ()),
    ("9", "Change target", ()),
    ("10", "Clean up target files", ()),
    ("0", "Exit", ()),
]


def _banner() -> None:
    print()
    print(c("╔══════════════════════════════════════════╗", C.CYAN, C.BOLD))
    print(c("║         hack-tools · OSCP Scanner        ║", C.CYAN, C.BOLD))
    print(c("╚══════════════════════════════════════════╝", C.CYAN, C.BOLD))
    print()


def _task_icon(state: ScanState, tasks: tuple[str, ...]) -> str:
    if not tasks:
        return "  "
    if state.is_done(*tasks):
        return c("✓", C.GREEN, C.BOLD)
    return c("○", C.YELLOW)


def _progress_panel(state: ScanState) -> None:
    done, total = state.done_count()
    bar_width = 20
    filled = int(bar_width * done / total) if total else 0
    bar = c("█" * filled, C.GREEN) + c("░" * (bar_width - filled), C.YELLOW)

    print(c("Progress", C.BOLD), f"[{bar}] {done}/{total}")
    for task_id in (
        "full_tcp", "detail_tcp", "udp", "domain_extracted", "hosts_updated", "ffuf", "feroxbuster", "lft",
    ):
        label = TASK_LABELS.get(task_id, task_id)
        if task_id == "udp" and state.is_done("udp_bg_started") and not state.is_done("udp"):
            label += " (running in background)"
        if state.is_done(task_id) or (task_id == "udp" and state.is_done("udp_bg_started")):
            when = state.task_history.get(task_id) or state.task_history.get("udp_bg_started", "")
            stamp = c(f" @ {when}", C.CYAN) if when else ""
            cmd = state.task_commands.get(task_id) or state.task_commands.get("udp_bg_started", "")
            print(c("  ✓", C.GREEN), label + stamp)
            if cmd:
                print(c(f"      $ {cmd}", C.BLUE))
        else:
            print(c("  ○", C.YELLOW), c(label, C.YELLOW))
    print()


def _status_line(state: ScanState) -> None:
    tcp = ",".join(str(p) for p in state.ports_tcp) or "-"
    udp = ",".join(str(p) for p in state.ports_udp) or "-"
    domain = state.detected_domain or "-"
    print(c(f"Target: {state.target}", C.GREEN, C.BOLD))
    print(c(f"Output: {state.outdir}", C.BLUE))
    print(c(f"Domain: {domain}  |  TCP: {tcp}  |  UDP: {udp}", C.CYAN))
    print()
    _progress_panel(state)


def _show_files(state: ScanState) -> None:
    print(c("[+] Generated files:", C.GREEN))
    if state.path.exists():
        for path in sorted(state.path.rglob("*")):
            if path.is_file():
                print(c(f"    {path}", C.BLUE))
    else:
        print(c("    (none)", C.YELLOW))

    print()
    print(c("[+] Command history:", C.GREEN))
    if not state.command_log:
        print(c("    (none)", C.YELLOW))
        return

    for entry in state.command_log:
        ok = entry.get("success") == "yes"
        status = c("OK", C.GREEN) if ok else c("FAIL", C.RED)
        label = TASK_LABELS.get(entry["task"], entry["task"])
        print(c(f"    [{status}] {label} @ {entry['at']}", C.CYAN))
        print(c(f"         {entry['command']}", C.BLUE))


def _pick_existing_scan() -> ScanState | None:
    scans = ScanState.find_existing()
    if not scans:
        print(c("[!] No existing scans in the current directory.", C.YELLOW))
        return None

    print(c("[+] Existing scans:", C.GREEN))
    for i, scan in enumerate(scans, 1):
        domain = scan.detected_domain or "-"
        tcp = ",".join(str(p) for p in scan.ports_tcp) or "-"
        done, total = scan.done_count()
        print(c(f"  {i}) {scan.target}  domain={domain}  tcp={tcp}  progress={done}/{total}", C.BLUE))

    choice = ask("Select number")
    if not choice.isdigit() or not (1 <= int(choice) <= len(scans)):
        print(c("[!] Invalid selection.", C.RED))
        return None
    return scans[int(choice) - 1]


def _pick_target(target: str | None = None) -> ScanState | None:
    if target:
        outdir = Path(f"oscp_scan_{target}")
        return ScanState.load(outdir) if outdir.exists() else ScanState.new(target)

    print()
    print(c("  1) New target", C.BOLD))
    print(c("  2) Load existing scan", C.BOLD))
    print()
    mode = ask("Choice", "1")
    if mode == "2":
        return _pick_existing_scan()
    target = ask("Enter target IP")
    if not target:
        print(c("[!] Invalid IP.", C.RED))
        return None
    state = ScanState.new(target)
    print(c(f"[+] New scan: {state.outdir}", C.GREEN))
    return state


def _parse_choices(raw: str) -> list[str]:
    return [part.strip() for part in raw.split(",") if part.strip()]


def _run_action(state: ScanState, choice: str, actions: dict[str, object]) -> ScanState | None:
    """Run one menu action. Returns None to exit, or updated state."""
    if choice == "0":
        print(c("Bye.", C.GREEN))
        return None

    if choice == "9":
        new_state = _pick_target()
        return new_state if new_state else state

    if choice == "10":
        print()
        print(c("── Clean up target files ──", C.YELLOW, C.BOLD))
        try:
            return cleanup.run_cleanup(state)
        except KeyboardInterrupt:
            print(c("\n[!] Interrupted.", C.YELLOW))
            return state

    if choice not in actions:
        print(c(f"[!] Invalid choice: {choice}", C.RED))
        return state

    label = next(item[1] for item in MENU_ITEMS if item[0] == choice)
    print()
    print(c(f"── {label} ──", C.YELLOW, C.BOLD))
    try:
        actions[choice]()
        return ScanState.load(state.outdir)
    except KeyboardInterrupt:
        print(c("\n[!] Interrupted.", C.YELLOW))
        return state


def run_menu(state: ScanState) -> ScanState | None:
    actions = {
        "1": lambda: nmap.run_full_tcp(state),
        "2": lambda: nmap.run_detail_tcp(state),
        "3": lambda: nmap.run_udp(state, background=False),
        "4": lambda: nmap.run_udp(state, background=True),
        "5": lambda: nmap.update_domain_from_nmap(state, offer_hosts=True) or True,
        "6": lambda: ffuf.run_ffuf(state),
        "11": lambda: feroxbuster.run_feroxbuster(state),
        "12": lambda: lft.run_lft_trace(state),
        "7": lambda: pipeline.run_pipeline(state) or True,
        "8": lambda: _show_files(state) or True,
    }

    while True:
        _banner()
        _status_line(state)

        for key, label, task_ids in MENU_ITEMS:
            if key in ("0", "8", "9", "10"):
                print(c(f"  {key}) {label}", C.BOLD))
            else:
                icon = _task_icon(state, task_ids)
                done_tag = c(" [done]", C.GREEN) if task_ids and state.is_done(*task_ids) else ""
                print(f"  {key}) {icon} {c(label, C.BOLD)}{done_tag}")

        print()
        print(c("  Tip: run multiple tasks with commas, e.g. 1,2,5", C.CYAN))
        print()
        choice = ask("Choice", "7")
        choices = _parse_choices(choice)

        if not choices:
            print(c("[!] Invalid choice.", C.RED))
            pause()
            continue

        if len(choices) == 1:
            result = _run_action(state, choices[0], actions)
            if result is None:
                return None
            state = result
            pause()
            continue

        if "0" in choices:
            print(c("Bye.", C.GREEN))
            return None

        print()
        print(c(f"[+] Running {len(choices)} task(s): {', '.join(choices)}", C.GREEN, C.BOLD))
        for i, item in enumerate(choices, 1):
            print(c(f"\n── Batch {i}/{len(choices)}: option {item} ──", C.MAGENTA, C.BOLD))
            result = _run_action(state, item, actions)
            if result is None:
                return None
            state = result

        pause()
        continue


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
