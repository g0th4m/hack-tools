"""Clean up generated scan artifacts for a target."""

from __future__ import annotations

import shutil

from oscp_scan import hosts
from oscp_scan.state import ScanState
from oscp_scan.ui import C, ask_yes_no, c


def run_cleanup(state: ScanState) -> ScanState:
    target = state.target
    outdir = state.path

    print(c(f"[+] Target: {target}", C.GREEN, C.BOLD))
    print(c(f"[+] Output directory: {outdir}", C.BLUE))

    if outdir.exists():
        files = [p for p in outdir.rglob("*") if p.is_file()]
        print(c(f"[+] Files to delete: {len(files)}", C.YELLOW))
        for path in sorted(files):
            print(c(f"    {path}", C.BLUE))
    else:
        print(c("[!] Output directory does not exist.", C.YELLOW))

    print()
    if not ask_yes_no(f"Delete all generated files for {target}?", default=False):
        print(c("[!] Cleanup cancelled.", C.YELLOW))
        return state

    if outdir.exists():
        shutil.rmtree(outdir)
        print(c(f"[+] Removed {outdir}", C.GREEN))

    if state.is_done("hosts_updated"):
        if ask_yes_no(f"Remove /etc/hosts entry for {target}?", default=True):
            if hosts.remove_hosts_entry(target):
                print(c("[+] /etc/hosts entry removed.", C.GREEN))
            else:
                print(c("[!] No hack-tools /etc/hosts entry found for this target.", C.YELLOW))

    fresh = ScanState.new(target)
    print(c(f"[+] Fresh scan state created for {target}.", C.GREEN))
    return fresh
