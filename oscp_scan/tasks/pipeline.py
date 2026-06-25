"""Full scan pipeline."""

from __future__ import annotations

from oscp_scan.state import ScanState
from oscp_scan.tasks import ffuf, nmap
from oscp_scan.ui import ask_yes_no


def run_pipeline(state: ScanState) -> None:
    if not nmap.run_full_tcp(state):
        return

    udp_bg = ask_yes_no("Run UDP top-100 in background while continuing?", default=False)
    if udp_bg:
        nmap.run_udp(state, background=True)

    if state.ports_tcp:
        if not nmap.run_detail_tcp(state):
            return
    else:
        nmap.update_domain_from_nmap(state)

    if state.detected_domain:
        if ask_yes_no(f"Run ffuf on subdomains of {state.detected_domain}?", default=True):
            ffuf.run_ffuf(state, domain=state.detected_domain)
    elif ask_yes_no("No domain detected. Run ffuf manually?", default=False):
        ffuf.run_ffuf(state)

    if udp_bg and not state.ports_udp:
        gnmap = state.path / "udp.gnmap"
        if gnmap.exists():
            from oscp_scan.parsers import nmap as nmap_parser
            state.ports_udp = nmap_parser.extract_open_ports(gnmap, "udp")
            state.save()

    state.mark_task("pipeline")
