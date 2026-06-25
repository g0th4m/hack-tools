"""Parse nmap output files."""

from __future__ import annotations

import re
from pathlib import Path

DOMAIN_RE = re.compile(
    r"^[a-zA-Z0-9]([a-zA-Z0-9.-]*[a-zA-Z0-9])?\.[a-zA-Z]{2,}$"
)
LAB_TLD_RE = re.compile(r"\.(htb|htb\.cloud|local|corp|internal)$", re.I)


def extract_open_ports(gnmap_file: Path, proto: str = "tcp") -> list[int]:
    if not gnmap_file.exists():
        return []

    ports: list[int] = []
    token = f"/open/{proto}"
    for line in gnmap_file.read_text(encoding="utf-8", errors="replace").splitlines():
        if "Ports:" not in line:
            continue
        for part in line.split():
            if token in part:
                port_str = part.split("/")[0]
                if port_str.isdigit():
                    ports.append(int(port_str))
    return sorted(set(ports))


def extract_domains_from_nmap(nmap_file: Path, target_ip: str) -> list[str]:
    if not nmap_file.exists():
        return []

    text = nmap_file.read_text(encoding="utf-8", errors="replace")
    found: set[str] = set()

    for match in re.finditer(r"Nmap scan report for ([^( \n]+)", text):
        host = match.group(1).strip().lower()
        if host != target_ip and DOMAIN_RE.match(host):
            found.add(host)

    for match in re.finditer(r"commonName[=: ]\s*([^,/|\n]+)", text, re.I):
        host = match.group(1).strip().lower()
        if host != target_ip and DOMAIN_RE.match(host):
            found.add(host)

    for match in re.finditer(r"DNS:([^,\n|]+)", text, re.I):
        host = match.group(1).strip().lower()
        if host != target_ip and DOMAIN_RE.match(host):
            found.add(host)

    for match in re.finditer(r"https?://([^/\"<>\s:]+)", text, re.I):
        host = match.group(1).strip().lower()
        if host not in ("localhost", target_ip) and DOMAIN_RE.match(host):
            found.add(host)

    return sorted(found)


def pick_base_domain(domains: list[str]) -> str | None:
    if not domains:
        return None

    lab_domains = [d for d in domains if LAB_TLD_RE.search(d)]
    pool = lab_domains or domains
    return min(pool, key=len)


def get_domain_sources(nmap_file: Path, domain: str) -> list[str]:
    if not nmap_file.exists():
        return []

    text = nmap_file.read_text(encoding="utf-8", errors="replace")
    sources: list[str] = []

    if re.search(rf"Nmap scan report for {re.escape(domain)}[ (]", text):
        sources.append("scan report")
    if re.search(rf"commonName[=: ].*{re.escape(domain)}", text, re.I):
        sources.append("SSL certificate")
    if re.search(rf"DNS:{re.escape(domain)}", text, re.I):
        sources.append("SSL SAN")
    if re.search(rf"https?://{re.escape(domain)}", text, re.I):
        sources.append("HTTP redirect")

    return sources


def extract_web_endpoint(gnmap_file: Path, target_ip: str) -> str | None:
    ports = extract_open_ports(gnmap_file, "tcp")
    if not ports:
        return None

    priority = [
        (443, "https"),
        (80, "http"),
        (8080, "http"),
        (8443, "https"),
    ]
    for port, scheme in priority:
        if port in ports:
            return f"{scheme}://{target_ip}:{port}"

    return f"http://{target_ip}:{ports[0]}"
