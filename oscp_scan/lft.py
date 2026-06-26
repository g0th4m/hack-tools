"""LFT (Layer Four Traceroute) runner and standalone CLI."""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
from pathlib import Path

from oscp_scan.commands import cmd_to_string, confirm_command
from oscp_scan.ui import C, c, print_cmd

WEB_PORTS = (80, 443, 8080, 8443, 8000, 8888, 22, 21)


def default_port(open_ports: list[int] | None = None) -> int:
    for port in WEB_PORTS:
        if open_ports and port in open_ports:
            return port
    if open_ports:
        return open_ports[0]
    return 80


def build_lft_cmd(
    target: str,
    *,
    dport: int = 80,
    adaptive: bool = True,
    udp: bool = False,
    max_ttl: int | None = None,
) -> list[str]:
    cmd = ["lft"]
    if adaptive:
        cmd.append("-E")
    if udp:
        cmd.append("-u")
    else:
        cmd.extend(["-d", str(dport)])
    if max_ttl is not None:
        cmd.extend(["-H", str(max_ttl)])
    cmd.append(f"{target}:{dport}" if not udp else target)
    return cmd


def run_lft_streaming(cmd: list[str], log_file: Path | None = None) -> int:
    log_handle = log_file.open("w", encoding="utf-8") if log_file else None
    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            errors="replace",
        )
        assert proc.stdout is not None
        for line in proc.stdout:
            print(line, end="")
            if log_handle:
                log_handle.write(line)
                log_handle.flush()
        return proc.wait()
    finally:
        if log_handle:
            log_handle.close()


def run_lft(
    target: str,
    *,
    dport: int = 80,
    adaptive: bool = True,
    udp: bool = False,
    max_ttl: int | None = None,
    log_file: Path | None = None,
    confirm: bool = True,
) -> tuple[int, str | None]:
    if not shutil.which("lft"):
        print(c("[!] lft not found in PATH.", C.RED))
        return -1, None

    cmd = build_lft_cmd(
        target,
        dport=dport,
        adaptive=adaptive,
        udp=udp,
        max_ttl=max_ttl,
    )

    if confirm:
        confirmed = confirm_command(cmd)
        if confirmed is None:
            return -1, None
        cmd = confirmed

    print()
    print_cmd(cmd)
    if log_file:
        print(c(f"    Log: {log_file}", C.CYAN))
    print()

    returncode = run_lft_streaming(cmd, log_file)
    command_str = cmd_to_string(cmd)
    if returncode != 0:
        print(c(f"[!] lft exited with code {returncode}.", C.RED))
    elif log_file:
        print(c(f"[+] Log: {log_file}", C.GREEN))
    return returncode, command_str


def _parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Layer Four Traceroute (lft) with confirm-before-run.",
    )
    parser.add_argument("target", help="Target IP or hostname")
    parser.add_argument(
        "-p", "--port",
        type=int,
        default=80,
        help="Destination TCP port (default: 80)",
    )
    parser.add_argument(
        "-o", "--output",
        help="Save output to this log file",
    )
    parser.add_argument(
        "-u", "--udp",
        action="store_true",
        help="Use UDP probes instead of TCP",
    )
    parser.add_argument(
        "--no-adaptive",
        action="store_true",
        help="Disable LFT adaptive mode (-E)",
    )
    parser.add_argument(
        "--max-ttl",
        type=int,
        metavar="HOPS",
        help="Maximum TTL/hops (-H)",
    )
    parser.add_argument(
        "-y", "--yes",
        action="store_true",
        help="Run without confirmation prompt",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    log_file = Path(args.output) if args.output else None
    returncode, _ = run_lft(
        args.target,
        dport=args.port,
        adaptive=not args.no_adaptive,
        udp=args.udp,
        max_ttl=args.max_ttl,
        log_file=log_file,
        confirm=not args.yes,
    )
    return 0 if returncode == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
