"""Run feroxbuster with streamed output and a simple progress bar."""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

from oscp_scan.ui import C, LiveProgress, c

PROGRESS_RE = re.compile(r"(\d+)\s*/\s*(\d+)")
HIT_RE = re.compile(r"^(\d{3})\s+\S+\s+.*?(https?://\S+)", re.I)
URL_RE = re.compile(r"(https?://\S+)")


def _update_progress(progress: LiveProgress, line: str, hits: int) -> None:
    match = PROGRESS_RE.search(line)
    if match:
        current, total = int(match.group(1)), int(match.group(2))
        if total > 0:
            progress.update(current, total, hits=hits)


def run_feroxbuster_streaming(
    cmd: list[str],
    log_file: Path,
    *,
    wordlist_lines: int = 0,
) -> int:
    progress = LiveProgress("Feroxbuster")
    hits = 0

    with log_file.open("w", encoding="utf-8") as log_handle:
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
            log_handle.write(line)
            log_handle.flush()
            stripped = line.rstrip()
            if not stripped:
                continue

            _update_progress(progress, stripped, hits)

            hit_match = HIT_RE.search(stripped)
            if hit_match:
                hits += 1
                progress.clear()
                print(c(stripped, C.MAGENTA))
                continue

            if wordlist_lines > 0 and "%" not in stripped:
                # Feroxbuster prints many status lines; avoid flooding the terminal.
                if "Feroxbuster" in stripped or "ERROR" in stripped.upper():
                    progress.clear()
                    print(stripped)

        returncode = proc.wait()

    if wordlist_lines > 0:
        progress.update(wordlist_lines, wordlist_lines, hits=hits)
    progress.finish(c(f"[+] Feroxbuster completed ({hits} path(s) on screen)", C.GREEN))
    return returncode
