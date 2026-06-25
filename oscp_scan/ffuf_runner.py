"""Run ffuf with a live progress bar."""

from __future__ import annotations

import re
import subprocess
import threading
from pathlib import Path

from oscp_scan.ui import LiveProgress, c, C

PROGRESS_RE = re.compile(
    r"Progress:\s*\[(\d+)/(\d+)\].*?(\d+)\s*req/sec.*?Errors:\s*(\d+)",
)
PROGRESS_MINI_RE = re.compile(r"\[(\d+)%\]-\[(\d+)/(\d+)\]")
PROGRESS_PAIR_RE = re.compile(r"\[(\d+)/(\d+)\]")
HIT_RE = re.compile(r"\[Status:\s*(\d+)", re.I)


def _parse_progress(chunk: str) -> tuple[int, int, int, int] | None:
    match = PROGRESS_RE.search(chunk)
    if match:
        return int(match.group(1)), int(match.group(2)), int(match.group(3)), int(match.group(4))

    match = PROGRESS_MINI_RE.search(chunk)
    if match:
        percent, pos, total_jobs = int(match.group(1)), int(match.group(2)), int(match.group(3))
        current = int(percent * pos / 100) if total_jobs else 0
        return current, total_jobs or 100, 0, 0

    matches = PROGRESS_PAIR_RE.findall(chunk)
    if matches:
        current, total = int(matches[-1][0]), int(matches[-1][1])
        return current, total, 0, 0

    return None


def _stderr_reader(
    proc: subprocess.Popen[str],
    progress: LiveProgress,
    *,
    fallback_total: int,
    hits: list[int],
) -> None:
    if not proc.stderr:
        return

    buffer = ""
    while True:
        chunk = proc.stderr.read(512)
        if not chunk:
            break
        buffer += chunk
        parts = re.split(r"[\r\n]", buffer)
        buffer = parts[-1]
        for part in parts[:-1]:
            parsed = _parse_progress(part)
            if parsed:
                current, total, rate, errors = parsed
                if total <= 0 and fallback_total > 0:
                    total = fallback_total
                progress.update(current, total, rate=rate, errors=errors, hits=hits[0])

    if buffer.strip():
        parsed = _parse_progress(buffer)
        if parsed:
            current, total, rate, errors = parsed
            if total <= 0 and fallback_total > 0:
                total = fallback_total
            progress.update(current, total, rate=rate, errors=errors, hits=hits[0])


def _stdout_reader(
    proc: subprocess.Popen[str],
    log_handle,
    progress: LiveProgress,
    hits: list[int],
) -> None:
    if not proc.stdout:
        return
    for line in proc.stdout:
        log_handle.write(line)
        log_handle.flush()
        if HIT_RE.search(line) or "* FUZZ:" in line:
            hits[0] += 1
            progress.clear()
            print(c(line.rstrip(), C.MAGENTA))


def run_ffuf_with_progress(
    cmd: list[str],
    log_file: Path,
    *,
    wordlist_lines: int = 0,
) -> int:
    progress = LiveProgress("FFuf")
    hits = [0]

    with log_file.open("w", encoding="utf-8") as log_handle:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
            errors="replace",
        )

        stderr_thread = threading.Thread(
            target=_stderr_reader,
            args=(proc, progress),
            kwargs={"fallback_total": wordlist_lines, "hits": hits},
            daemon=True,
        )
        stdout_thread = threading.Thread(
            target=_stdout_reader,
            args=(proc, log_handle, progress),
            kwargs={"hits": hits},
            daemon=True,
        )
        stderr_thread.start()
        stdout_thread.start()

        stderr_thread.join()
        stdout_thread.join()
        returncode = proc.wait()

    total = wordlist_lines or hits[0] or 1
    progress.finish(c(f"[+] FFuf completed ({hits[0]} hit(s))", C.GREEN))
    return returncode
