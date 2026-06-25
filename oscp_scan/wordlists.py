"""Discover and select wordlists on the system (Kali / SecLists)."""

from __future__ import annotations

import subprocess
from dataclasses import dataclass
from pathlib import Path

from oscp_scan.ui import C, ask, c

SEARCH_ROOTS = (
    Path("/usr/share/seclists"),
    Path("/usr/share/wordlists"),
    Path("/usr/share/wordlists/seclists"),
    Path("/opt/seclists"),
)

WORDLIST_EXTENSIONS = {".txt", ".lst"}


@dataclass(frozen=True)
class WordlistEntry:
    path: Path
    lines: int
    size_bytes: int

    @property
    def display_name(self) -> str:
        for marker in ("seclists", "wordlists"):
            if marker in self.path.parts:
                idx = self.path.parts.index(marker)
                return str(Path(*self.path.parts[idx + 1:]))
        return str(self.path)


def _format_count(value: int) -> str:
    return f"{value:,}"


def _format_size(size: int) -> str:
    if size < 1024:
        return f"{size}B"
    if size < 1024 * 1024:
        return f"{size / 1024:.1f}KB"
    return f"{size / (1024 * 1024):.1f}MB"


def _count_lines_batch(files: list[Path]) -> dict[Path, int]:
    counts: dict[Path, int] = {}
    chunk_size = 150

    for i in range(0, len(files), chunk_size):
        chunk = files[i : i + chunk_size]
        result = subprocess.run(
            ["wc", "-l", *[str(p) for p in chunk]],
            capture_output=True,
            text=True,
            errors="replace",
        )
        if result.returncode != 0:
            for path in chunk:
                counts[path] = _count_lines_python(path)
            continue

        for line in result.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            parts = line.split()
            if len(parts) < 2:
                continue
            try:
                line_count = int(parts[0])
            except ValueError:
                continue
            path_str = parts[-1]
            if path_str == "total":
                continue
            counts[Path(path_str)] = line_count

        for path in chunk:
            counts.setdefault(path, _count_lines_python(path))

    return counts


def _count_lines_python(path: Path) -> int:
    try:
        with path.open("rb") as handle:
            return sum(1 for _ in handle)
    except OSError:
        return 0


def _find_wordlist_files(root: Path) -> list[Path]:
    result = subprocess.run(
        [
            "find", str(root), "-type", "f", "(",
            "-iname", "*.txt", "-o", "-iname", "*.lst",
            ")",
        ],
        capture_output=True,
        text=True,
        errors="replace",
    )
    if result.returncode != 0:
        return sorted(
            p for p in root.rglob("*")
            if p.is_file() and p.suffix.lower() in WORDLIST_EXTENSIONS
        )

    files = [Path(line) for line in result.stdout.splitlines() if line.strip()]
    return sorted(set(files))


def discover_wordlists(
    *,
    roots: tuple[Path, ...] = SEARCH_ROOTS,
    name_filter: str | None = None,
) -> list[WordlistEntry]:
    seen: set[Path] = set()
    files: list[Path] = []

    for root in roots:
        if not root.is_dir():
            continue
        for path in _find_wordlist_files(root):
            resolved = path.resolve()
            if resolved in seen:
                continue
            seen.add(resolved)
            files.append(resolved)

    if name_filter:
        needle = name_filter.lower()
        files = [p for p in files if needle in str(p).lower()]

    if not files:
        return []

    line_counts = _count_lines_batch(files)
    entries: list[WordlistEntry] = []
    for path in files:
        try:
            size = path.stat().st_size
        except OSError:
            size = 0
        entries.append(WordlistEntry(path=path, lines=line_counts.get(path, 0), size_bytes=size))

    entries.sort(key=lambda e: (e.path.parts[0] if e.path.parts else "", e.display_name.lower()))
    return entries


def _default_filter() -> str:
    return "dns"


def count_wordlist_lines(path: str | Path) -> int:
    path = Path(path)
    if not path.is_file():
        return 0
    result = subprocess.run(
        ["wc", "-l", str(path)],
        capture_output=True,
        text=True,
        errors="replace",
    )
    if result.returncode == 0:
        try:
            return int(result.stdout.strip().split()[0])
        except (IndexError, ValueError):
            pass
    try:
        with path.open("rb") as handle:
            return sum(1 for _ in handle)
    except OSError:
        return 0


def pick_wordlist(*, default_path: str | None = None) -> tuple[str, int] | None:
    print()
    print(c("[+] Scanning wordlists (SecLists / wordlists)...", C.YELLOW, C.BOLD))

    name_filter = ask("Filter paths (empty=all, dns=subdomain lists)", _default_filter())
    if name_filter.lower() in ("all", "*"):
        name_filter = None

    entries = discover_wordlists(name_filter=name_filter or None)
    if not entries:
        print(c("[!] No wordlists found on this system.", C.RED))
        custom = ask("Enter wordlist path manually")
        if custom and Path(custom).is_file():
            return custom, count_wordlist_lines(custom)
        return None

    print(c(f"[+] Found {len(entries)} wordlist file(s)", C.GREEN))
    print()
    print(c(f"{'#':>4}  {'Lines':>10}  {'Size':>8}  Path", C.CYAN, C.BOLD))
    print(c("─" * 72, C.CYAN))

    default_index: int | None = None
    if default_path:
        default_resolved = Path(default_path).resolve()
        for i, entry in enumerate(entries, 1):
            if entry.path == default_resolved:
                default_index = i
                break

    for i, entry in enumerate(entries, 1):
        marker = ""
        if default_index == i:
            marker = c(" *", C.GREEN)
        print(
            c(f"{i:>4}", C.BLUE),
            c(f"{_format_count(entry.lines):>10}", C.MAGENTA),
            c(f"{_format_size(entry.size_bytes):>8}", C.CYAN),
            entry.display_name + marker,
        )

    print()
    default_hint = str(default_index) if default_index else "1"
    choice = ask("Select number, full path, or type 'all' to rescan without filter", default_hint)

    if choice.isdigit():
        index = int(choice)
        if 1 <= index <= len(entries):
            selected = entries[index - 1]
            print(c(f"[+] Selected: {selected.path}", C.GREEN))
            return str(selected.path), selected.lines
        print(c("[!] Invalid number.", C.RED))
        return None

    if choice and Path(choice).is_file():
        return choice, count_wordlist_lines(choice)

    print(c(f"[!] Wordlist not found: {choice}", C.RED))
    return None
