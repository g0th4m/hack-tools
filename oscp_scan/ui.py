"""Terminal UI helpers."""

from __future__ import annotations

import sys


class C:
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN = "\033[36m"
    BOLD = "\033[1m"
    RESET = "\033[0m"


def supports_color() -> bool:
    return sys.stdout.isatty()


def c(text: str, *styles: str) -> str:
    if not supports_color():
        return text
    prefix = "".join(styles)
    return f"{prefix}{text}{C.RESET}"


def print_cmd(cmd: list[str]) -> None:
    print(c("Command:", C.CYAN, C.BOLD), c(" ".join(cmd), C.BLUE))


def ask(prompt: str, default: str = "") -> str:
    suffix = f" [{default}]" if default else ""
    value = input(c(f"{prompt}{suffix}: ", C.YELLOW)).strip()
    return value or default


def ask_yes_no(prompt: str, *, default: bool = False) -> bool:
    hint = "Y/n" if default else "y/N"
    value = input(c(f"{prompt} [{hint}]: ", C.YELLOW)).strip().lower()
    if not value:
        return default
    return value in ("y", "yes")


def pause() -> None:
    input(c("\nPress Enter to continue...", C.CYAN))


def format_progress_bar(current: int, total: int, *, width: int = 28) -> str:
    if total <= 0:
        percent = 0.0
    else:
        percent = min(100.0, (current / total) * 100.0)
    filled = int(width * percent / 100.0)
    bar = "█" * filled + "░" * (width - filled)
    return f"[{bar}] {percent:5.1f}% ({current:,}/{total:,})"


class LiveProgress:
    """Single-line progress display for long-running tools."""

    def __init__(self, label: str = "FFuf") -> None:
        self.label = label
        self._last_len = 0

    def update(
        self,
        current: int,
        total: int,
        *,
        rate: int = 0,
        errors: int = 0,
        hits: int = 0,
    ) -> None:
        bar = format_progress_bar(current, total)
        extras = []
        if rate:
            extras.append(f"{rate} req/s")
        if errors:
            extras.append(f"errors {errors}")
        if hits:
            extras.append(f"hits {hits}")
        suffix = f" | {' | '.join(extras)}" if extras else ""
        line = c(f"{self.label}: {bar}{suffix}", C.CYAN, C.BOLD)
        padding = max(self._last_len - len(line), 0)
        sys.stderr.write(f"\r\033[2K{line}{' ' * padding}")
        sys.stderr.flush()
        self._last_len = len(line)

    def clear(self) -> None:
        sys.stderr.write("\r\033[2K")
        sys.stderr.flush()
        self._last_len = 0

    def finish(self, message: str = "") -> None:
        self.clear()
        if message:
            print(message)

