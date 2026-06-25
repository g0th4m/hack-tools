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
    return value in ("y", "yes", "s", "si")


def pause() -> None:
    input(c("\nPremi Invio per continuare...", C.CYAN))
