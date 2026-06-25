"""Persistent scan state."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


@dataclass
class ScanState:
    target: str
    outdir: str = ""
    ports_tcp: list[int] = field(default_factory=list)
    ports_udp: list[int] = field(default_factory=list)
    detected_domain: str | None = None
    all_domains: list[str] = field(default_factory=list)
    web_url: str | None = None
    tasks_done: list[str] = field(default_factory=list)
    updated_at: str = ""

    def __post_init__(self) -> None:
        if not self.outdir:
            self.outdir = f"oscp_scan_{self.target}"

    @property
    def path(self) -> Path:
        return Path(self.outdir)

    @property
    def state_file(self) -> Path:
        return self.path / "state.json"

    @property
    def full_prefix(self) -> Path:
        return self.path / "full"

    @property
    def detail_prefix(self) -> Path:
        return self.path / "detail"

    @property
    def udp_prefix(self) -> Path:
        return self.path / "udp"

    def ensure_outdir(self) -> None:
        self.path.mkdir(parents=True, exist_ok=True)

    def mark_task(self, task: str) -> None:
        if task not in self.tasks_done:
            self.tasks_done.append(task)
        self.updated_at = datetime.now(timezone.utc).isoformat()
        self.save()

    def save(self) -> None:
        self.ensure_outdir()
        self.updated_at = datetime.now(timezone.utc).isoformat()
        self.state_file.write_text(
            json.dumps(asdict(self), indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        if self.detected_domain:
            (self.path / "detected_domain.txt").write_text(
                self.detected_domain + "\n", encoding="utf-8"
            )

    @classmethod
    def load(cls, outdir: str | Path) -> ScanState:
        outdir = Path(outdir)
        state_file = outdir / "state.json"
        if state_file.exists():
            data: dict[str, Any] = json.loads(state_file.read_text(encoding="utf-8"))
            return cls(**data)

        target = outdir.name.removeprefix("oscp_scan_")
        state = cls(target=target, outdir=str(outdir))
        state.save()
        return state

    @classmethod
    def new(cls, target: str) -> ScanState:
        state = cls(target=target)
        state.ensure_outdir()
        state.save()
        return state

    @classmethod
    def find_existing(cls, base_dir: Path | None = None) -> list[ScanState]:
        base = base_dir or Path.cwd()
        scans: list[ScanState] = []
        for path in sorted(base.glob("oscp_scan_*")):
            if path.is_dir():
                try:
                    scans.append(cls.load(path))
                except (json.JSONDecodeError, TypeError):
                    continue
        return scans
