from __future__ import annotations

import json
from pathlib import Path

from switchmap_py.model.mac import MacEntry


class MacListStore:
    def __init__(self, path: Path) -> None:
        self.path = path

    def load(self) -> list[MacEntry]:
        if not self.path.exists():
            return []
        payload = json.loads(self.path.read_text())
        return [MacEntry(**entry) for entry in payload]

    def save(self, entries: list[MacEntry]) -> None:
        payload = [entry.__dict__ for entry in entries]
        self.path.write_text(json.dumps(payload, indent=2, sort_keys=True))
