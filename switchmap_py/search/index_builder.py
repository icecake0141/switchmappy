from __future__ import annotations

import json
from pathlib import Path


def load_index(output_dir: Path) -> dict:
    index_path = output_dir / "search" / "index.json"
    if not index_path.exists():
        return {}
    return json.loads(index_path.read_text())
