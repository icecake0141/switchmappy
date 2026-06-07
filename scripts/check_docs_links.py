# Copyright 2026 OpenAI
# SPDX-License-Identifier: Apache-2.0
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# This file was created or modified with the assistance of an AI (Large Language Model).
# Review required for correctness, security, and licensing.

from __future__ import annotations

import re
import sys
from pathlib import Path
from urllib.parse import unquote, urlparse

LINK_RE = re.compile(r"(?<!!)\[[^\]]+\]\(([^)]+)\)")
SKIP_SCHEMES = {"http", "https", "mailto"}


def _target_path(markdown_path: Path, raw_target: str) -> Path | None:
    target = raw_target.strip().split("#", maxsplit=1)[0]
    if not target:
        return None
    parsed = urlparse(target)
    if parsed.scheme in SKIP_SCHEMES or parsed.netloc:
        return None
    return (markdown_path.parent / unquote(parsed.path)).resolve()


def main() -> int:
    root = Path.cwd().resolve()
    failures: list[str] = []
    for markdown_path in sorted(root.rglob("*.md")):
        if any(part.startswith(".") for part in markdown_path.relative_to(root).parts):
            continue
        text = markdown_path.read_text(encoding="utf-8")
        for match in LINK_RE.finditer(text):
            target = _target_path(markdown_path, match.group(1))
            if target is None:
                continue
            try:
                target.relative_to(root)
            except ValueError:
                failures.append(f"{markdown_path.relative_to(root)} links outside repository: {match.group(1)}")
                continue
            if not target.exists():
                failures.append(f"{markdown_path.relative_to(root)} missing link target: {match.group(1)}")
    if failures:
        print("\n".join(failures), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
