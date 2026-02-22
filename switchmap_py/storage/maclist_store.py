# Copyright 2024
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

import json
import logging
from dataclasses import asdict
from pathlib import Path

from switchmap_py.model.mac import MacEntry

logger = logging.getLogger(__name__)


class MacListStore:
    def __init__(self, path: Path) -> None:
        self.path = path

    def load(self) -> list[MacEntry]:
        if not self.path.exists():
            return []
        payload = json.loads(self.path.read_text(encoding="utf-8"))
        entries: list[MacEntry] = []
        skipped: list[str] = []
        for index, entry in enumerate(payload):
            try:
                entries.append(MacEntry(**entry))
            except (TypeError, ValueError) as exc:
                skipped.append(f"{index}: {exc}")
        if skipped:
            logger.warning(
                "Skipped %d invalid maclist record(s): %s",
                len(skipped),
                "; ".join(skipped),
            )
        return entries

    def save(self, entries: list[MacEntry]) -> None:
        # Using asdict() for consistent dataclass serialization approach.
        # The sort_keys=True ensures deterministic, reproducible JSON output.
        # The ensure_ascii=False preserves UTF-8 characters in output (instead of \uXXXX escapes).
        payload = [asdict(entry) for entry in entries]
        self.path.write_text(
            json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False),
            encoding="utf-8",
        )
