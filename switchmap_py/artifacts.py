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

import json
import re
from pathlib import Path
from typing import Mapping

_SAFE_RE = re.compile(r"[^A-Za-z0-9_.-]+")


def safe_artifact_name(value: str) -> str:
    token = _SAFE_RE.sub("_", value.strip())
    return token.strip("_") or "artifact"


class CollectorArtifactRecorder:
    def __init__(self, root: Path, switch_name: str, method: str) -> None:
        self.root = root
        self.switch_name = switch_name
        self.method = method
        self.switch_dir = root / safe_artifact_name(switch_name)
        self.switch_dir.mkdir(parents=True, exist_ok=True)
        self.records: list[dict[str, object]] = []

    def record_text(self, *, kind: str, name: str, content: str, status: str = "success") -> None:
        filename = f"{safe_artifact_name(kind)}-{safe_artifact_name(name)}.txt"
        path = self.switch_dir / filename
        path.write_text(content, encoding="utf-8")
        self.records.append(self._record(kind=kind, name=name, path=path, status=status, bytes=len(content.encode())))
        self._write_index()

    def record_table(self, *, oid: str, rows: Mapping[str, str], status: str = "success") -> None:
        path = self.switch_dir / f"snmp-{safe_artifact_name(oid)}.json"
        path.write_text(json.dumps(dict(rows), indent=2, sort_keys=True), encoding="utf-8")
        self.records.append(self._record(kind="snmp-table", name=oid, path=path, status=status, rows=len(rows)))
        self._write_index()

    def _record(self, *, kind: str, name: str, path: Path, status: str, **extra: object) -> dict[str, object]:
        return {
            "switch": self.switch_name,
            "method": self.method,
            "kind": kind,
            "name": name,
            "status": status,
            "path": str(path),
            "relative_path": str(path.relative_to(self.root)),
            **extra,
        }

    def _write_index(self) -> None:
        (self.switch_dir / "index.json").write_text(
            json.dumps(self.records, indent=2, sort_keys=True), encoding="utf-8"
        )
