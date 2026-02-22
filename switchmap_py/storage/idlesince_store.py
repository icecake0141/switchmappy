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
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger(__name__)


@dataclass
class PortIdleState:
    port: str
    idle_since: datetime | None
    last_active: datetime | None


class IdleSinceStore:
    def __init__(self, directory: Path) -> None:
        self.directory = directory
        self.directory.mkdir(parents=True, exist_ok=True)

    def _path_for(self, switch_name: str) -> Path:
        return self.directory / f"{switch_name}.json"

    def _parse_timestamp(
        self, payload: dict[str, object], *, key: str, port: str, switch_name: str
    ) -> datetime | None:
        raw = payload.get(key)
        if not raw:
            return None
        if not isinstance(raw, str):
            logger.warning(
                "Invalid %s timestamp for port %s on switch %s: %r",
                key,
                port,
                switch_name,
                raw,
            )
            return None
        try:
            return datetime.fromisoformat(raw).astimezone(timezone.utc)
        except ValueError:
            logger.warning(
                "Invalid %s timestamp for port %s on switch %s: %r",
                key,
                port,
                switch_name,
                raw,
            )
            return None

    def load(self, switch_name: str) -> dict[str, PortIdleState]:
        path = self._path_for(switch_name)
        if not path.exists():
            return {}

        # Read and parse JSON with error handling
        try:
            raw = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as e:
            logger.error(
                "Failed to read idle state file for switch %s: %s",
                switch_name,
                e,
            )
            return {}

        # Handle JSON parsing errors
        try:
            data = json.loads(raw)
        except json.JSONDecodeError as e:
            logger.error(
                "Corrupted JSON in idle state file for switch %s at %s: %s",
                switch_name,
                path,
                e,
            )
            return {}

        # Validate top-level structure is a dict
        if not isinstance(data, dict):
            logger.error(
                "Invalid idle state file for switch %s: expected dict, got %s",
                switch_name,
                type(data).__name__,
            )
            return {}

        # Parse individual port entries with validation
        result: dict[str, PortIdleState] = {}
        for port, payload in data.items():
            # Validate payload is a dict
            if not isinstance(payload, dict):
                logger.warning(
                    "Invalid payload for port %s on switch %s: expected dict, got %s. Skipping.",
                    port,
                    switch_name,
                    type(payload).__name__,
                )
                continue

            idle_since = self._parse_timestamp(
                payload, key="idle_since", port=port, switch_name=switch_name
            )
            last_active = self._parse_timestamp(
                payload, key="last_active", port=port, switch_name=switch_name
            )
            result[port] = PortIdleState(
                port=port, idle_since=idle_since, last_active=last_active
            )
        return result

    def save(self, switch_name: str, data: dict[str, PortIdleState]) -> None:
        # The sort_keys=True ensures deterministic, reproducible JSON output.
        # The ensure_ascii=False preserves UTF-8 characters in output (instead of \uXXXX escapes).
        payload = {
            port: {
                "idle_since": state.idle_since.isoformat()
                if state.idle_since
                else None,
                "last_active": state.last_active.isoformat()
                if state.last_active
                else None,
            }
            for port, state in data.items()
        }
        self._path_for(switch_name).write_text(
            json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False),
            encoding="utf-8",
        )

    def update_port(
        self,
        state: PortIdleState | None,
        *,
        port: str,
        is_active: bool,
        observed_at: datetime | None = None,
    ) -> PortIdleState:
        observed_at = observed_at or datetime.now(tz=timezone.utc)
        if is_active:
            return PortIdleState(port=port, idle_since=None, last_active=observed_at)
        if state and state.idle_since:
            return PortIdleState(
                port=port, idle_since=state.idle_since, last_active=state.last_active
            )
        return PortIdleState(port=port, idle_since=observed_at, last_active=None)
