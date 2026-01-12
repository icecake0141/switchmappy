from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import json
from pathlib import Path


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

    def load(self, switch_name: str) -> dict[str, PortIdleState]:
        path = self._path_for(switch_name)
        if not path.exists():
            return {}
        raw = path.read_text()
        data = json.loads(raw)
        result: dict[str, PortIdleState] = {}
        for port, payload in data.items():
            idle_since = (
                datetime.fromisoformat(payload["idle_since"]).astimezone(timezone.utc)
                if payload["idle_since"]
                else None
            )
            last_active = (
                datetime.fromisoformat(payload["last_active"]).astimezone(timezone.utc)
                if payload["last_active"]
                else None
            )
            result[port] = PortIdleState(
                port=port, idle_since=idle_since, last_active=last_active
            )
        return result

    def save(self, switch_name: str, data: dict[str, PortIdleState]) -> None:
        payload = {
            port: {
                "idle_since": state.idle_since.isoformat() if state.idle_since else None,
                "last_active": state.last_active.isoformat() if state.last_active else None,
            }
            for port, state in data.items()
        }
        self._path_for(switch_name).write_text(
            json.dumps(payload, indent=2, sort_keys=True)
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
