from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Vlan:
    vlan_id: str
    name: str
    ports: list[str] = field(default_factory=list)
