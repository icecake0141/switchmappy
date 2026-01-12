from __future__ import annotations

from dataclasses import dataclass, field
from typing import Mapping

from .port import Port
from .vlan import Vlan


@dataclass
class Switch:
    name: str
    management_ip: str
    vendor: str
    ports: list[Port] = field(default_factory=list)
    vlans: list[Vlan] = field(default_factory=list)

    def port_by_name(self) -> Mapping[str, Port]:
        return {port.name: port for port in self.ports}
