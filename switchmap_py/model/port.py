from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional


@dataclass
class Port:
    name: str
    descr: str
    admin_status: str
    oper_status: str
    speed: Optional[int]
    vlan: Optional[str]
    macs: list[str] = field(default_factory=list)
    idle_since: Optional[datetime] = None
    last_active: Optional[datetime] = None
    is_trunk: bool = False

    @property
    def is_active(self) -> bool:
        return self.oper_status.lower() == "up" and bool(self.macs)
