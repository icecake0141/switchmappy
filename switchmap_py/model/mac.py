from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


@dataclass
class MacEntry:
    mac: str
    ip: Optional[str]
    hostname: Optional[str]
    switch: Optional[str]
    port: Optional[str]
