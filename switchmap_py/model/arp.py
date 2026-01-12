from __future__ import annotations

from dataclasses import dataclass


@dataclass
class ArpEntry:
    ip: str
    mac: str
    hostname: str | None = None
