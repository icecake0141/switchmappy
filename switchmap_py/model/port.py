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

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

from .neighbor import Neighbor


@dataclass
class Port:
    name: str
    descr: str
    admin_status: str
    oper_status: str
    speed: Optional[int]
    vlan: Optional[str]
    macs: list[str] = field(default_factory=list)
    neighbors: list[Neighbor] = field(default_factory=list)
    input_errors: Optional[int] = None
    output_errors: Optional[int] = None
    poe_status: Optional[str] = None
    poe_power_w: Optional[float] = None
    idle_since: Optional[datetime] = None
    last_active: Optional[datetime] = None
    is_trunk: bool = False

    @property
    def is_active(self) -> bool:
        return self.oper_status.lower() == "up" and bool(self.macs)

    @property
    def neighbor_names(self) -> list[str]:
        return [neighbor.device for neighbor in self.neighbors if neighbor.device]
