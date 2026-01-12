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
