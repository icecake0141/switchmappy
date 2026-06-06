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
from typing import Optional


@dataclass
class Neighbor:
    device: str
    protocol: str
    port: Optional[str] = None
    capabilities: list[str] = field(default_factory=list)

    @property
    def display_name(self) -> str:
        protocol = self.protocol.upper() if self.protocol else ""
        details = []
        if protocol:
            details.append(protocol)
        if self.port:
            details.append(self.port)
        if self.capabilities:
            details.append("/".join(self.capabilities))
        suffix = f" ({', '.join(details)})" if details else ""
        return f"{self.device}{suffix}"
