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

import csv
import ipaddress
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator, TextIO

from switchmap_py.importers.arp_csv import is_valid_mac


@dataclass(frozen=True)
class HostnameRecord:
    ip: str | None
    hostname: str
    mac: str | None = None


def _is_valid_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def parse_hostname_csv(handle: TextIO) -> Iterator[HostnameRecord]:
    reader = csv.reader(handle)
    for row in reader:
        if not row or row[0].strip().startswith("#"):
            continue
        parts = [part.strip() for part in row]
        if len(parts) >= 3 and is_valid_mac(parts[0]) and _is_valid_ip(parts[1]) and parts[2]:
            yield HostnameRecord(mac=parts[0].lower(), ip=parts[1], hostname=parts[2])
        elif len(parts) >= 2 and _is_valid_ip(parts[0]) and parts[1]:
            yield HostnameRecord(ip=parts[0], hostname=parts[1])


def load_hostname_csv(path: Path) -> list[HostnameRecord]:
    with path.open(newline="", encoding="utf-8") as handle:
        return list(parse_hostname_csv(handle))
