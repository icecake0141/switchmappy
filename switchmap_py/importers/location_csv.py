# Copyright 2026 SwitchMappy
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
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator, TextIO

from switchmap_py.importers.arp_csv import is_valid_ip, is_valid_mac


@dataclass(frozen=True)
class LocationRecord:
    mac: str | None
    ip: str | None
    office: str | None
    location: str | None


def _empty_to_none(value: str) -> str | None:
    stripped = value.strip()
    return stripped or None


def _record_from_parts(parts: list[str]) -> LocationRecord | None:
    if len(parts) < 3:
        return None
    key = parts[0].strip()
    if is_valid_mac(key):
        return LocationRecord(
            mac=key.lower(),
            ip=None,
            office=_empty_to_none(parts[1]),
            location=_empty_to_none(parts[2]),
        )
    if is_valid_ip(key):
        return LocationRecord(
            mac=None,
            ip=key,
            office=_empty_to_none(parts[1]),
            location=_empty_to_none(parts[2]),
        )
    return None


def parse_location_csv(handle: TextIO) -> Iterator[LocationRecord]:
    reader = csv.reader(handle)
    rows = [[part.strip() for part in row] for row in reader if row and not row[0].strip().startswith("#")]
    if not rows:
        return

    header = [part.lower() for part in rows[0]]
    header_names = {"mac", "ip", "office", "location"}
    if header_names & set(header):
        indexes = {name: header.index(name) for name in header_names if name in header}
        for row in rows[1:]:
            mac = _empty_to_none(row[indexes["mac"]]) if "mac" in indexes and len(row) > indexes["mac"] else None
            ip = _empty_to_none(row[indexes["ip"]]) if "ip" in indexes and len(row) > indexes["ip"] else None
            office = (
                _empty_to_none(row[indexes["office"]]) if "office" in indexes and len(row) > indexes["office"] else None
            )
            location = (
                _empty_to_none(row[indexes["location"]])
                if "location" in indexes and len(row) > indexes["location"]
                else None
            )
            if mac and not is_valid_mac(mac):
                mac = None
            if ip and not is_valid_ip(ip):
                ip = None
            if mac or ip:
                yield LocationRecord(mac=mac.lower() if mac else None, ip=ip, office=office, location=location)
        return

    for row in rows:
        record = _record_from_parts(row)
        if record is not None:
            yield record


def load_location_csv(path: Path) -> list[LocationRecord]:
    with path.open(newline="", encoding="utf-8") as handle:
        return list(parse_location_csv(handle))
