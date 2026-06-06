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
from pathlib import Path

_DEFAULT_OUI_VENDORS = {
    "000c29": "VMware, Inc.",
    "3ca308": "Texas Instruments",
    "485e5e": "SERNET (SUZHOU) TECHNOLOGIES CORPORATION",
    "525400": "QEMU virtual machine",
    "707414": "Murata Manufacturing Co., Ltd.",
    "8060b7": "Cloud Network Technology Singapore Pte. Ltd.",
    "ac1f6b": "Super Micro Computer, Inc.",
    "b827eb": "Raspberry Pi Foundation",
    "c4ff84": "Turing Machines Inc.",
    "c00925": "FN-LINK TECHNOLOGY Ltd.",
    "ecb5fa": "Philips Lighting BV",
}


def normalize_oui_prefix(value: str) -> str | None:
    token = value.strip().lower().replace("-", "").replace(":", "").replace(".", "")
    if len(token) < 6:
        return None
    prefix = token[:6]
    if not all(character in "0123456789abcdef" for character in prefix):
        return None
    return prefix


def load_oui_vendors(path: Path | None = None) -> dict[str, str]:
    vendors = dict(_DEFAULT_OUI_VENDORS)
    if path is None or not path.exists():
        return vendors
    with path.open(newline="", encoding="utf-8") as handle:
        reader = csv.reader(handle)
        for row in reader:
            if len(row) < 2 or row[0].strip().startswith("#"):
                continue
            prefix = normalize_oui_prefix(row[0])
            vendor = row[1].strip()
            if prefix and vendor:
                vendors[prefix] = vendor
    return vendors


def vendor_for_mac(mac: str, vendors: dict[str, str]) -> str:
    prefix = normalize_oui_prefix(mac)
    if prefix is None:
        return ""
    return vendors.get(prefix, "")
