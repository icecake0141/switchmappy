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

from switchmap_py.oui import load_oui_vendors, normalize_oui_prefix, vendor_for_mac


def test_vendor_for_mac_uses_default_oui_data():
    vendors = load_oui_vendors()

    assert normalize_oui_prefix("52:54:00:00:10:10") == "525400"
    assert vendor_for_mac("52:54:00:00:10:10", vendors) == "QEMU / CML virtual machine"
