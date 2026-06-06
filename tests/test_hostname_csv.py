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

import io

from switchmap_py.importers.hostname_csv import parse_hostname_csv


def test_parse_hostname_csv_accepts_mac_ip_hostname_and_ip_hostname():
    records = list(
        parse_hostname_csv(
            io.StringIO(
                "\n".join(
                    [
                        "00:11:22:33:44:55,192.0.2.10,host-a",
                        "192.0.2.11,host-b",
                    ]
                )
            )
        )
    )

    assert records[0].mac == "00:11:22:33:44:55"
    assert records[0].ip == "192.0.2.10"
    assert records[0].hostname == "host-a"
    assert records[1].mac is None
    assert records[1].ip == "192.0.2.11"
    assert records[1].hostname == "host-b"
