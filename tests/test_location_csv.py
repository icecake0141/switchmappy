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

from io import StringIO

from switchmap_py.importers.location_csv import parse_location_csv


def test_parse_location_csv_with_header_accepts_mac_and_ip_rows():
    rows = list(
        parse_location_csv(
            StringIO(
                "\n".join(
                    [
                        "mac,ip,office,location",
                        "00:11:22:33:44:55,,Tokyo HQ,4F-12",
                        ",192.0.2.10,Osaka,2F-03",
                        "not-a-mac,,Ignored,Nowhere",
                    ]
                )
            )
        )
    )

    assert rows[0].mac == "00:11:22:33:44:55"
    assert rows[0].office == "Tokyo HQ"
    assert rows[0].location == "4F-12"
    assert rows[1].ip == "192.0.2.10"
    assert rows[1].office == "Osaka"
    assert len(rows) == 2


def test_parse_location_csv_without_header_matches_mac_or_ip_key():
    rows = list(
        parse_location_csv(
            StringIO(
                "\n".join(
                    [
                        "# key,office,location",
                        "00:11:22:33:44:55,Tokyo HQ,4F-12",
                        "192.0.2.10,Osaka,2F-03",
                        "invalid,Ignored,Nowhere",
                    ]
                )
            )
        )
    )

    assert [row.mac for row in rows] == ["00:11:22:33:44:55", None]
    assert [row.ip for row in rows] == [None, "192.0.2.10"]
