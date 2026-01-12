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

import json

from switchmap_py.model.mac import MacEntry
from switchmap_py.storage.maclist_store import MacListStore


def test_load_missing_file_returns_empty_list(tmp_path):
    store = MacListStore(tmp_path / "maclist.json")

    assert store.load() == []


def test_save_load_roundtrip(tmp_path):
    path = tmp_path / "maclist.json"
    store = MacListStore(path)
    entries = [
        MacEntry(
            mac="aa:bb:cc:dd:ee:ff",
            ip="192.168.0.10",
            hostname="host-1",
            switch="switch-1",
            port="Gi1/0/1",
        ),
        MacEntry(
            mac="11:22:33:44:55:66",
            ip=None,
            hostname=None,
            switch=None,
            port=None,
        ),
    ]

    store.save(entries)
    loaded = store.load()

    assert loaded == entries


def test_load_skips_invalid_records(tmp_path, caplog):
    path = tmp_path / "maclist.json"
    payload = [
        {
            "mac": "aa:bb:cc:dd:ee:ff",
            "ip": "192.168.0.10",
            "hostname": "host-1",
            "switch": "switch-1",
            "port": "Gi1/0/1",
        },
        {"mac": "11:22:33:44:55:66"},
        "not-a-dict",
    ]
    path.write_text(json.dumps(payload))
    store = MacListStore(path)

    with caplog.at_level("WARNING"):
        loaded = store.load()

    assert loaded == [
        MacEntry(
            mac="aa:bb:cc:dd:ee:ff",
            ip="192.168.0.10",
            hostname="host-1",
            switch="switch-1",
            port="Gi1/0/1",
        )
    ]
    assert "Skipped 2 invalid maclist record(s)" in caplog.text
