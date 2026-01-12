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
