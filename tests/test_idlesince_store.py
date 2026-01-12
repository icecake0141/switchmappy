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

from datetime import datetime, timezone
import json
import logging

from switchmap_py.storage.idlesince_store import IdleSinceStore, PortIdleState


def test_idle_transition(tmp_path):
    store = IdleSinceStore(tmp_path)
    ts = datetime(2024, 1, 1, tzinfo=timezone.utc)
    state = PortIdleState(port="Gi1/0/1", idle_since=None, last_active=None)

    updated = store.update_port(state, port=state.port, is_active=False, observed_at=ts)
    assert updated.idle_since == ts
    assert updated.last_active is None

    updated_active = store.update_port(
        updated, port=state.port, is_active=True, observed_at=ts
    )
    assert updated_active.idle_since is None
    assert updated_active.last_active == ts


def test_update_port_preserves_idle_since(tmp_path):
    store = IdleSinceStore(tmp_path)
    ts = datetime(2024, 1, 1, tzinfo=timezone.utc)
    state = PortIdleState(port="Gi1/0/2", idle_since=ts, last_active=None)

    updated = store.update_port(state, port=state.port, is_active=False, observed_at=ts)

    assert updated.idle_since == ts
    assert updated.last_active is None


def test_save_load_roundtrip(tmp_path):
    store = IdleSinceStore(tmp_path)
    idle_ts = datetime(2024, 1, 2, 3, 4, tzinfo=timezone.utc)
    active_ts = datetime(2024, 1, 3, 4, 5, tzinfo=timezone.utc)

    data = {
        "Gi1/0/3": PortIdleState(port="Gi1/0/3", idle_since=idle_ts, last_active=None),
        "Gi1/0/4": PortIdleState(
            port="Gi1/0/4", idle_since=None, last_active=active_ts
        ),
    }

    store.save("switch-1", data)
    loaded = store.load("switch-1")

    assert loaded["Gi1/0/3"].idle_since == idle_ts
    assert loaded["Gi1/0/3"].last_active is None
    assert loaded["Gi1/0/4"].idle_since is None
    assert loaded["Gi1/0/4"].last_active == active_ts


def test_load_with_invalid_timestamps_logs_warning(tmp_path, caplog):
    store = IdleSinceStore(tmp_path)
    raw_data = {
        "Gi1/0/5": {"idle_since": "not-a-timestamp", "last_active": "also-bad"},
        "Gi1/0/6": {
            "idle_since": "2024-01-04T05:06:07+00:00",
            "last_active": None,
        },
    }
    store._path_for("switch-2").write_text(json.dumps(raw_data))

    with caplog.at_level(logging.WARNING):
        loaded = store.load("switch-2")

    assert loaded["Gi1/0/5"].idle_since is None
    assert loaded["Gi1/0/5"].last_active is None
    assert loaded["Gi1/0/6"].idle_since == datetime(
        2024, 1, 4, 5, 6, 7, tzinfo=timezone.utc
    )
    assert loaded["Gi1/0/6"].last_active is None
    assert "Invalid idle_since timestamp" in caplog.text
    assert "Invalid last_active timestamp" in caplog.text
