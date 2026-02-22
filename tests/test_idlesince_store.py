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
import logging
from datetime import datetime, timezone

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


def test_load_corrupted_json_returns_empty_and_logs_error(tmp_path, caplog):
    """Test that corrupted/invalid JSON is handled gracefully."""
    store = IdleSinceStore(tmp_path)
    # Write invalid JSON to file
    store._path_for("switch-3").write_text("{broken json syntax")

    with caplog.at_level(logging.ERROR):
        loaded = store.load("switch-3")

    assert loaded == {}
    assert "Corrupted JSON" in caplog.text
    assert "switch-3" in caplog.text


def test_load_non_dict_json_returns_empty_and_logs_error(tmp_path, caplog):
    """Test that non-dict top-level JSON is handled gracefully."""
    store = IdleSinceStore(tmp_path)
    # Write array instead of dict
    store._path_for("switch-4").write_text(json.dumps([1, 2, 3]))

    with caplog.at_level(logging.ERROR):
        loaded = store.load("switch-4")

    assert loaded == {}
    assert "Invalid idle state file" in caplog.text
    assert "expected dict, got list" in caplog.text


def test_load_non_dict_payload_skips_port_and_logs_warning(tmp_path, caplog):
    """Test that non-dict payload values are skipped with warning."""
    store = IdleSinceStore(tmp_path)
    raw_data = {
        "Gi1/0/7": "string-instead-of-dict",
        "Gi1/0/8": {"idle_since": "2024-01-05T06:07:08+00:00", "last_active": None},
        "Gi1/0/9": 123,  # number instead of dict
    }
    store._path_for("switch-5").write_text(json.dumps(raw_data))

    with caplog.at_level(logging.WARNING):
        loaded = store.load("switch-5")

    # Only the valid port should be loaded
    assert "Gi1/0/7" not in loaded
    assert "Gi1/0/8" in loaded
    assert loaded["Gi1/0/8"].idle_since == datetime(
        2024, 1, 5, 6, 7, 8, tzinfo=timezone.utc
    )
    assert "Gi1/0/9" not in loaded
    assert "Invalid payload for port Gi1/0/7" in caplog.text
    assert "expected dict, got str" in caplog.text
    assert "Invalid payload for port Gi1/0/9" in caplog.text
    assert "expected dict, got int" in caplog.text


def test_load_empty_file_returns_empty(tmp_path, caplog):
    """Test that an empty file is handled gracefully."""
    store = IdleSinceStore(tmp_path)
    store._path_for("switch-6").write_text("")

    with caplog.at_level(logging.ERROR):
        loaded = store.load("switch-6")

    assert loaded == {}
    assert "Corrupted JSON" in caplog.text


def test_load_unreadable_file_returns_empty_and_logs_error(tmp_path, caplog):
    """Test that file read errors are handled gracefully."""
    store = IdleSinceStore(tmp_path)
    path = store._path_for("switch-7")
    # Create file with invalid UTF-8
    path.write_bytes(b"\xff\xfe invalid utf-8")

    with caplog.at_level(logging.ERROR):
        loaded = store.load("switch-7")

    assert loaded == {}
    assert "Failed to read idle state file" in caplog.text


def test_load_mixed_valid_invalid_data_loads_valid_only(tmp_path, caplog):
    """Test that file with mixed valid/invalid data loads valid entries only."""
    store = IdleSinceStore(tmp_path)
    raw_data = {
        "Gi1/0/10": {"idle_since": "2024-01-06T07:08:09+00:00", "last_active": None},
        "Gi1/0/11": "invalid",
        "Gi1/0/12": {
            "idle_since": None,
            "last_active": "2024-01-07T08:09:10+00:00",
        },
        "Gi1/0/13": {"idle_since": "bad-timestamp", "last_active": None},
    }
    store._path_for("switch-8").write_text(json.dumps(raw_data))

    with caplog.at_level(logging.WARNING):
        loaded = store.load("switch-8")

    # Valid ports should be loaded
    assert "Gi1/0/10" in loaded
    assert loaded["Gi1/0/10"].idle_since == datetime(
        2024, 1, 6, 7, 8, 9, tzinfo=timezone.utc
    )
    assert "Gi1/0/12" in loaded
    assert loaded["Gi1/0/12"].last_active == datetime(
        2024, 1, 7, 8, 9, 10, tzinfo=timezone.utc
    )
    # Invalid non-dict port should be skipped
    assert "Gi1/0/11" not in loaded
    # Port with bad timestamp should still be loaded with None values
    assert "Gi1/0/13" in loaded
    assert loaded["Gi1/0/13"].idle_since is None
