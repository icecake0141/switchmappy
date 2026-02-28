# Copyright 2025 OpenAI Codex
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

from typer.testing import CliRunner

from switchmap_py.cli import app
from switchmap_py.snmp.collectors import PortSnapshot
from switchmap_py.storage import idlesince_store as idlesince_module
from switchmap_py.storage.idlesince_store import IdleSinceStore, PortIdleState


def test_scan_switch_updates_idle_since(tmp_path, monkeypatch):
    idlesince_dir = tmp_path / "idlesince"
    config_path = tmp_path / "site.yml"
    config_path.write_text(
        "\n".join(
            [
                f"destination_directory: {tmp_path / 'output'}",
                f"idlesince_directory: {idlesince_dir}",
                f"maclist_file: {tmp_path / 'maclist.json'}",
                "switches:",
                "  - name: sw1",
                "    management_ip: 192.0.2.1",
                "    community: public",
            ]
        )
    )

    fixed_time = datetime(2024, 1, 5, tzinfo=timezone.utc)

    class FixedDateTime(datetime):
        @classmethod
        def now(cls, tz=None):
            return fixed_time.astimezone(tz) if tz else fixed_time.replace(tzinfo=None)

    monkeypatch.setattr(idlesince_module, "datetime", FixedDateTime)

    store = IdleSinceStore(idlesince_dir)
    store.save(
        "sw1",
        {"Gi1/0/1": PortIdleState(port="Gi1/0/1", idle_since=fixed_time, last_active=None)},
    )

    def fake_collect_port_snapshots(_switch, _timeout, _retries):
        return [
            PortSnapshot(
                name="Gi1/0/1",
                is_active=True,
                mac_count=2,
                oper_status="up",
            ),
            PortSnapshot(
                name="Gi1/0/2",
                is_active=False,
                mac_count=0,
                oper_status="down",
            ),
        ]

    monkeypatch.setattr("switchmap_py.cli.collect_port_snapshots", fake_collect_port_snapshots)

    runner = CliRunner()
    result = runner.invoke(app, ["scan-switch", "--config", str(config_path)])
    assert result.exit_code == 0

    loaded = store.load("sw1")
    assert loaded["Gi1/0/1"].idle_since is None
    assert loaded["Gi1/0/1"].last_active == fixed_time
    assert loaded["Gi1/0/2"].idle_since == fixed_time
    assert loaded["Gi1/0/2"].last_active is None


def test_scan_switch_keeps_missing_ports(tmp_path, monkeypatch):
    idlesince_dir = tmp_path / "idlesince"
    config_path = tmp_path / "site.yml"
    config_path.write_text(
        "\n".join(
            [
                f"destination_directory: {tmp_path / 'output'}",
                f"idlesince_directory: {idlesince_dir}",
                f"maclist_file: {tmp_path / 'maclist.json'}",
                "switches:",
                "  - name: sw1",
                "    management_ip: 192.0.2.1",
                "    community: public",
            ]
        )
    )

    fixed_time = datetime(2024, 1, 5, tzinfo=timezone.utc)

    class FixedDateTime(datetime):
        @classmethod
        def now(cls, tz=None):
            return fixed_time.astimezone(tz) if tz else fixed_time.replace(tzinfo=None)

    monkeypatch.setattr(idlesince_module, "datetime", FixedDateTime)

    store = IdleSinceStore(idlesince_dir)
    missing_state = PortIdleState(port="Gi1/0/2", idle_since=fixed_time, last_active=None)
    store.save(
        "sw1",
        {
            "Gi1/0/1": PortIdleState(port="Gi1/0/1", idle_since=None, last_active=fixed_time),
            "Gi1/0/2": missing_state,
        },
    )

    def fake_collect_port_snapshots(_switch, _timeout, _retries):
        return [
            PortSnapshot(
                name="Gi1/0/1",
                is_active=True,
                mac_count=2,
                oper_status="up",
            )
        ]

    monkeypatch.setattr("switchmap_py.cli.collect_port_snapshots", fake_collect_port_snapshots)

    runner = CliRunner()
    result = runner.invoke(app, ["scan-switch", "--config", str(config_path)])
    assert result.exit_code == 0

    loaded = store.load("sw1")
    assert loaded["Gi1/0/2"].idle_since == missing_state.idle_since
    assert loaded["Gi1/0/2"].last_active == missing_state.last_active


def test_scan_switch_propagates_snmp_errors(tmp_path, monkeypatch):
    """Verify that SNMP errors cause scan-switch to fail fast."""
    from switchmap_py.snmp.session import SnmpError

    config_path = tmp_path / "site.yml"
    config_path.write_text(
        "\n".join(
            [
                f"destination_directory: {tmp_path / 'output'}",
                f"idlesince_directory: {tmp_path / 'idlesince'}",
                f"maclist_file: {tmp_path / 'maclist.json'}",
                "switches:",
                "  - name: sw1",
                "    management_ip: 192.0.2.1",
                "    community: public",
            ]
        )
    )

    def fake_collect_port_snapshots(_switch, _timeout, _retries):
        raise SnmpError("SNMP timeout")

    monkeypatch.setattr("switchmap_py.cli.collect_port_snapshots", fake_collect_port_snapshots)

    runner = CliRunner()
    result = runner.invoke(app, ["scan-switch", "--config", str(config_path)])

    # Scan-switch should fail fast on SNMP errors (not catch them)
    assert result.exit_code != 0
    assert isinstance(result.exception, SnmpError)
