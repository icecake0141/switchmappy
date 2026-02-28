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

import json
from datetime import datetime, timezone

import pytest

pytest.importorskip("typer")

from typer.testing import CliRunner

from switchmap_py.cli import app
from switchmap_py.model.port import Port
from switchmap_py.model.switch import Switch
from switchmap_py.model.vlan import Vlan
from switchmap_py.snmp.session import SnmpError
from switchmap_py.storage.idlesince_store import IdleSinceStore, PortIdleState


def test_cli_build_html_generates_all_expected_pages(tmp_path, monkeypatch):
    output_dir = tmp_path / "output"
    config_path = tmp_path / "site.yml"
    maclist_path = tmp_path / "maclist.json"
    maclist_path.write_text(
        json.dumps(
            [
                {
                    "mac": "00:11:22:33:44:55",
                    "ip": "192.0.2.100",
                    "hostname": "host-a",
                    "switch": "sw-ok",
                    "port": "Gi1/0/1",
                }
            ]
        ),
        encoding="utf-8",
    )
    config_path.write_text(
        "\n".join(
            [
                f"destination_directory: {output_dir}",
                f"idlesince_directory: {tmp_path / 'idlesince'}",
                f"maclist_file: {maclist_path}",
                "unused_after_days: 30",
                "switches:",
                "  - name: sw-ok",
                "    management_ip: 192.0.2.10",
                "    community: public",
                "    trunk_ports: [\"Gi1/0/1\"]",
                "  - name: sw-bad",
                "    management_ip: 192.0.2.11",
                "    community: public",
            ]
        ),
        encoding="utf-8",
    )
    IdleSinceStore(tmp_path / "idlesince").save(
        "sw-ok",
        {
            "Gi1/0/1": PortIdleState(
                port="Gi1/0/1",
                idle_since=datetime(2023, 11, 1, tzinfo=timezone.utc),
                last_active=None,
            )
        },
    )

    def fake_collect_switch_state(sw, _timeout, _retries):
        if sw.name == "sw-bad":
            raise SnmpError("SNMP failure")
        return Switch(
            name="sw-ok",
            management_ip="192.0.2.10",
            vendor="test",
            ports=[
                Port(
                    name="Gi1/0/1",
                    descr="Uplink",
                    admin_status="up",
                    oper_status="up",
                    speed=1000,
                    vlan="10",
                    macs=["00:11:22:33:44:55"],
                    is_trunk=True,
                )
            ],
            vlans=[Vlan(vlan_id="10", name="Users", ports=["Gi1/0/1"])],
        )

    monkeypatch.setattr("switchmap_py.cli.collect_switch_state", fake_collect_switch_state)

    runner = CliRunner()
    result = runner.invoke(app, ["build-html", "--config", str(config_path)])
    assert result.exit_code == 0

    assert (output_dir / "index.html").exists()
    assert (output_dir / "switches" / "sw-ok.html").exists()
    assert (output_dir / "ports" / "index.html").exists()
    assert (output_dir / "vlans" / "index.html").exists()
    assert (output_dir / "search" / "index.html").exists()
    assert (output_dir / "search" / "index.json").exists()

    index_html = (output_dir / "index.html").read_text(encoding="utf-8")
    switch_html = (output_dir / "switches" / "sw-ok.html").read_text(encoding="utf-8")
    ports_html = (output_dir / "ports" / "index.html").read_text(encoding="utf-8")
    vlan_html = (output_dir / "vlans" / "index.html").read_text(encoding="utf-8")
    assert "sw-bad" in index_html
    assert "192.0.2.100 (host-a)" in switch_html
    assert "Users" in vlan_html
    assert "Trunk" in switch_html
    assert "Unused (>= 30d)" in switch_html
    assert "Unused (>= 30d)" in ports_html
