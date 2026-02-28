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

from switchmap_py import collectors
from switchmap_py.config import SwitchConfig
from switchmap_py.model.switch import Switch
from switchmap_py.snmp.collectors import PortSnapshot


def test_dispatch_collect_switch_state_uses_snmp(monkeypatch):
    switch = SwitchConfig(name="sw1", management_ip="192.0.2.1", community="public")
    called = {"snmp": 0}

    def fake_snmp(_switch, timeout, retries):
        called["snmp"] += 1
        assert timeout == 2
        assert retries == 1
        return Switch(name="sw1", management_ip="192.0.2.1", vendor="test")

    monkeypatch.setattr(collectors, "collect_switch_state_snmp", fake_snmp)
    result = collectors.collect_switch_state(switch, timeout=2, retries=1)
    assert called["snmp"] == 1
    assert result.name == "sw1"


def test_dispatch_collect_switch_state_uses_ssh(monkeypatch):
    switch = SwitchConfig(
        name="sw-ssh",
        management_ip="192.0.2.50",
        collection_method="ssh",
        ssh_username="ops",
        ssh_password="pw",
    )
    called = {"ssh": 0}

    def fake_ssh(_switch, timeout):
        called["ssh"] += 1
        assert timeout == 3
        return Switch(name="sw-ssh", management_ip="192.0.2.50", vendor="test")

    monkeypatch.setattr(collectors, "collect_switch_state_ssh", fake_ssh)
    result = collectors.collect_switch_state(switch, timeout=3, retries=9)
    assert called["ssh"] == 1
    assert result.name == "sw-ssh"


def test_dispatch_collect_port_snapshots_uses_ssh(monkeypatch):
    switch = SwitchConfig(
        name="sw-ssh",
        management_ip="192.0.2.50",
        collection_method="ssh",
        ssh_username="ops",
        ssh_password="pw",
    )

    def fake_ssh_snapshots(_switch, timeout):
        assert timeout == 4
        return [PortSnapshot(name="Gi1/0/1", is_active=True, mac_count=0, oper_status="up")]

    monkeypatch.setattr(collectors, "collect_port_snapshots_ssh", fake_ssh_snapshots)
    snapshots = collectors.collect_port_snapshots(switch, timeout=4, retries=0)
    assert len(snapshots) == 1
    assert snapshots[0].name == "Gi1/0/1"
