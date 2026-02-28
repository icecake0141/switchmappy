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

from switchmap_py.config import SwitchConfig
from switchmap_py.ssh import collectors
from switchmap_py.ssh.session import SshError


class StubSession:
    def __init__(self, output: str) -> None:
        self.output = output
        self.commands: list[str] = []

    def run(self, command: str, timeout: int) -> str:
        assert timeout == 3
        self.commands.append(command)
        return self.output


def test_collect_switch_state_parses_interface_status(monkeypatch):
    switch = SwitchConfig(
        name="sw-ssh",
        management_ip="192.0.2.50",
        collection_method="ssh",
        ssh_username="ops",
        ssh_password="pw",
        trunk_ports=["Gi1/0/1"],
    )
    output = "\n".join(
        [
            "Port Name Status Vlan Duplex Speed Type",
            "Gi1/0/1 Uplink-Core connected 10 a-full a-1000 10/100/1000-TX",
            "Gi1/0/2 User-Port notconnect 20 auto auto 10/100/1000-TX",
        ]
    )
    session = StubSession(output)
    monkeypatch.setattr(collectors, "build_session", lambda *_args, **_kwargs: session)

    state = collectors.collect_switch_state(switch, timeout=3)
    assert session.commands == ["show interfaces status"]
    assert len(state.ports) == 2
    assert state.ports[0].name == "Gi1/0/1"
    assert state.ports[0].descr == "Uplink-Core"
    assert state.ports[0].oper_status == "up"
    assert state.ports[0].is_trunk is True
    assert state.ports[0].vlan == "10"
    assert state.ports[0].speed == 1000
    assert state.ports[1].oper_status == "down"


def test_collect_port_snapshots_marks_up_ports_active(monkeypatch):
    switch = SwitchConfig(
        name="sw-ssh",
        management_ip="192.0.2.50",
        collection_method="ssh",
        ssh_username="ops",
        ssh_password="pw",
    )
    output = "Gi1/0/1 connected Uplink"
    monkeypatch.setattr(collectors, "build_session", lambda *_args, **_kwargs: StubSession(output))

    snapshots = collectors.collect_port_snapshots(switch, timeout=3)
    assert len(snapshots) == 1
    assert snapshots[0].is_active is True
    assert snapshots[0].mac_count == 0


def test_collect_switch_state_returns_empty_on_ssh_error(monkeypatch):
    switch = SwitchConfig(
        name="sw-ssh",
        management_ip="192.0.2.50",
        collection_method="ssh",
        ssh_username="ops",
        ssh_password="pw",
    )

    class ErrorSession:
        def run(self, _command: str, timeout: int) -> str:
            assert timeout == 3
            raise SshError("command failed")

    monkeypatch.setattr(collectors, "build_session", lambda *_args, **_kwargs: ErrorSession())
    state = collectors.collect_switch_state(switch, timeout=3)
    assert state.ports == []


def test_collect_switch_state_uses_juniper_command(monkeypatch):
    switch = SwitchConfig(
        name="sw-junos",
        management_ip="192.0.2.60",
        vendor="juniper",
        collection_method="ssh",
        ssh_username="ops",
        ssh_password="pw",
    )
    output = "\n".join(
        [
            "Interface               Admin Link Proto    Local                 Remote",
            "ge-0/0/1                up    up",
            "ge-0/0/2                up    down",
            "ge-0/0/2.0              up    up   inet     192.0.2.1/24",
        ]
    )
    session = StubSession(output)
    monkeypatch.setattr(collectors, "build_session", lambda *_args, **_kwargs: session)

    state = collectors.collect_switch_state(switch, timeout=3)
    assert session.commands == ["show interfaces terse"]
    assert [port.name for port in state.ports] == ["ge-0/0/1", "ge-0/0/2"]
    assert state.ports[0].oper_status == "up"
    assert state.ports[1].oper_status == "down"
