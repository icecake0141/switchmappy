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
    def __init__(self, output: str | None = None, *, by_command: dict[str, str] | None = None) -> None:
        self.output = output or ""
        self.by_command = by_command or {}
        self.commands: list[str] = []

    def run(self, command: str, timeout: int) -> str:
        assert timeout == 3
        self.commands.append(command)
        if command in self.by_command:
            return self.by_command[command]
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
    status_output = "\n".join(
        [
            "Port Name Status Vlan Duplex Speed Type",
            "Gi1/0/1 Uplink-Core connected 10 a-full a-1000 10/100/1000-TX",
            "Gi1/0/2 User-Port notconnect 20 auto auto 10/100/1000-TX",
        ]
    )
    mac_output = "\n".join(
        [
            "Vlan    Mac Address       Type        Ports",
            "10      0011.2233.4455    dynamic     Gi1/0/1",
        ]
    )
    session = StubSession(
        by_command={
            "show interfaces status": status_output,
            "show mac address-table": mac_output,
            "show vlan brief": "10 default active Gi1/0/1",
        }
    )
    monkeypatch.setattr(collectors, "build_session", lambda *_args, **_kwargs: session)

    state = collectors.collect_switch_state(switch, timeout=3)
    assert session.commands == ["show interfaces status", "show mac address-table", "show vlan brief"]
    assert len(state.ports) == 2
    assert state.ports[0].name == "Gi1/0/1"
    assert state.ports[0].descr == "Uplink-Core"
    assert state.ports[0].oper_status == "up"
    assert state.ports[0].is_trunk is True
    assert state.ports[0].vlan == "10"
    assert state.ports[0].speed == 1000
    assert state.ports[0].macs == ["00:11:22:33:44:55"]
    assert state.ports[1].macs == []
    assert state.ports[1].oper_status == "down"


def test_collect_port_snapshots_marks_up_ports_active(monkeypatch):
    switch = SwitchConfig(
        name="sw-ssh",
        management_ip="192.0.2.50",
        collection_method="ssh",
        ssh_username="ops",
        ssh_password="pw",
    )
    session = StubSession(
        by_command={
            "show interfaces status": "Gi1/0/1 Uplink connected 10 full 1000 copper",
            "show mac address-table": "10 00:11:22:33:44:55 dynamic Gi1/0/1",
            "show vlan brief": "10 default active Gi1/0/1",
        }
    )
    monkeypatch.setattr(collectors, "build_session", lambda *_args, **_kwargs: session)

    snapshots = collectors.collect_port_snapshots(switch, timeout=3)
    assert len(snapshots) == 1
    assert snapshots[0].is_active is True
    assert snapshots[0].mac_count == 1


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


def test_collect_switch_state_keeps_ports_when_mac_command_fails(monkeypatch):
    switch = SwitchConfig(
        name="sw-ssh",
        management_ip="192.0.2.50",
        collection_method="ssh",
        ssh_username="ops",
        ssh_password="pw",
    )

    class PartialErrorSession:
        def __init__(self) -> None:
            self.commands: list[str] = []

        def run(self, command: str, timeout: int) -> str:
            assert timeout == 3
            self.commands.append(command)
            if command == "show interfaces status":
                return "Gi1/0/1 Uplink connected 10 full 1000 copper"
            if command == "show vlan brief":
                return "10 default active Gi1/0/1"
            raise SshError("mac command failed")

    session = PartialErrorSession()
    monkeypatch.setattr(collectors, "build_session", lambda *_args, **_kwargs: session)

    state = collectors.collect_switch_state(switch, timeout=3)
    assert session.commands == ["show interfaces status", "show mac address-table", "show vlan brief"]
    assert [port.name for port in state.ports] == ["Gi1/0/1"]
    assert state.ports[0].macs == []


def test_collect_switch_state_uses_juniper_command(monkeypatch):
    switch = SwitchConfig(
        name="sw-junos",
        management_ip="192.0.2.60",
        vendor="juniper",
        collection_method="ssh",
        ssh_username="ops",
        ssh_password="pw",
    )
    status_output = "\n".join(
        [
            "Interface               Admin Link Proto    Local                 Remote",
            "ge-0/0/1                up    up",
            "ge-0/0/2                up    down",
            "ge-0/0/2.0              up    up   inet     192.0.2.1/24",
        ]
    )
    mac_output = "default 00:11:22:33:44:66 D 0 ge-0/0/1.0"
    session = StubSession(
        by_command={
            "show interfaces terse": status_output,
            "show ethernet-switching table": mac_output,
            "show vlans": "default 10 ge-0/0/1.0",
        }
    )
    monkeypatch.setattr(collectors, "build_session", lambda *_args, **_kwargs: session)

    state = collectors.collect_switch_state(switch, timeout=3)
    assert session.commands == ["show interfaces terse", "show ethernet-switching table", "show vlans"]
    assert [port.name for port in state.ports] == ["ge-0/0/1", "ge-0/0/2"]
    assert state.ports[0].oper_status == "up"
    assert state.ports[0].macs == ["00:11:22:33:44:66"]
    assert state.ports[0].vlan == "10"
    assert state.ports[1].oper_status == "down"


def test_collect_switch_state_uses_arista_command(monkeypatch):
    switch = SwitchConfig(
        name="sw-arista",
        management_ip="192.0.2.70",
        vendor="arista",
        collection_method="ssh",
        ssh_username="ops",
        ssh_password="pw",
    )
    status_output = "\n".join(
        [
            "Port Name Status Vlan Duplex Speed Type",
            "Et1 Uplink connected 10 full 10000 10Gbase-SR",
        ]
    )
    session = StubSession(
        by_command={
            "show interfaces status": status_output,
            "show mac address-table": "10 0011.2233.4466 dynamic Et1",
            "show vlan brief": "10 default active Et1",
        }
    )
    monkeypatch.setattr(collectors, "build_session", lambda *_args, **_kwargs: session)

    state = collectors.collect_switch_state(switch, timeout=3)
    assert session.commands == ["show interfaces status", "show mac address-table", "show vlan brief"]
    assert [port.name for port in state.ports] == ["Et1"]
    assert state.ports[0].oper_status == "up"
    assert state.ports[0].macs == ["00:11:22:33:44:66"]


def test_collect_switch_state_uses_fortiswitch_command(monkeypatch):
    switch = SwitchConfig(
        name="sw-forti",
        management_ip="192.0.2.80",
        vendor="Fortinet FortiSwitch OS",
        collection_method="ssh",
        ssh_username="ops",
        ssh_password="pw",
    )
    status_output = "\n".join(
        [
            "Port Status Speed Description",
            "port1 up 1000 Uplink-Core",
            "port2 down 100 User-Edge",
        ]
    )
    session = StubSession(
        by_command={
            "get switch interface status": status_output,
            "get switch mac-address-table": "10 00:11:22:33:44:77 dynamic port1",
            "show switch vlan": "default 10 port1,port2",
        }
    )
    monkeypatch.setattr(collectors, "build_session", lambda *_args, **_kwargs: session)

    state = collectors.collect_switch_state(switch, timeout=3)
    assert session.commands == ["get switch interface status", "get switch mac-address-table", "show switch vlan"]
    assert [port.name for port in state.ports] == ["port1", "port2"]
    assert state.ports[0].oper_status == "up"
    assert state.ports[0].speed == 1000
    assert state.ports[0].macs == ["00:11:22:33:44:77"]
    assert state.ports[0].vlan == "10"
    assert state.ports[1].oper_status == "down"
    assert state.ports[1].vlan == "10"
