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

    def run(self, _command: str, timeout: int) -> str:
        assert timeout == 3
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
            "Port Status Description",
            "Gi1/0/1 connected Uplink-Core",
            "Gi1/0/2 notconnect User-Port",
        ]
    )
    monkeypatch.setattr(collectors, "build_session", lambda *_args, **_kwargs: StubSession(output))

    state = collectors.collect_switch_state(switch, timeout=3)
    assert len(state.ports) == 2
    assert state.ports[0].name == "Gi1/0/1"
    assert state.ports[0].oper_status == "up"
    assert state.ports[0].is_trunk is True
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
