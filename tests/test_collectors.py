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

from switchmap_py.config import SwitchConfig
from switchmap_py.snmp import collectors, mibs


class StubSession:
    def __init__(self, tables):
        self._tables = tables

    def get_table(self, oid):
        return self._tables.get(oid, {})


def test_collect_switch_state_falls_back_to_descr_or_ifindex(monkeypatch):
    switch = SwitchConfig(
        name="sw1",
        management_ip="192.0.2.1",
        community="public",
        trunk_ports=["Gi1/0/1"],
    )
    tables = {
        mibs.IF_NAME: {
            f"{mibs.IF_NAME}.1": "",
            f"{mibs.IF_NAME}.2": "",
        },
        mibs.IF_DESCR: {
            f"{mibs.IF_DESCR}.1": "Gi1/0/1",
            f"{mibs.IF_DESCR}.2": "",
        },
        mibs.IF_ADMIN_STATUS: {
            f"{mibs.IF_ADMIN_STATUS}.1": "1",
            f"{mibs.IF_ADMIN_STATUS}.2": "1",
        },
        mibs.IF_OPER_STATUS: {
            f"{mibs.IF_OPER_STATUS}.1": "1",
            f"{mibs.IF_OPER_STATUS}.2": "2",
        },
        mibs.IF_SPEED: {
            f"{mibs.IF_SPEED}.1": "1000",
            f"{mibs.IF_SPEED}.2": "1000",
        },
    }

    monkeypatch.setattr(
        collectors,
        "build_session",
        lambda *_args, **_kwargs: StubSession(tables),
    )
    monkeypatch.setattr(collectors, "_collect_macs", lambda _session: ({}, {}))

    state = collectors.collect_switch_state(switch, timeout=1, retries=0)
    assert state.ports[0].name == "Gi1/0/1"
    assert state.ports[0].is_trunk is True
    assert state.ports[1].name == "2"


def test_collect_switch_state_assigns_vlan_to_ports(monkeypatch):
    switch = SwitchConfig(
        name="sw1",
        management_ip="192.0.2.1",
        community="public",
    )
    tables = {
        mibs.IF_NAME: {f"{mibs.IF_NAME}.1": "Gi1/0/1"},
        mibs.IF_DESCR: {f"{mibs.IF_DESCR}.1": "Gi1/0/1"},
        mibs.IF_ADMIN_STATUS: {f"{mibs.IF_ADMIN_STATUS}.1": "1"},
        mibs.IF_OPER_STATUS: {f"{mibs.IF_OPER_STATUS}.1": "1"},
        mibs.IF_SPEED: {f"{mibs.IF_SPEED}.1": "1000"},
        mibs.DOT1D_BASE_PORT_IFINDEX: {f"{mibs.DOT1D_BASE_PORT_IFINDEX}.1": "1"},
        mibs.QBRIDGE_VLAN_FDB_PORT: {
            f"{mibs.QBRIDGE_VLAN_FDB_PORT}.10.0.17.34.51.68.85": "1"
        },
        mibs.QBRIDGE_VLAN_FDB_STATUS: {
            f"{mibs.QBRIDGE_VLAN_FDB_STATUS}.10.0.17.34.51.68.85": "3"
        },
        mibs.QBRIDGE_VLAN_NAME: {f"{mibs.QBRIDGE_VLAN_NAME}.10": "Users"},
    }

    monkeypatch.setattr(
        collectors,
        "build_session",
        lambda *_args, **_kwargs: StubSession(tables),
    )

    state = collectors.collect_switch_state(switch, timeout=1, retries=0)
    assert len(state.ports) == 1
    assert state.ports[0].vlan == "10"
    assert len(state.vlans) == 1
    assert state.vlans[0].vlan_id == "10"
    assert state.vlans[0].ports == ["Gi1/0/1"]


def test_collect_switch_state_builds_vlan_from_fdb_without_name_table(monkeypatch):
    switch = SwitchConfig(
        name="sw1",
        management_ip="192.0.2.1",
        community="public",
    )
    tables = {
        mibs.IF_NAME: {f"{mibs.IF_NAME}.1": "Gi1/0/1"},
        mibs.IF_DESCR: {f"{mibs.IF_DESCR}.1": "Gi1/0/1"},
        mibs.IF_ADMIN_STATUS: {f"{mibs.IF_ADMIN_STATUS}.1": "1"},
        mibs.IF_OPER_STATUS: {f"{mibs.IF_OPER_STATUS}.1": "1"},
        mibs.IF_SPEED: {f"{mibs.IF_SPEED}.1": "1000"},
        mibs.DOT1D_BASE_PORT_IFINDEX: {f"{mibs.DOT1D_BASE_PORT_IFINDEX}.1": "1"},
        mibs.QBRIDGE_VLAN_FDB_PORT: {
            f"{mibs.QBRIDGE_VLAN_FDB_PORT}.20.0.17.34.51.68.85": "1"
        },
        mibs.QBRIDGE_VLAN_FDB_STATUS: {
            f"{mibs.QBRIDGE_VLAN_FDB_STATUS}.20.0.17.34.51.68.85": "3"
        },
        mibs.QBRIDGE_VLAN_NAME: {},
    }

    monkeypatch.setattr(
        collectors,
        "build_session",
        lambda *_args, **_kwargs: StubSession(tables),
    )

    state = collectors.collect_switch_state(switch, timeout=1, retries=0)
    assert len(state.vlans) == 1
    assert state.vlans[0].vlan_id == "20"
    assert state.vlans[0].name == "VLAN 20"
    assert state.vlans[0].source == "derived"
    assert state.vlans[0].ports == ["Gi1/0/1"]
