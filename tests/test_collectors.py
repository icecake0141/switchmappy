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

from pathlib import Path

from switchmap_py.config import SwitchConfig
from switchmap_py.snmp import collectors, mibs

FIXTURE_DIR = Path(__file__).resolve().parent / "fixtures" / "synthetic"


class StubSession:
    def __init__(self, tables):
        self._tables = tables

    def get_table(self, oid):
        return self._tables.get(oid, {})


def _snmpwalk_fixture(name: str) -> dict[str, dict[str, str]]:
    tables: dict[str, dict[str, str]] = {}
    for raw_line in (FIXTURE_DIR / name).read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        oid, value = _parse_snmpwalk_line(line)
        for base_oid in vars(mibs).values():
            if not isinstance(base_oid, str):
                continue
            if oid == base_oid or oid.startswith(f"{base_oid}."):
                tables.setdefault(base_oid, {})[oid] = value
                break
    return tables


def _parse_snmpwalk_line(line: str) -> tuple[str, str]:
    oid_text, value_text = line.split("=", 1)
    oid = oid_text.strip().removeprefix(".")
    value = value_text.strip()
    if ":" in value:
        _value_type, value = value.split(":", 1)
        value = value.strip()
    if value.startswith('"') and value.endswith('"'):
        value = value[1:-1]
    return oid, value


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
        mibs.IF_TYPE: {
            f"{mibs.IF_TYPE}.1": "6",
            f"{mibs.IF_TYPE}.2": "9999",
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
    monkeypatch.setattr(collectors, "_collect_macs", lambda _session: ({}, {}, []))

    state = collectors.collect_switch_state(switch, timeout=1, retries=0)
    assert state.ports[0].name == "Gi1/0/1"
    assert state.ports[0].media == "ethernetCsmacd"
    assert state.ports[0].is_trunk is True
    assert state.ports[1].name == "2"
    assert state.ports[1].media == "9999"


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
        mibs.QBRIDGE_VLAN_FDB_PORT: {f"{mibs.QBRIDGE_VLAN_FDB_PORT}.10.0.17.34.51.68.85": "1"},
        mibs.QBRIDGE_VLAN_FDB_STATUS: {f"{mibs.QBRIDGE_VLAN_FDB_STATUS}.10.0.17.34.51.68.85": "3"},
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
    assert state.diagnostics[0]["label"] == "Q-BRIDGE populated"


def test_collect_switch_state_uses_alias_last_change_and_lldp(monkeypatch):
    switch = SwitchConfig(
        name="sw1",
        management_ip="192.0.2.1",
        community="public",
    )
    tables = {
        mibs.IF_NAME: {f"{mibs.IF_NAME}.1": "Gi1/0/1"},
        mibs.IF_ALIAS: {f"{mibs.IF_ALIAS}.1": "Access printer"},
        mibs.IF_DESCR: {f"{mibs.IF_DESCR}.1": "Gi1/0/1"},
        mibs.IF_ADMIN_STATUS: {f"{mibs.IF_ADMIN_STATUS}.1": "1"},
        mibs.IF_OPER_STATUS: {f"{mibs.IF_OPER_STATUS}.1": "1"},
        mibs.IF_LAST_CHANGE: {f"{mibs.IF_LAST_CHANGE}.1": "12345"},
        mibs.IF_SPEED: {f"{mibs.IF_SPEED}.1": "1000"},
        mibs.LLDP_LOC_PORT_ID: {f"{mibs.LLDP_LOC_PORT_ID}.7": "1"},
        mibs.LLDP_REM_SYS_NAME: {f"{mibs.LLDP_REM_SYS_NAME}.0.7.1": "neighbor-a"},
        mibs.LLDP_REM_PORT_ID: {f"{mibs.LLDP_REM_PORT_ID}.0.7.1": "Gi0/1"},
        mibs.LLDP_REM_SYS_CAP_ENABLED: {f"{mibs.LLDP_REM_SYS_CAP_ENABLED}.0.7.1": "20"},
    }

    monkeypatch.setattr(
        collectors,
        "build_session",
        lambda *_args, **_kwargs: StubSession(tables),
    )
    monkeypatch.setattr(collectors, "_collect_macs", lambda _session: ({}, {}, []))

    state = collectors.collect_switch_state(switch, timeout=1, retries=0)
    assert state.ports[0].descr == "Access printer"
    assert state.ports[0].last_change == "12345"
    assert [(neighbor.device, neighbor.protocol, neighbor.port) for neighbor in state.ports[0].neighbors] == [
        ("neighbor-a", "lldp", "Gi0/1")
    ]
    assert state.ports[0].neighbors[0].capabilities == ["bridge", "router"]


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
        mibs.QBRIDGE_VLAN_FDB_PORT: {f"{mibs.QBRIDGE_VLAN_FDB_PORT}.20.0.17.34.51.68.85": "1"},
        mibs.QBRIDGE_VLAN_FDB_STATUS: {f"{mibs.QBRIDGE_VLAN_FDB_STATUS}.20.0.17.34.51.68.85": "3"},
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


def test_collect_switch_state_records_legacy_fdb_diagnostic_and_inventory(monkeypatch):
    switch = SwitchConfig(
        name="sw1",
        management_ip="192.0.2.1",
        community="public@10",
    )
    tables = {
        mibs.IF_NAME: {f"{mibs.IF_NAME}.1": "Gi1/0/1"},
        mibs.IF_DESCR: {f"{mibs.IF_DESCR}.1": "Gi1/0/1"},
        mibs.IF_ADMIN_STATUS: {f"{mibs.IF_ADMIN_STATUS}.1": "1"},
        mibs.IF_OPER_STATUS: {f"{mibs.IF_OPER_STATUS}.1": "1"},
        mibs.IF_SPEED: {f"{mibs.IF_SPEED}.1": "1000"},
        mibs.IF_IN_ERRORS: {f"{mibs.IF_IN_ERRORS}.1": "4"},
        mibs.IF_OUT_ERRORS: {f"{mibs.IF_OUT_ERRORS}.1": "9"},
        mibs.DOT1D_BASE_PORT_IFINDEX: {f"{mibs.DOT1D_BASE_PORT_IFINDEX}.1": "1"},
        mibs.QBRIDGE_VLAN_FDB_PORT: {},
        mibs.DOT1D_TP_FDB_PORT: {f"{mibs.DOT1D_TP_FDB_PORT}.0.17.34.51.68.85": "1"},
        mibs.DOT1D_TP_FDB_STATUS: {f"{mibs.DOT1D_TP_FDB_STATUS}.0.17.34.51.68.85": "3"},
        mibs.ENT_PHYSICAL_MODEL_NAME: {f"{mibs.ENT_PHYSICAL_MODEL_NAME}.1": "C9300-24P"},
        mibs.ENT_PHYSICAL_SERIAL_NUM: {f"{mibs.ENT_PHYSICAL_SERIAL_NUM}.1": "DEMO-CISCO-0001"},
        mibs.ENT_PHYSICAL_SOFTWARE_REV: {f"{mibs.ENT_PHYSICAL_SOFTWARE_REV}.1": "17.12.1"},
        mibs.PETH_PSE_PORT_DETECTION_STATUS: {f"{mibs.PETH_PSE_PORT_DETECTION_STATUS}.1.1": "3"},
        mibs.PETH_PSE_PORT_POWER: {f"{mibs.PETH_PSE_PORT_POWER}.1.1": "154"},
    }

    monkeypatch.setattr(
        collectors,
        "build_session",
        lambda *_args, **_kwargs: StubSession(tables),
    )

    state = collectors.collect_switch_state(switch, timeout=1, retries=0)
    labels = [diagnostic["label"] for diagnostic in state.diagnostics]
    assert "Q-BRIDGE empty" in labels
    assert "FDB populated" in labels
    assert "VLAN-indexed community may be required" in labels
    assert state.platform == "C9300-24P"
    assert state.serial_number == "DEMO-CISCO-0001"
    assert state.os_version == "17.12.1"
    assert state.ports[0].macs == ["00:11:22:33:44:55"]
    assert state.ports[0].input_errors == 4
    assert state.ports[0].output_errors == 9
    assert state.ports[0].poe_status == "delivering"
    assert state.ports[0].poe_power_w == 15.4


def test_collect_switch_state_covers_cisco_cml_qbridge_fixture(monkeypatch):
    switch = SwitchConfig(
        name="cml-iosvl2-1",
        management_ip="192.0.2.10",
        community="public",
    )
    tables = _snmpwalk_fixture("cisco_cml_qbridge_snmpwalk.txt")

    monkeypatch.setattr(
        collectors,
        "build_session",
        lambda *_args, **_kwargs: StubSession(tables),
    )

    state = collectors.collect_switch_state(switch, timeout=1, retries=0)
    labels = [diagnostic["label"] for diagnostic in state.diagnostics]
    ports_by_name = {port.name: port for port in state.ports}

    assert labels == ["Q-BRIDGE populated"]
    assert ports_by_name["Gi1/0/1"].vlan == "10"
    assert ports_by_name["Gi1/0/1"].macs == ["52:54:00:00:10:01"]
    assert ports_by_name["Gi1/0/2"].vlan == "20"
    assert ports_by_name["Gi1/0/2"].macs == ["52:54:00:00:20:01"]
    assert [(vlan.vlan_id, vlan.name, vlan.ports, vlan.source) for vlan in state.vlans] == [
        ("10", "USERS", ["Gi1/0/1"], "named"),
        ("20", "SERVERS", ["Gi1/0/2"], "named"),
    ]
    assert state.platform == "CML-IOSvL2"
    assert state.serial_number == "DEMO-CML-0001"
    assert state.os_version == "15.2-CML"


def test_collect_switch_state_covers_cisco_cml_vlan_indexed_community_fixture(monkeypatch):
    switch = SwitchConfig(
        name="cml-iosvl2-1-vlan10",
        management_ip="192.0.2.10",
        community="public@10",
    )
    tables = _snmpwalk_fixture("cisco_cml_vlan_indexed_community_snmpwalk.txt")

    monkeypatch.setattr(
        collectors,
        "build_session",
        lambda *_args, **_kwargs: StubSession(tables),
    )

    state = collectors.collect_switch_state(switch, timeout=1, retries=0)
    labels = [diagnostic["label"] for diagnostic in state.diagnostics]

    assert labels == [
        "Q-BRIDGE empty",
        "FDB populated",
        "VLAN-indexed community may be required",
    ]
    assert state.ports[0].name == "Gi1/0/1"
    assert state.ports[0].macs == ["52:54:00:00:41:10"]
    assert state.ports[0].vlan is None
    assert state.vlans == []
    assert state.platform == "CML-IOSvL2"
