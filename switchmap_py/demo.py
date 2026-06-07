# Copyright 2026 SwitchMappy
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
from dataclasses import asdict
from datetime import datetime, timedelta, timezone
from pathlib import Path

from switchmap_py.model.mac import MacEntry
from switchmap_py.model.neighbor import Neighbor
from switchmap_py.model.port import Port
from switchmap_py.model.switch import Switch
from switchmap_py.model.vlan import Vlan
from switchmap_py.render.build import build_site
from switchmap_py.storage.idlesince_store import IdleSinceStore, PortIdleState
from switchmap_py.storage.maclist_store import MacListStore


def _sample_switches() -> list[Switch]:
    return [
        Switch(
            name="core-1",
            management_ip="192.0.2.10",
            vendor="Cisco IOS-XE",
            platform="C9300-48UXM",
            serial_number="FOCDEMO1001",
            os_version="17.12.1",
            uptime="12 weeks, 4 days",
            ports=[
                Port(
                    name="Gi1/0/1",
                    descr="User desk A-101",
                    admin_status="up",
                    oper_status="up",
                    speed=1000,
                    vlan="10",
                    duplex="a-full",
                    media="10/100/1000-TX",
                    macs=["00:11:22:33:44:55"],
                    switchport_mode="access",
                    access_vlan="10 (Users)",
                    input_errors=0,
                    output_errors=0,
                    poe_status="on",
                    poe_power_w=7.4,
                ),
                Port(
                    name="Gi1/0/2",
                    descr="Conference phone",
                    admin_status="up",
                    oper_status="up",
                    speed=1000,
                    vlan="20",
                    duplex="a-full",
                    media="10/100/1000-TX",
                    macs=["00:11:22:33:44:66"],
                    switchport_mode="access",
                    access_vlan="20 (Voice)",
                    voice_vlan="20 (Voice)",
                    input_errors=1,
                    output_errors=0,
                    poe_status="on",
                    poe_power_w=4.8,
                ),
                Port(
                    name="Te1/1/1",
                    descr="FortiSwitch uplink",
                    admin_status="up",
                    oper_status="up",
                    speed=10000,
                    vlan="trunk",
                    duplex="full",
                    media="SFP-10G-SR",
                    macs=["00:11:22:33:44:77"],
                    neighbors=[
                        Neighbor(device="access-forti-1", protocol="lldp", port="port49", capabilities=["bridge"])
                    ],
                    switchport_mode="trunk",
                    native_vlan="1",
                    allowed_vlans="1,10,20,30",
                    transceiver_model="SFP-10G-SR",
                    transceiver_tx_power_dbm=-2.1,
                    transceiver_rx_power_dbm=-3.4,
                    transceiver_current_ma=6.8,
                    input_errors=0,
                    output_errors=2,
                    is_trunk=True,
                ),
                Port(
                    name="Hu1/1/1",
                    descr="Datacenter leaf",
                    admin_status="up",
                    oper_status="up",
                    speed=100000,
                    vlan="trunk",
                    duplex="full",
                    media="QSFP28-LR",
                    macs=["00:11:22:33:44:aa"],
                    neighbors=[
                        Neighbor(
                            device="leaf-1", protocol="cdp", port="Ethernet1/49", capabilities=["router", "switch"]
                        )
                    ],
                    switchport_mode="trunk",
                    native_vlan="1",
                    allowed_vlans="1,10,20,30,40",
                    transceiver_model="QSFP28-LR4",
                    transceiver_tx_power_dbm=-1.7,
                    transceiver_rx_power_dbm=-4.6,
                    transceiver_current_ma=31.2,
                    is_trunk=True,
                ),
            ],
            vlans=[
                Vlan(vlan_id="10", name="Users", ports=["Gi1/0/1", "Te1/1/1"]),
                Vlan(vlan_id="20", name="Voice", ports=["Gi1/0/2", "Te1/1/1"]),
                Vlan(vlan_id="30", name="Servers", ports=["Te1/1/1"]),
            ],
        ),
        Switch(
            name="access-forti-1",
            management_ip="192.0.2.20",
            vendor="Fortinet FortiSwitch OS",
            platform="FortiSwitch-448E",
            serial_number="S448EDEMO1001",
            os_version="FortiSwitchOS v7.4.3",
            uptime="38 days",
            ports=[
                Port(
                    name="port1",
                    descr="Demo workstation",
                    admin_status="up",
                    oper_status="up",
                    speed=1000,
                    vlan="10",
                    duplex="full",
                    media="copper",
                    macs=["00:11:22:33:44:88"],
                    switchport_mode="access",
                    access_vlan="10",
                    input_errors=0,
                    output_errors=0,
                ),
                Port(
                    name="port49",
                    descr="FortiLink uplink",
                    admin_status="up",
                    oper_status="up",
                    speed=10000,
                    vlan="1",
                    duplex="full",
                    media="10G-Base-LR",
                    macs=["00:11:22:33:44:99"],
                    neighbors=[Neighbor(device="core-1", protocol="lldp", port="Te1/1/1", capabilities=["bridge"])],
                    switchport_mode="trunk",
                    native_vlan="1",
                    allowed_vlans="1,10,20,30",
                    transceiver_model="SFP-10GLR-31",
                    transceiver_tx_power_dbm=-2.2468,
                    transceiver_rx_power_dbm=-3.3003,
                    transceiver_current_ma=0.7616,
                    is_trunk=True,
                ),
            ],
            vlans=[
                Vlan(vlan_id="1", name="default", ports=["port49"]),
                Vlan(vlan_id="10", name="Users", ports=["port1", "port49"]),
                Vlan(vlan_id="30", name="Servers", ports=["port49"]),
            ],
            diagnostics=[
                {
                    "kind": "snmp_fdb",
                    "label": "VLAN-indexed community may be required",
                    "detail": "Legacy FDB has MACs but VLAN-aware Q-BRIDGE data is empty",
                }
            ],
        ),
        Switch(
            name="leaf-1",
            management_ip="192.0.2.30",
            vendor="Arista EOS",
            platform="vEOS-demo",
            serial_number="JPEDEMO1001",
            os_version="4.31.1F",
            uptime="7 weeks",
            ports=[
                Port(
                    name="Et1",
                    descr="Core uplink",
                    admin_status="up",
                    oper_status="up",
                    speed=100000,
                    vlan="trunk",
                    duplex="full",
                    media="100Gbase-LR4",
                    neighbors=[
                        Neighbor(device="core-1", protocol="lldp", port="Hu1/1/1", capabilities=["bridge", "router"])
                    ],
                    switchport_mode="trunk",
                    native_vlan="1",
                    allowed_vlans="1,30,40",
                    transceiver_model="QSFP28-LR4",
                    transceiver_tx_power_dbm=-1.3,
                    transceiver_rx_power_dbm=-5.5,
                    transceiver_current_ma=30.8,
                    is_trunk=True,
                ),
                Port(
                    name="Et2",
                    descr="Application server",
                    admin_status="up",
                    oper_status="up",
                    speed=10000,
                    vlan="30",
                    duplex="full",
                    media="10Gbase-SR",
                    macs=["00:11:22:33:44:aa"],
                    switchport_mode="access",
                    access_vlan="30",
                    transceiver_model="SFP-10G-SR",
                    transceiver_tx_power_dbm=-2.0,
                    transceiver_rx_power_dbm=-3.0,
                    transceiver_current_ma=7.5,
                    input_errors=3,
                    output_errors=1,
                ),
            ],
            vlans=[
                Vlan(vlan_id="30", name="Servers", ports=["Et1", "Et2"]),
                Vlan(vlan_id="40", name="Storage", ports=["Et1"]),
            ],
        ),
    ]


def _sample_mac_entries() -> list[MacEntry]:
    return [
        MacEntry("00:11:22:33:44:55", "192.0.2.101", "workstation-a.example.test", None, None),
        MacEntry("00:11:22:33:44:66", "192.0.2.102", "conference-phone.example.test", None, None),
        MacEntry("00:11:22:33:44:88", "192.0.2.103", "demo-workstation.example.test", None, None),
        MacEntry("00:11:22:33:44:aa", "192.0.2.110", "app-server.example.test", None, None),
        MacEntry("00:11:22:33:44:bb", "192.0.2.250", "stale-arp.example.test", None, None),
    ]


def _history_seed_payload(build_date: datetime) -> dict[str, object]:
    previous = _sample_switches()
    previous[0].ports[0].oper_status = "down"
    previous[0].ports[0].macs = []
    previous[2].ports[1].transceiver_rx_power_dbm = -2.8
    previous[2].ports[1].macs = ["00:11:22:33:44:aa"]
    return {
        "generated_at": (build_date - timedelta(days=1)).isoformat(),
        "switches": [asdict(switch) for switch in previous],
        "maclist": [asdict(entry) for entry in _sample_mac_entries()],
        "endpoint_correlations": [
            {
                "mac": "00:11:22:33:44:aa",
                "ip": "192.0.2.110",
                "hostname": "app-server.example.test",
                "switch": "core-1",
                "port": "Gi1/0/48",
            }
        ],
        "failed_switches": [],
        "debug": {},
    }


def _write_demo_artifacts(artifacts_dir: Path) -> None:
    records_by_switch = {
        "core-1": [
            {
                "switch": "core-1",
                "method": "ssh",
                "kind": "ssh-command",
                "name": "show interfaces status",
                "status": "success",
                "relative_path": "core-1/ssh-command-show_interfaces_status.txt",
                "bytes": 256,
            }
        ],
        "access-forti-1": [
            {
                "switch": "access-forti-1",
                "method": "snmp",
                "kind": "snmp-table",
                "name": "1.3.6.1.2.1.17.7.1.2.2.1.2",
                "status": "success",
                "relative_path": "access-forti-1/snmp-qbridge.json",
                "rows": 0,
            },
            {
                "switch": "access-forti-1",
                "method": "snmp",
                "kind": "snmp-table",
                "name": "1.3.6.1.2.1.17.4.3.1.2",
                "status": "success",
                "relative_path": "access-forti-1/snmp-bridge.json",
                "rows": 4,
            },
        ],
        "demo-snmp-failed": [
            {
                "switch": "demo-snmp-failed",
                "method": "snmp",
                "kind": "snmp-table",
                "name": "1.3.6.1.2.1.17.7.1.2.2.1.2",
                "status": "error",
                "relative_path": "demo-snmp-failed/snmp-qbridge.json",
                "rows": 0,
            }
        ],
    }
    for switch_name, records in records_by_switch.items():
        switch_dir = artifacts_dir / switch_name
        switch_dir.mkdir(parents=True, exist_ok=True)
        (switch_dir / "index.json").write_text(json.dumps(records, indent=2, sort_keys=True), encoding="utf-8")


def build_demo_report(*, output_dir: Path, build_date: datetime) -> None:
    state_dir = output_dir / ".demo-state"
    maclist_path = state_dir / "maclist.json"
    idlesince_dir = state_dir / "idlesince"
    history_dir = state_dir / "history"
    artifacts_dir = state_dir / "artifacts"
    state_dir.mkdir(parents=True, exist_ok=True)
    history_dir.mkdir(parents=True, exist_ok=True)
    artifacts_dir.mkdir(parents=True, exist_ok=True)

    MacListStore(maclist_path).save(_sample_mac_entries())
    IdleSinceStore(idlesince_dir).save(
        "core-1",
        {
            "Gi1/0/3": PortIdleState(
                port="Gi1/0/3",
                idle_since=build_date - timedelta(days=45),
                last_active=build_date - timedelta(days=45),
            )
        },
    )
    previous_stamp = (build_date - timedelta(days=1)).astimezone(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    (history_dir / f"{previous_stamp}.json").write_text(
        json.dumps(_history_seed_payload(build_date), indent=2, sort_keys=True, default=str),
        encoding="utf-8",
    )
    _write_demo_artifacts(artifacts_dir)

    build_site(
        switches=_sample_switches(),
        failed_switches=["demo-snmp-failed"],
        failed_switch_reasons={"demo-snmp-failed": "[SNMP_TIMEOUT] demo timeout"},
        output_dir=output_dir,
        template_dir=Path(__file__).parent / "render" / "templates",
        static_dir=Path(__file__).parent / "render" / "static",
        idlesince_store=IdleSinceStore(idlesince_dir),
        maclist_store=MacListStore(maclist_path),
        build_date=build_date,
        unused_after_days=30,
        history_dir=history_dir,
        artifacts_dir=artifacts_dir,
    )
