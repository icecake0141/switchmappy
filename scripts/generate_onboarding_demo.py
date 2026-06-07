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

import shutil
from datetime import datetime, timezone
from pathlib import Path

from switchmap_py.model.mac import MacEntry
from switchmap_py.model.neighbor import Neighbor
from switchmap_py.model.port import Port
from switchmap_py.model.switch import Switch
from switchmap_py.model.vlan import Vlan
from switchmap_py.render.build import build_site
from switchmap_py.storage.idlesince_store import IdleSinceStore
from switchmap_py.storage.maclist_store import MacListStore

ROOT = Path(__file__).resolve().parents[1]
DEMO_ROOT = ROOT / "docs" / "assets" / "onboarding" / "demo"
OUTPUT_DIR = DEMO_ROOT / "output"
IDLESINCE_DIR = DEMO_ROOT / "idlesince"
HISTORY_DIR = DEMO_ROOT / "history"
ARTIFACTS_DIR = DEMO_ROOT / "artifacts"
MACLIST_FILE = DEMO_ROOT / "maclist.json"
CONFIG_FILE = DEMO_ROOT / "site.yml"


def _port(
    name: str,
    descr: str,
    oper_status: str,
    vlan: str | None,
    macs: list[str],
    *,
    speed: int | None = 1000,
    neighbor: Neighbor | None = None,
    role: str = "endpoint",
    input_errors: int | None = None,
    output_errors: int | None = None,
    poe_status: str | None = None,
    poe_power_w: float | None = None,
    is_trunk: bool = False,
) -> Port:
    return Port(
        name=name,
        descr=descr,
        admin_status="up",
        oper_status=oper_status,
        speed=speed,
        vlan=vlan,
        duplex="full" if oper_status == "up" else None,
        media="copper" if speed and speed <= 1000 else "fiber",
        transceiver_model="SFP-10G-SR" if speed == 10000 else None,
        transceiver_tx_power_dbm=-2.1 if speed == 10000 else None,
        transceiver_rx_power_dbm=-2.4 if speed == 10000 else None,
        transceiver_current_ma=7.8 if speed == 10000 else None,
        macs=macs,
        neighbors=[neighbor] if neighbor else [],
        input_errors=input_errors,
        output_errors=output_errors,
        poe_status=poe_status,
        poe_power_w=poe_power_w,
        switchport_mode="trunk" if is_trunk else "access",
        access_vlan=vlan if not is_trunk else None,
        native_vlan="10" if is_trunk else None,
        allowed_vlans="10,20,30" if is_trunk else None,
        role=role,
        role_confidence="high",
        role_evidence=["synthetic onboarding demo"],
        is_trunk=is_trunk,
    )


def _switches() -> list[Switch]:
    access_neighbor = Neighbor(device="dist-sw1", protocol="lldp", port="Te1/1/1", capabilities=["bridge"])
    core_neighbor = Neighbor(device="edge-router1", protocol="cdp", port="Gi0/0", capabilities=["router"])
    return [
        Switch(
            name="access-sw1",
            management_ip="192.0.2.20",
            vendor="generic",
            platform="DemoSwitch 24P",
            serial_number="DEMOACCESS001",
            os_version="demo-os 1.0",
            uptime="45 days",
            ports=[
                _port(
                    "Gi1/0/1",
                    "Front desk phone",
                    "up",
                    "20",
                    ["02:00:00:00:20:01"],
                    poe_status="delivering",
                    poe_power_w=5.4,
                ),
                _port("Gi1/0/2", "Conference display", "up", "30", ["02:00:00:00:30:02"]),
                _port("Gi1/0/3", "", "up", "20", ["02:00:00:00:20:03"], input_errors=3),
                _port("Gi1/0/4", "Spare desk", "down", "20", []),
                _port(
                    "Gi1/0/24",
                    "Uplink to distribution",
                    "up",
                    None,
                    ["02:00:00:00:ff:24"],
                    neighbor=access_neighbor,
                    role="network",
                    is_trunk=True,
                ),
            ],
            vlans=[
                Vlan(vlan_id="20", name="users", ports=["Gi1/0/1", "Gi1/0/3"]),
                Vlan(vlan_id="30", name="conference", ports=["Gi1/0/2"]),
            ],
            diagnostics=[{"collector": "demo", "status": "success", "message": "Synthetic onboarding data"}],
        ),
        Switch(
            name="dist-sw1",
            management_ip="192.0.2.10",
            vendor="generic",
            platform="DemoSwitch 10G",
            serial_number="DEMODIST001",
            os_version="demo-os 1.0",
            uptime="120 days",
            ports=[
                _port(
                    "Te1/1/1",
                    "Downlink to access-sw1",
                    "up",
                    None,
                    ["02:00:00:00:ff:11"],
                    speed=10000,
                    neighbor=Neighbor(device="access-sw1", protocol="lldp", port="Gi1/0/24", capabilities=["bridge"]),
                    role="network",
                    is_trunk=True,
                ),
                _port(
                    "Te1/1/2",
                    "Router handoff",
                    "up",
                    None,
                    ["02:00:00:00:ff:12"],
                    speed=10000,
                    neighbor=core_neighbor,
                    role="network",
                    output_errors=2,
                    is_trunk=True,
                ),
                _port("Gi1/0/10", "Build server", "up", "10", ["02:00:00:00:10:10"]),
            ],
            vlans=[
                Vlan(vlan_id="10", name="servers", ports=["Gi1/0/10"]),
                Vlan(vlan_id="20", name="users", ports=["Te1/1/1"]),
                Vlan(vlan_id="30", name="conference", ports=["Te1/1/1"]),
            ],
            diagnostics=[{"collector": "demo", "status": "success", "message": "Synthetic onboarding data"}],
        ),
    ]


def _mac_entries() -> list[MacEntry]:
    return [
        MacEntry("02:00:00:00:20:01", "198.51.100.21", "front-desk-phone.example.test", "access-sw1", "Gi1/0/1"),
        MacEntry("02:00:00:00:30:02", "198.51.100.32", "conference-display.example.test", "access-sw1", "Gi1/0/2"),
        MacEntry("02:00:00:00:20:03", "198.51.100.23", "unlabeled-workstation.example.test", "access-sw1", "Gi1/0/3"),
        MacEntry("02:00:00:00:10:10", "198.51.100.110", "build-server.example.test", "dist-sw1", "Gi1/0/10"),
    ]


def _write_config() -> None:
    CONFIG_FILE.write_text(
        "\n".join(
            [
                "# Copyright 2026 SwitchMappy",
                "# SPDX-License-Identifier: Apache-2.0",
                "#",
                '# Licensed under the Apache License, Version 2.0 (the "License");',
                "# you may not use this file except in compliance with the License.",
                "# You may obtain a copy of the License at",
                "#",
                "#     http://www.apache.org/licenses/LICENSE-2.0",
                "#",
                "# This file was created or modified with the assistance of an AI (Large Language Model).",
                "# Review required for correctness, security, and licensing.",
                "",
                "# Synthetic SwitchMappy onboarding demo configuration.",
                "destination_directory: docs/assets/onboarding/demo/output",
                "idlesince_directory: docs/assets/onboarding/demo/idlesince",
                "maclist_file: docs/assets/onboarding/demo/maclist.json",
                "history_directory: docs/assets/onboarding/demo/history",
                "collection_artifacts_directory: docs/assets/onboarding/demo/artifacts",
                "unused_after_days: 30",
                "switches:",
                "  - name: access-sw1",
                "    management_ip: 192.0.2.20",
                "    community: public",
                "  - name: dist-sw1",
                "    management_ip: 192.0.2.10",
                "    community: public",
                "",
            ]
        ),
        encoding="utf-8",
    )


def main() -> None:
    for path in [OUTPUT_DIR, IDLESINCE_DIR, HISTORY_DIR, ARTIFACTS_DIR]:
        if path.exists():
            shutil.rmtree(path)
        path.mkdir(parents=True, exist_ok=True)
    DEMO_ROOT.mkdir(parents=True, exist_ok=True)
    _write_config()

    mac_store = MacListStore(MACLIST_FILE)
    mac_store.save(_mac_entries())

    build_site(
        switches=_switches(),
        failed_switches=["demo-spare-sw"],
        failed_switch_reasons={"demo-spare-sw": "[SNMP_TIMEOUT] Synthetic timeout example"},
        output_dir=OUTPUT_DIR,
        template_dir=ROOT / "switchmap_py" / "render" / "templates",
        static_dir=ROOT / "switchmap_py" / "render" / "static",
        idlesince_store=IdleSinceStore(IDLESINCE_DIR),
        maclist_store=mac_store,
        build_date=datetime(2026, 1, 15, 9, 30, tzinfo=timezone.utc),
        unused_after_days=30,
        oui_file=None,
        history_dir=HISTORY_DIR,
        artifacts_dir=ARTIFACTS_DIR / "20260115T093000Z",
    )
    print(f"Generated synthetic onboarding demo at {OUTPUT_DIR}")


if __name__ == "__main__":
    main()
