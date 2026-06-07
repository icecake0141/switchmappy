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


def _access_switch(name: str, number: int, dist_switch: str, dist_port: str) -> Switch:
    phone_mac = f"02:00:00:00:20:{number:02x}"
    workstation_mac = f"02:00:00:00:21:{number:02x}"
    camera_mac = f"02:00:00:00:40:{number:02x}"
    return Switch(
        name=name,
        management_ip=f"192.0.2.{20 + number}",
        vendor="generic",
        platform="DemoSwitch Access 48P",
        serial_number=f"DEMOACCESS{number:03d}",
        os_version="demo-os access 3.2",
        uptime=f"{30 + number} days",
        ports=[
            _port(
                "Gi1/0/1",
                f"Desk phone {number}",
                "up",
                "20",
                [phone_mac],
                poe_status="delivering",
                poe_power_w=5.0 + number / 10,
            ),
            _port("Gi1/0/2", f"Workstation {number}", "up", "20", [workstation_mac]),
            _port("Gi1/0/3", f"Conference display {number}", "up", "30", [f"02:00:00:00:30:{number:02x}"]),
            _port(
                "Gi1/0/4",
                f"Security camera {number}",
                "up",
                "40",
                [camera_mac],
                poe_status="delivering",
                poe_power_w=7.0 + number / 10,
            ),
            _port("Gi1/0/5", "", "up", "20", [f"02:00:00:00:22:{number:02x}"], input_errors=number),
            _port("Gi1/0/6", "Spare desk", "down", "20", []),
            _port(
                "Gi1/0/48",
                f"Uplink to {dist_switch}",
                "up",
                None,
                [f"02:00:00:00:ff:{number:02x}"],
                speed=10000,
                neighbor=Neighbor(device=dist_switch, protocol="lldp", port=dist_port, capabilities=["bridge"]),
                role="network",
                is_trunk=True,
            ),
        ],
        vlans=[
            Vlan(vlan_id="20", name="users", ports=["Gi1/0/1", "Gi1/0/2", "Gi1/0/5", "Gi1/0/48"]),
            Vlan(vlan_id="30", name="conference", ports=["Gi1/0/3", "Gi1/0/48"]),
            Vlan(vlan_id="40", name="security", ports=["Gi1/0/4", "Gi1/0/48"]),
        ],
        diagnostics=[{"collector": "demo", "status": "success", "message": "Synthetic onboarding data"}],
    )


def _distribution_switch(name: str, number: int, access_names: list[str]) -> Switch:
    ports: list[Port] = []
    vlan_ports: list[str] = []
    for index, access_name in enumerate(access_names, start=1):
        port_name = f"Te1/1/{index}"
        vlan_ports.append(port_name)
        ports.append(
            _port(
                port_name,
                f"Downlink to {access_name}",
                "up",
                None,
                [f"02:00:00:10:{number:02x}:{index:02x}"],
                speed=10000,
                neighbor=Neighbor(device=access_name, protocol="lldp", port="Gi1/0/48", capabilities=["bridge"]),
                role="network",
                is_trunk=True,
            )
        )
    ports.extend(
        [
            _port(
                "Te1/1/47",
                "Core uplink A",
                "up",
                None,
                [f"02:00:00:10:{number:02x}:47"],
                speed=10000,
                neighbor=Neighbor(device="core-sw1", protocol="lldp", port=f"Et1/{number}", capabilities=["bridge"]),
                role="network",
                output_errors=number,
                is_trunk=True,
            ),
            _port(
                "Te1/1/48",
                "Core uplink B",
                "up",
                None,
                [f"02:00:00:10:{number:02x}:48"],
                speed=10000,
                neighbor=Neighbor(device="core-sw2", protocol="lldp", port=f"Et1/{number}", capabilities=["bridge"]),
                role="network",
                is_trunk=True,
            ),
            _port("Gi1/0/10", f"Build server {number}", "up", "10", [f"02:00:00:00:10:{number:02x}"]),
        ]
    )
    return Switch(
        name=name,
        management_ip=f"192.0.2.{10 + number}",
        vendor="generic",
        platform="DemoSwitch Distribution 10G",
        serial_number=f"DEMODIST{number:03d}",
        os_version="demo-os distribution 4.1",
        uptime=f"{100 + number} days",
        ports=ports,
        vlans=[
            Vlan(vlan_id="10", name="servers", ports=["Gi1/0/10", "Te1/1/47", "Te1/1/48"]),
            Vlan(vlan_id="20", name="users", ports=vlan_ports + ["Te1/1/47", "Te1/1/48"]),
            Vlan(vlan_id="30", name="conference", ports=vlan_ports + ["Te1/1/47", "Te1/1/48"]),
            Vlan(vlan_id="40", name="security", ports=vlan_ports + ["Te1/1/47", "Te1/1/48"]),
        ],
        diagnostics=[{"collector": "demo", "status": "success", "message": "Synthetic onboarding data"}],
    )


def _core_switch(name: str, number: int, dist_names: list[str]) -> Switch:
    ports: list[Port] = []
    for index, dist_name in enumerate(dist_names, start=1):
        ports.append(
            _port(
                f"Et1/{index}",
                f"Distribution link to {dist_name}",
                "up",
                None,
                [f"02:00:00:ff:{number:02x}:{index:02x}"],
                speed=10000,
                neighbor=Neighbor(
                    device=dist_name,
                    protocol="lldp",
                    port=f"Te1/1/{46 + number}",
                    capabilities=["bridge"],
                ),
                role="network",
                is_trunk=True,
            )
        )
    ports.extend(
        [
            _port(
                "Et1/47",
                "Core peer link",
                "up",
                None,
                [f"02:00:00:ff:{number:02x}:47"],
                speed=10000,
                neighbor=Neighbor(
                    device="core-sw2" if name == "core-sw1" else "core-sw1",
                    protocol="lldp",
                    port="Et1/47",
                    capabilities=["bridge"],
                ),
                role="network",
                is_trunk=True,
            ),
            _port(
                "Et1/48",
                "Router handoff",
                "up",
                None,
                [f"02:00:00:ff:{number:02x}:48"],
                speed=10000,
                neighbor=Neighbor(device="edge-router1", protocol="cdp", port=f"Gi0/{number}", capabilities=["router"]),
                role="network",
                is_trunk=True,
            ),
        ]
    )
    return Switch(
        name=name,
        management_ip=f"192.0.2.{number}",
        vendor="generic",
        platform="DemoSwitch Core 40G",
        serial_number=f"DEMOCORE{number:03d}",
        os_version="demo-os core 5.0",
        uptime=f"{200 + number} days",
        ports=ports,
        vlans=[
            Vlan(vlan_id="10", name="servers", ports=[port.name for port in ports]),
            Vlan(vlan_id="20", name="users", ports=[port.name for port in ports]),
            Vlan(vlan_id="30", name="conference", ports=[port.name for port in ports]),
            Vlan(vlan_id="40", name="security", ports=[port.name for port in ports]),
        ],
        diagnostics=[{"collector": "demo", "status": "success", "message": "Synthetic onboarding data"}],
    )


def _switches() -> list[Switch]:
    access_groups = {
        "dist-sw1": ["access-sw1", "access-sw2"],
        "dist-sw2": ["access-sw3", "access-sw4"],
        "dist-sw3": ["access-sw5"],
    }
    switches: list[Switch] = [
        _core_switch("core-sw1", 1, list(access_groups)),
        _core_switch("core-sw2", 2, list(access_groups)),
    ]
    for index, (dist_name, access_names) in enumerate(access_groups.items(), start=1):
        switches.append(_distribution_switch(dist_name, index, access_names))
        for access_index, access_name in enumerate(access_names, start=1):
            switches.append(_access_switch(access_name, index * 10 + access_index, dist_name, f"Te1/1/{access_index}"))
    return switches


def _mac_entries() -> list[MacEntry]:
    entries: list[MacEntry] = []
    for number in [11, 12, 21, 22, 31]:
        switch_name = f"access-sw{len(entries) // 5 + 1}"
        entries.extend(
            [
                MacEntry(
                    f"02:00:00:00:20:{number:02x}",
                    f"198.51.100.{20 + number}",
                    f"desk-phone-{number}.example.test",
                    switch_name,
                    "Gi1/0/1",
                ),
                MacEntry(
                    f"02:00:00:00:21:{number:02x}",
                    f"198.51.100.{40 + number}",
                    f"workstation-{number}.example.test",
                    switch_name,
                    "Gi1/0/2",
                ),
                MacEntry(
                    f"02:00:00:00:30:{number:02x}",
                    f"198.51.100.{60 + number}",
                    f"conference-display-{number}.example.test",
                    switch_name,
                    "Gi1/0/3",
                ),
                MacEntry(
                    f"02:00:00:00:40:{number:02x}",
                    f"198.51.100.{80 + number}",
                    f"security-camera-{number}.example.test",
                    switch_name,
                    "Gi1/0/4",
                ),
                MacEntry(
                    f"02:00:00:00:22:{number:02x}",
                    f"198.51.100.{100 + number}",
                    f"unlabeled-workstation-{number}.example.test",
                    switch_name,
                    "Gi1/0/5",
                ),
            ]
        )
    for number in [1, 2, 3]:
        entries.append(
            MacEntry(
                f"02:00:00:00:10:{number:02x}",
                f"198.51.100.{10 + number}",
                f"build-server-{number}.example.test",
                f"dist-sw{number}",
                "Gi1/0/10",
            )
        )
    return entries


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
                "# The fixture renders 10 switches across core, distribution, and access platforms.",
                "destination_directory: docs/assets/onboarding/demo/output",
                "idlesince_directory: docs/assets/onboarding/demo/idlesince",
                "maclist_file: docs/assets/onboarding/demo/maclist.json",
                "history_directory: docs/assets/onboarding/demo/history",
                "collection_artifacts_directory: docs/assets/onboarding/demo/artifacts",
                "unused_after_days: 30",
                "switches:",
                "  - name: core-sw1",
                "    management_ip: 192.0.2.1",
                "    community: public",
                "  - name: core-sw2",
                "    management_ip: 192.0.2.2",
                "    community: public",
                "  - name: dist-sw1",
                "    management_ip: 192.0.2.11",
                "    community: public",
                "  - name: dist-sw2",
                "    management_ip: 192.0.2.12",
                "    community: public",
                "  - name: dist-sw3",
                "    management_ip: 192.0.2.13",
                "    community: public",
                "  - name: access-sw1",
                "    management_ip: 192.0.2.31",
                "    community: public",
                "  - name: access-sw2",
                "    management_ip: 192.0.2.32",
                "    community: public",
                "  - name: access-sw3",
                "    management_ip: 192.0.2.41",
                "    community: public",
                "  - name: access-sw4",
                "    management_ip: 192.0.2.42",
                "    community: public",
                "  - name: access-sw5",
                "    management_ip: 192.0.2.51",
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
