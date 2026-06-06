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
        assert timeout in {3, 6}
        self.commands.append(command)
        if command in self.by_command:
            return self.by_command[command]
        return self.output


def _neighbor_devices(port) -> list[str]:
    return [neighbor.device for neighbor in port.neighbors]


def _neighbor_protocols(port) -> list[str]:
    return [neighbor.protocol for neighbor in port.neighbors]


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
            "show interfaces switchport": (
                "Name: Gi1/0/1\n"
                "Operational Mode: trunk\n"
                "Trunking Native Mode VLAN: 1 (default)\n"
                "Trunking VLANs Enabled: 10,20\n"
                "Name: Gi1/0/2\n"
                "Operational Mode: static access\n"
                "Access Mode VLAN: 20 (VLAN0020)\n"
                "Voice VLAN: none\n"
            ),
            "show lldp neighbors detail": "Local Intf: Gi1/0/1\nSystem Name: dist-sw1\n",
            "show interfaces counters errors": "Gi1/0/1 0 0 5 7 0 0",
            "show power inline": "Gi1/0/1 auto on 15.4 30.0",
            "show version": (
                "Cisco IOS Software, Version 17.12.1\n"
                "sw-ssh uptime is 2 weeks, 1 day\n"
                "Model number                    : C9300-24P\n"
                "System Serial Number            : FOC1234X1YZ\n"
            ),
        }
    )
    monkeypatch.setattr(collectors, "build_session", lambda *_args, **_kwargs: session)

    state = collectors.collect_switch_state(switch, timeout=3)
    assert session.commands == [
        "show interfaces status",
        "show mac address-table",
        "show vlan brief",
        "show interfaces switchport",
        "show lldp neighbors detail",
        "show interfaces counters errors",
        "show power inline",
        "show version",
    ]
    assert state.platform == "C9300-24P"
    assert state.serial_number == "FOC1234X1YZ"
    assert state.os_version == "17.12.1"
    assert state.uptime == "2 weeks, 1 day"
    assert len(state.ports) == 2
    assert state.ports[0].name == "Gi1/0/1"
    assert state.ports[0].descr == "Uplink-Core"
    assert state.ports[0].oper_status == "up"
    assert state.ports[0].is_trunk is True
    assert state.ports[0].vlan == "10"
    assert state.ports[0].duplex == "a-full"
    assert state.ports[0].speed == 1000
    assert state.ports[0].switchport_mode == "trunk"
    assert state.ports[0].native_vlan == "1 (default)"
    assert state.ports[0].allowed_vlans == "10,20"
    assert state.ports[0].macs == ["00:11:22:33:44:55"]
    assert _neighbor_devices(state.ports[0]) == ["dist-sw1"]
    assert _neighbor_protocols(state.ports[0]) == ["lldp"]
    assert state.ports[0].neighbor_summaries == ["dist-sw1 (LLDP)"]
    assert state.ports[0].input_errors == 7
    assert state.ports[0].output_errors == 5
    assert state.ports[0].poe_status == "on"
    assert state.ports[0].poe_power_w == 15.4
    assert state.ports[1].macs == []
    assert state.ports[1].oper_status == "down"
    assert state.ports[1].switchport_mode == "access"
    assert state.ports[1].access_vlan == "20 (VLAN0020)"


def test_parse_cisco_cdp_detail_keeps_entries_with_blank_lines():
    output = """
-------------------------
Device ID: switchmappy-sw2.switchmappy.local
Entry address(es):
  IP address: 192.168.128.236
Platform: Linux Unix,  Capabilities: Router Switch IGMP
Interface: Ethernet0/1,  Port ID (outgoing port): Ethernet0/1
Holdtime : 168 sec

Version :
Cisco IOS Software [IOSXE]

advertisement version: 2
Management address(es):
  IP address: 192.168.128.236

-------------------------
Device ID: switchmappy-sw2.switchmappy.local
Entry address(es):
  IP address: 192.168.128.236
Platform: Linux Unix,  Capabilities: Router Switch IGMP
Interface: Ethernet0/0,  Port ID (outgoing port): Ethernet0/0
Holdtime : 149 sec
"""

    neighbors = collectors._parse_cisco_cdp_neighbors_detail(output)

    assert [neighbor.device for neighbor in neighbors["et0/1"]] == ["switchmappy-sw2.switchmappy.local"]
    assert neighbors["et0/1"][0].port == "Ethernet0/1"
    assert neighbors["et0/1"][0].capabilities == ["router", "switch", "igmp"]
    assert [neighbor.device for neighbor in neighbors["et0/0"]] == ["switchmappy-sw2.switchmappy.local"]


def test_parse_cisco_switchport_extracts_operational_vlan_details():
    details = collectors._parse_cisco_switchport(
        "\n".join(
            [
                "Name: Gi1/0/1",
                "Operational Mode: trunk",
                "Trunking Native Mode VLAN: 99 (Native)",
                "Trunking VLANs Enabled: 10,20,30",
                "Name: Gi1/0/2",
                "Operational Mode: static access",
                "Access Mode VLAN: 20 (Users)",
                "Voice VLAN: 30 (Voice)",
            ]
        )
    )

    assert details["gi1/0/1"].mode == "trunk"
    assert details["gi1/0/1"].native_vlan == "99 (Native)"
    assert details["gi1/0/1"].allowed_vlans == "10,20,30"
    assert details["gi1/0/2"].mode == "access"
    assert details["gi1/0/2"].access_vlan == "20 (Users)"
    assert details["gi1/0/2"].voice_vlan == "30 (Voice)"


def test_parse_cisco_show_version_extracts_inventory():
    inventory = collectors._parse_cisco_show_version(
        "\n".join(
            [
                "Cisco IOS XE Software, Version 17.12.1",
                "edge-sw1 uptime is 1 week, 2 days",
                "Model number                    : C9300-24P",
                "System Serial Number            : FOC1234X1YZ",
            ]
        )
    )

    assert inventory.platform == "C9300-24P"
    assert inventory.serial_number == "FOC1234X1YZ"
    assert inventory.os_version == "17.12.1"
    assert inventory.uptime == "1 week, 2 days"


def test_parse_cisco_show_version_uses_image_name_when_model_is_absent():
    inventory = collectors._parse_cisco_show_version(
        "\n".join(
            [
                "Cisco IOS Software [IOSXE], Linux Software (X86_64BI_LINUX_L2-ADVENTERPRISEK9-M), Version 17.18.2",
                "edge-sw1 uptime is 3 hours, 25 minutes",
                "Processor board ID 2039822",
            ]
        )
    )

    assert inventory.platform == "X86_64BI_LINUX_L2-ADVENTERPRISEK9-M"
    assert inventory.serial_number == "2039822"
    assert inventory.os_version == "17.18.2"


def test_canonical_port_name_matches_cisco_short_and_long_forms():
    assert collectors._canonical_port_name("Ethernet0/1") == "et0/1"
    assert collectors._canonical_port_name("Et0/1") == "et0/1"
    assert collectors._canonical_port_name("GigabitEthernet1/0/1") == "gi1/0/1"
    assert collectors._canonical_port_name("Gi1/0/1") == "gi1/0/1"


def test_run_command_rejects_cisco_invalid_output():
    class InvalidSession:
        def run(self, _command: str, timeout: int) -> str:
            assert timeout == 3
            return 'Line has invalid autocommand "show power inline"'

    try:
        collectors._run_command(InvalidSession(), "show power inline", timeout=3)
    except SshError as exc:
        assert "invalid autocommand" in str(exc)
    else:
        raise AssertionError("Expected SshError")


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
            "show lldp neighbors detail": "Local Intf: Gi1/0/1\nSystem Name: access1\n",
            "show interfaces counters errors": "Gi1/0/1 0 0 1 2 0 0",
            "show power inline": "Gi1/0/1 auto on 5.0 30.0",
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
            assert timeout in {3, 6}
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
            assert timeout in {3, 6}
            self.commands.append(command)
            if command == "show interfaces status":
                return "Gi1/0/1 Uplink connected 10 full 1000 copper"
            if command == "show vlan brief":
                return "10 default active Gi1/0/1"
            raise SshError("mac command failed")

    session = PartialErrorSession()
    monkeypatch.setattr(collectors, "build_session", lambda *_args, **_kwargs: session)

    state = collectors.collect_switch_state(switch, timeout=3)
    assert session.commands == [
        "show interfaces status",
        "show mac address-table",
        "show vlan brief",
        "show interfaces switchport",
        "show lldp neighbors detail",
        "show cdp neighbors detail",
        "show interfaces counters errors",
        "show power inline",
        "show version",
    ]
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
            "show lldp neighbors": "ge-0/0/1 - aa:bb:cc:dd:ee:ff ge-0/0/48 dist-junos-1",
            'show interfaces extensive | match "Physical interface|Input errors|Output errors"': (
                "Physical interface: ge-0/0/1, Enabled, Physical link is Up\n"
                "Input errors: 3, Output drops: 0\n"
                "Output errors: 8, Carrier transitions: 1\n"
            ),
            "show poe interface": "ge-0/0/1 Enabled Delivering 7.2W class-4",
        }
    )
    monkeypatch.setattr(collectors, "build_session", lambda *_args, **_kwargs: session)

    state = collectors.collect_switch_state(switch, timeout=3)
    assert session.commands == [
        "show interfaces terse",
        "show ethernet-switching table",
        "show vlans",
        "show lldp neighbors",
        'show interfaces extensive | match "Physical interface|Input errors|Output errors"',
        "show poe interface",
    ]
    assert [port.name for port in state.ports] == ["ge-0/0/1", "ge-0/0/2"]
    assert state.ports[0].oper_status == "up"
    assert state.ports[0].macs == ["00:11:22:33:44:66"]
    assert state.ports[0].vlan == "10"
    assert _neighbor_devices(state.ports[0]) == ["dist-junos-1"]
    assert _neighbor_protocols(state.ports[0]) == ["lldp"]
    assert state.ports[0].input_errors == 3
    assert state.ports[0].output_errors == 8
    assert state.ports[0].poe_status == "delivering 7.2w"
    assert state.ports[0].poe_power_w == 7.2
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
            "show interfaces switchport": "Name: Et1\nOperational Mode: trunk\nTrunking VLANs Enabled: 10\n",
            "show lldp neighbors detail": "Local Intf: Et1\nSystem Name: leaf-1\n",
            "show interfaces counters errors": "Et1 0 0 9 4 0 0",
            "show power inline": "Et1 auto on 3.5 30.0",
            "show version": "Cisco vEOS, Version 4.31.1F\nProcessor board ID JPE00000000\n",
        }
    )
    monkeypatch.setattr(collectors, "build_session", lambda *_args, **_kwargs: session)

    state = collectors.collect_switch_state(switch, timeout=3)
    assert session.commands == [
        "show interfaces status",
        "show mac address-table",
        "show vlan brief",
        "show interfaces switchport",
        "show lldp neighbors detail",
        "show interfaces counters errors",
        "show power inline",
        "show version",
    ]
    assert [port.name for port in state.ports] == ["Et1"]
    assert state.ports[0].oper_status == "up"
    assert state.ports[0].macs == ["00:11:22:33:44:66"]
    assert _neighbor_devices(state.ports[0]) == ["leaf-1"]
    assert _neighbor_protocols(state.ports[0]) == ["lldp"]
    assert state.ports[0].input_errors == 4
    assert state.ports[0].output_errors == 9
    assert state.ports[0].poe_status == "on"
    assert state.ports[0].poe_power_w == 3.5
    assert state.ports[0].switchport_mode == "trunk"


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
            "Portname Status Tpid Vlan Duplex Speed Flags Discard",
            "port1 up 8100 10 full 1000M , , none",
            "port2 down 8100 10 full 100M , , none",
        ]
    )
    session = StubSession(
        by_command={
            "diagnose switch physical-ports summary": status_output,
            "diagnose switch mac-address list": "MAC: 00:11:22:33:44:77\tVLAN: 10 Port: port1(port-id 1)",
            "diagnose switch vlan list": "10 port1 port2",
            "get switch lldp neighbors-detail": "port1 aa:bb:cc:dd:ee:ff port48 fsw-core-1",
            "diagnose switch physical-ports error-counters": "port1 2 3\nport2 0 1",
            "get switch poe inline-status": "port1 Enabled Delivering 8.8W\nport2 Enabled Off 0.0W",
            "get system status": "\n".join(
                [
                    "fortiswitch-edge # Version: FortiSwitch-108D-VM v7.2.0,build4746,220621 (Interim)",
                    "Serial-Number: S108DVIUL-MKIA2D",
                ]
            ),
        }
    )
    monkeypatch.setattr(collectors, "build_session", lambda *_args, **_kwargs: session)

    state = collectors.collect_switch_state(switch, timeout=3)
    assert session.commands == [
        "diagnose switch physical-ports summary",
        "diagnose switch mac-address list",
        "diagnose switch vlan list",
        "get switch lldp neighbors-detail",
        "diagnose switch physical-ports error-counters",
        "get switch poe inline-status",
        "get system status",
    ]
    assert [port.name for port in state.ports] == ["port1", "port2"]
    assert state.ports[0].oper_status == "up"
    assert state.ports[0].speed == 1000
    assert state.ports[0].macs == ["00:11:22:33:44:77"]
    assert state.ports[0].vlan == "10"
    assert state.ports[0].switchport_mode == "access"
    assert state.ports[0].access_vlan == "10"
    assert _neighbor_devices(state.ports[0]) == ["fsw-core-1"]
    assert _neighbor_protocols(state.ports[0]) == ["lldp"]
    assert state.ports[0].input_errors == 2
    assert state.ports[0].output_errors == 3
    assert state.ports[0].poe_status == "delivering"
    assert state.ports[0].poe_power_w == 8.8
    assert state.ports[1].oper_status == "down"
    assert state.ports[1].vlan == "10"
    assert state.ports[1].switchport_mode == "access"
    assert state.ports[1].access_vlan == "10"
    assert state.ports[1].input_errors == 0
    assert state.ports[1].output_errors == 1
    assert state.ports[1].poe_status == "off"
    assert state.ports[1].poe_power_w == 0.0
    assert state.platform == "FortiSwitch-108D-VM"
    assert state.os_version == "FortiSwitch-108D-VM v7.2.0,build4746,220621 (Interim)"
    assert state.serial_number == "S108DVIUL-MKIA2D"


def test_collect_switch_state_parses_cml_fortiswitch_vm_output(monkeypatch):
    switch = SwitchConfig(
        name="sw-forti",
        management_ip="192.0.2.80",
        vendor="fortiswitch",
        collection_method="ssh",
        ssh_username="ops",
        ssh_password="pw",
        trunk_ports=["port1"],
    )
    session = StubSession(
        by_command={
            "diagnose switch physical-ports summary": "\n".join(
                [
                    "  Portname    Status  Tpid  Vlan  Duplex  Speed  Flags         Discard",
                    "  __________  ______  ____  ____  ______  _____  ____________  _________",
                    "  port1       up      8100  1     full    100M   QS,  ,        none",
                    "  port2       down    8100  1     full    -        ,  ,        none",
                    "  internal    up      8100  1     full    100M     ,  ,        none",
                ]
            ),
            "diagnose switch mac-address list": "\n".join(
                [
                    "MAC: 52:54:00:00:10:10\tVLAN: 1 Port: port1(port-id 1)",
                    "  Flags: 0x13000000 [ dynamic age forward-dst forward-src ]",
                    "MAC: 36:f0:e1:7f:00:01\tVLAN: 1 Port: internal(port-id 9)",
                ]
            ),
            "diagnose switch vlan list": "\n".join(
                [
                    "  VlanId  Ports",
                    "  ______  ___________________________________________________",
                    "  1       port1 port2 port3 port4 port5 port6 port7 port8 internal",
                    "  10      port1",
                ]
            ),
            "get switch lldp neighbors-detail": "\n".join(
                [
                    "Neighbor learned on port port1 by LLDP protocol",
                    "System Name: edge-sw3.switchmappy.local",
                    "Port ID: Et0/3 (ifname)",
                ]
            ),
            "diagnose switch physical-ports error-counters": "command parse error before 'error-counters'",
            "get switch poe inline-status": "command parse error before 'inline-status'",
            "get system status": "\n".join(
                [
                    "Version: FortiSwitch-108D-VM v7.2.0,build4746,220621 (Interim)",
                    "Serial-Number: S108DVIUL-MKIA2D",
                ]
            ),
        }
    )
    monkeypatch.setattr(collectors, "build_session", lambda *_args, **_kwargs: session)

    state = collectors.collect_switch_state(switch, timeout=3)

    assert [port.name for port in state.ports] == ["port1", "port2", "internal"]
    assert state.ports[0].oper_status == "up"
    assert state.ports[0].speed == 100
    assert state.ports[0].descr == ""
    assert state.ports[0].vlan == "1"
    assert state.ports[0].switchport_mode == "trunk"
    assert state.ports[0].access_vlan == "1"
    assert state.ports[0].allowed_vlans == "1,10"
    assert state.ports[0].macs == ["52:54:00:00:10:10"]
    assert state.ports[0].is_trunk is True
    assert _neighbor_devices(state.ports[0]) == ["edge-sw3.switchmappy.local"]
    assert _neighbor_protocols(state.ports[0]) == ["lldp"]
    assert state.ports[1].oper_status == "down"
    assert state.ports[2].macs == ["36:f0:e1:7f:00:01"]
    assert state.platform == "FortiSwitch-108D-VM"
    assert state.os_version == "FortiSwitch-108D-VM v7.2.0,build4746,220621 (Interim)"
    assert state.serial_number == "S108DVIUL-MKIA2D"


def test_collect_switch_state_falls_back_to_cdp_neighbors(monkeypatch):
    switch = SwitchConfig(
        name="sw-cisco",
        management_ip="192.0.2.90",
        vendor="cisco",
        collection_method="ssh",
        ssh_username="ops",
        ssh_password="pw",
    )

    class CdpFallbackSession:
        def __init__(self) -> None:
            self.commands: list[str] = []

        def run(self, command: str, timeout: int) -> str:
            assert timeout in {3, 6}
            self.commands.append(command)
            if command == "show interfaces status":
                return "Gi1/0/1 Uplink connected 10 full 1000 copper"
            if command == "show mac address-table":
                return "10 00:11:22:33:44:55 dynamic Gi1/0/1"
            if command == "show vlan brief":
                return "10 default active Gi1/0/1"
            if command == "show interfaces switchport":
                return "Name: Gi1/0/1\nOperational Mode: static access\nAccess Mode VLAN: 10 (default)\n"
            if command == "show lldp neighbors detail":
                raise SshError("lldp unsupported")
            if command == "show cdp neighbors detail":
                return "Device ID: cdp-edge-1\nInterface: Gi1/0/1, Port ID (outgoing port): Gi0/1\n"
            if command == "show interfaces counters errors":
                return "Gi1/0/1 0 0 4 6 0 0"
            if command == "show power inline":
                return "Gi1/0/1 auto on 11.2 30.0"
            if command == "show version":
                return "Cisco IOS Software, Version 17.9.4\nProcessor board ID FOCEDGE1\n"
            raise AssertionError(f"unexpected command: {command}")

    session = CdpFallbackSession()
    monkeypatch.setattr(collectors, "build_session", lambda *_args, **_kwargs: session)

    state = collectors.collect_switch_state(switch, timeout=3)
    assert session.commands == [
        "show interfaces status",
        "show mac address-table",
        "show vlan brief",
        "show interfaces switchport",
        "show lldp neighbors detail",
        "show cdp neighbors detail",
        "show interfaces counters errors",
        "show power inline",
        "show version",
    ]
    assert [port.name for port in state.ports] == ["Gi1/0/1"]
    assert _neighbor_devices(state.ports[0]) == ["cdp-edge-1"]
    assert _neighbor_protocols(state.ports[0]) == ["cdp"]
    assert state.ports[0].input_errors == 6
    assert state.ports[0].output_errors == 4
    assert state.ports[0].poe_status == "on"
    assert state.ports[0].poe_power_w == 11.2
