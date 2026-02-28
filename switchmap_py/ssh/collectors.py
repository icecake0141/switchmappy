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

import logging
import re

from switchmap_py.config import SwitchConfig
from switchmap_py.model.port import Port
from switchmap_py.model.switch import Switch
from switchmap_py.snmp.collectors import PortSnapshot
from switchmap_py.ssh.session import SshConfig, SshError, SshSession

logger = logging.getLogger(__name__)

_WS_RE = re.compile(r"\s+")
_STATUS_TOKENS = {
    "connected",
    "notconnect",
    "disabled",
    "err-disabled",
    "inactive",
    "up",
    "down",
}
_MAC_RE = re.compile(r"^(?:[0-9a-fA-F]{2}[:.-]?){6}$")
_VLAN_ID_RE = re.compile(r"^\d{1,4}$")


def _vendor_profile(vendor: str) -> str:
    value = vendor.lower()
    if "juniper" in value:
        return "juniper"
    if "fortinet" in value or "fortiswitch" in value:
        return "fortiswitch"
    if "arista" in value:
        return "arista"
    return "cisco_like"


def build_session(switch: SwitchConfig, timeout: int) -> SshSession:
    return SshSession(
        SshConfig(
            hostname=switch.management_ip,
            port=switch.ssh_port,
            username=switch.ssh_username or "",
            password=switch.ssh_password,
            private_key=switch.ssh_private_key,
            connect_timeout=timeout,
        )
    )


def _normalize_oper_status(status: str) -> str:
    value = status.lower()
    if value in {"connected", "up"}:
        return "up"
    if value in {"notconnect", "down", "disabled", "err-disabled", "inactive"}:
        return "down"
    return value


def _parse_speed(token: str) -> int | None:
    match = re.search(r"(\d+)$", token)
    if not match:
        return None
    try:
        return int(match.group(1))
    except ValueError:
        return None


def _normalize_mac(value: str) -> str | None:
    token = value.strip().lower().replace("-", "").replace(":", "").replace(".", "")
    if len(token) != 12 or not all(ch in "0123456789abcdef" for ch in token):
        return None
    return ":".join(token[index : index + 2] for index in range(0, 12, 2))


def _canonical_port_name(value: str) -> str:
    return value.strip().lower().split(".")[0]


def _parse_cisco_interface_status(text: str, switch: SwitchConfig) -> list[Port]:
    ports: list[Port] = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        lower = line.lower()
        if lower.startswith(("port ", "name ", "----")):
            continue
        tokens = _WS_RE.split(line)
        if len(tokens) < 2:
            continue
        name = tokens[0]
        status_index = -1
        for index, token in enumerate(tokens[1:], start=1):
            if token.lower() in _STATUS_TOKENS:
                status_index = index
                break
        if status_index < 1:
            continue
        descr = " ".join(tokens[1:status_index]) if status_index > 1 else ""
        raw_status = tokens[status_index]
        oper_status = _normalize_oper_status(raw_status)
        admin_status = "down" if raw_status.lower() in {"disabled", "err-disabled"} else "up"
        vlan = None
        if status_index + 1 < len(tokens):
            vlan = tokens[status_index + 1]
        speed = None
        if status_index + 3 < len(tokens):
            speed = _parse_speed(tokens[status_index + 3])
        ports.append(
            Port(
                name=name,
                descr=descr,
                admin_status=admin_status,
                oper_status=oper_status,
                speed=speed,
                vlan=vlan,
                macs=[],
                is_trunk=name in switch.trunk_ports,
            )
        )
    return ports


def _parse_juniper_interfaces_terse(text: str, switch: SwitchConfig) -> list[Port]:
    ports: list[Port] = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        lower = line.lower()
        if lower.startswith(("interface", "physical interface", "---")):
            continue
        tokens = _WS_RE.split(line)
        if len(tokens) < 3:
            continue
        name = tokens[0]
        if "." in name:
            # Skip logical interfaces and focus on physical ports.
            continue
        admin_status = _normalize_oper_status(tokens[1])
        oper_status = _normalize_oper_status(tokens[2])
        ports.append(
            Port(
                name=name,
                descr="",
                admin_status=admin_status,
                oper_status=oper_status,
                speed=None,
                vlan=None,
                macs=[],
                is_trunk=name in switch.trunk_ports,
            )
        )
    return ports


def _parse_fortiswitch_interface_status(text: str, switch: SwitchConfig) -> list[Port]:
    ports: list[Port] = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        lower = line.lower()
        if lower.startswith(("port ", "name ", "interface ", "----")):
            continue
        tokens = _WS_RE.split(line)
        if len(tokens) < 2:
            continue
        name = tokens[0]
        if not re.match(r"^(port|internal)\d+", name.lower()):
            continue
        raw_status = tokens[1]
        oper_status = _normalize_oper_status(raw_status)
        admin_status = "down" if oper_status == "down" else "up"
        speed = _parse_speed(tokens[2]) if len(tokens) > 2 else None
        descr = " ".join(tokens[3:]) if len(tokens) > 3 else ""
        ports.append(
            Port(
                name=name,
                descr=descr,
                admin_status=admin_status,
                oper_status=oper_status,
                speed=speed,
                vlan=None,
                macs=[],
                is_trunk=name in switch.trunk_ports,
            )
        )
    return ports


def _parse_cisco_like_mac_table(text: str) -> dict[str, set[str]]:
    macs_by_port: dict[str, set[str]] = {}
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        lower = line.lower()
        if lower.startswith(("vlan", "----", "legend", "total", "mac address")):
            continue
        tokens = _WS_RE.split(line)
        mac = next((tok for tok in tokens if _MAC_RE.match(tok)), None)
        if not mac:
            continue
        port_token = tokens[-1]
        for port_name in port_token.split(","):
            canonical = _canonical_port_name(port_name)
            if not canonical:
                continue
            normalized_mac = _normalize_mac(mac)
            if not normalized_mac:
                continue
            macs_by_port.setdefault(canonical, set()).add(normalized_mac)
    return macs_by_port


def _parse_juniper_mac_table(text: str) -> dict[str, set[str]]:
    macs_by_port: dict[str, set[str]] = {}
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        lower = line.lower()
        if lower.startswith(("mac", "vlan", "ethernet switching", "name", "---")):
            continue
        tokens = _WS_RE.split(line)
        mac = next((tok for tok in tokens if _MAC_RE.match(tok)), None)
        if not mac:
            continue
        interface = next((tok for tok in tokens if "/" in tok), "")
        canonical = _canonical_port_name(interface)
        normalized_mac = _normalize_mac(mac)
        if canonical and normalized_mac:
            macs_by_port.setdefault(canonical, set()).add(normalized_mac)
    return macs_by_port


def _parse_fortiswitch_mac_table(text: str) -> dict[str, set[str]]:
    macs_by_port: dict[str, set[str]] = {}
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        lower = line.lower()
        if lower.startswith(("vlan", "mac", "----")):
            continue
        tokens = _WS_RE.split(line)
        if len(tokens) < 3:
            continue
        mac = next((tok for tok in tokens if _MAC_RE.match(tok)), None)
        if not mac:
            continue
        port_token = tokens[-1]
        canonical = _canonical_port_name(port_token)
        normalized_mac = _normalize_mac(mac)
        if canonical and normalized_mac:
            macs_by_port.setdefault(canonical, set()).add(normalized_mac)
    return macs_by_port


def _parse_cisco_vlan_brief(text: str) -> dict[str, str]:
    vlan_by_port: dict[str, str] = {}
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        lower = line.lower()
        if lower.startswith(("vlan", "----")):
            continue
        tokens = _WS_RE.split(line)
        if len(tokens) < 4:
            continue
        vlan_id = tokens[0]
        if not _VLAN_ID_RE.match(vlan_id):
            continue
        ports_token = tokens[-1]
        for port_name in ports_token.split(","):
            canonical = _canonical_port_name(port_name)
            if canonical:
                vlan_by_port[canonical] = vlan_id
    return vlan_by_port


def _parse_juniper_vlans(text: str) -> dict[str, str]:
    vlan_by_port: dict[str, str] = {}
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        lower = line.lower()
        if lower.startswith(("name", "---")):
            continue
        tokens = _WS_RE.split(line)
        vlan_id = next((tok for tok in tokens if _VLAN_ID_RE.match(tok)), None)
        if not vlan_id:
            continue
        for token in tokens:
            if "/" not in token:
                continue
            for candidate in token.split(","):
                canonical = _canonical_port_name(candidate)
                if canonical:
                    vlan_by_port[canonical] = vlan_id
    return vlan_by_port


def _parse_fortiswitch_vlans(text: str) -> dict[str, str]:
    vlan_by_port: dict[str, str] = {}
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        lower = line.lower()
        if lower.startswith(("vlan", "----", "id ")):
            continue
        tokens = _WS_RE.split(line)
        vlan_id = next((tok for tok in tokens if _VLAN_ID_RE.match(tok)), None)
        if not vlan_id:
            continue
        for token in tokens:
            for candidate in token.split(","):
                if not re.match(r"^(port|internal)\d+", candidate.lower()):
                    continue
                canonical = _canonical_port_name(candidate)
                if canonical:
                    vlan_by_port[canonical] = vlan_id
    return vlan_by_port


def _collect_interface_output(session: SshSession, switch: SwitchConfig, timeout: int) -> str:
    profile = _vendor_profile(switch.vendor)
    if profile == "juniper":
        command = "show interfaces terse"
    elif profile == "fortiswitch":
        command = "get switch interface status"
    else:
        command = "show interfaces status"
    return session.run(command, timeout=timeout)


def _collect_mac_output(session: SshSession, switch: SwitchConfig, timeout: int) -> str:
    profile = _vendor_profile(switch.vendor)
    if profile == "juniper":
        command = "show ethernet-switching table"
    elif profile == "fortiswitch":
        command = "get switch mac-address-table"
    else:
        command = "show mac address-table"
    return session.run(command, timeout=timeout)


def _collect_vlan_output(session: SshSession, switch: SwitchConfig, timeout: int) -> str:
    profile = _vendor_profile(switch.vendor)
    if profile == "juniper":
        command = "show vlans"
    elif profile == "fortiswitch":
        command = "show switch vlan"
    else:
        command = "show vlan brief"
    return session.run(command, timeout=timeout)


def collect_switch_state(switch: SwitchConfig, timeout: int) -> Switch:
    session = build_session(switch, timeout=timeout)
    ports: list[Port] = []
    try:
        output = _collect_interface_output(session, switch, timeout=timeout)
        profile = _vendor_profile(switch.vendor)
        if profile == "juniper":
            ports = _parse_juniper_interfaces_terse(output, switch)
        elif profile == "fortiswitch":
            ports = _parse_fortiswitch_interface_status(output, switch)
        else:
            ports = _parse_cisco_interface_status(output, switch)
        try:
            mac_output = _collect_mac_output(session, switch, timeout=timeout)
            if profile == "juniper":
                macs_by_port = _parse_juniper_mac_table(mac_output)
            elif profile == "fortiswitch":
                macs_by_port = _parse_fortiswitch_mac_table(mac_output)
            else:
                macs_by_port = _parse_cisco_like_mac_table(mac_output)
            for port in ports:
                canonical = _canonical_port_name(port.name)
                port.macs = sorted(macs_by_port.get(canonical, set()))
        except SshError:
            logger.warning(
                "SSH MAC collection command failed for switch %s; continuing without MAC table.",
                switch.name,
                exc_info=True,
            )
        try:
            vlan_output = _collect_vlan_output(session, switch, timeout=timeout)
            if profile == "juniper":
                vlan_by_port = _parse_juniper_vlans(vlan_output)
            elif profile == "fortiswitch":
                vlan_by_port = _parse_fortiswitch_vlans(vlan_output)
            else:
                vlan_by_port = _parse_cisco_vlan_brief(vlan_output)
            for port in ports:
                if port.vlan:
                    continue
                canonical = _canonical_port_name(port.name)
                mapped_vlan = vlan_by_port.get(canonical)
                if mapped_vlan:
                    port.vlan = mapped_vlan
        except SshError:
            logger.warning(
                "SSH VLAN collection command failed for switch %s; continuing without VLAN table.",
                switch.name,
                exc_info=True,
            )
    except SshError:
        logger.warning(
            "SSH collection command failed for switch %s; returning empty switch state.",
            switch.name,
            exc_info=True,
        )
    return Switch(
        name=switch.name,
        management_ip=switch.management_ip,
        vendor=switch.vendor,
        ports=ports,
        vlans=[],
    )


def collect_port_snapshots(switch: SwitchConfig, timeout: int) -> list[PortSnapshot]:
    state = collect_switch_state(switch, timeout=timeout)
    snapshots: list[PortSnapshot] = []
    for port in state.ports:
        snapshots.append(
            PortSnapshot(
                name=port.name,
                is_active=port.is_active,
                mac_count=len(port.macs),
                oper_status=port.oper_status,
            )
        )
    return snapshots
