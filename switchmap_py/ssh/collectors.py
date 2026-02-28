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


def _collect_interface_output(session: SshSession, switch: SwitchConfig, timeout: int) -> str:
    profile = _vendor_profile(switch.vendor)
    if profile == "juniper":
        command = "show interfaces terse"
    elif profile == "fortiswitch":
        command = "get switch interface status"
    else:
        command = "show interfaces status"
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
                is_active=port.oper_status.lower() == "up",
                mac_count=0,
                oper_status=port.oper_status,
            )
        )
    return snapshots
