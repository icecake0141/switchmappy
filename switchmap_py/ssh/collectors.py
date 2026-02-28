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
    if value in {"notconnect", "down", "disabled"}:
        return "down"
    return value


def _parse_interface_status(text: str, switch: SwitchConfig) -> list[Port]:
    ports: list[Port] = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        lower = line.lower()
        if lower.startswith(("port ", "name ", "----")):
            continue
        parts = _WS_RE.split(line, maxsplit=2)
        if len(parts) < 2:
            continue
        name = parts[0]
        oper_status = _normalize_oper_status(parts[1])
        descr = parts[2] if len(parts) > 2 else ""
        ports.append(
            Port(
                name=name,
                descr=descr,
                admin_status="up",
                oper_status=oper_status,
                speed=None,
                vlan=None,
                macs=[],
                is_trunk=name in switch.trunk_ports,
            )
        )
    return ports


def collect_switch_state(switch: SwitchConfig, timeout: int) -> Switch:
    session = build_session(switch, timeout=timeout)
    ports: list[Port] = []
    try:
        output = session.run("show interfaces status", timeout=timeout)
        ports = _parse_interface_status(output, switch)
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
