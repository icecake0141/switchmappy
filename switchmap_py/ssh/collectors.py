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
from switchmap_py.model.neighbor import Neighbor
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
_PORT_HINT_RE = re.compile(r"^(?:gi|fa|te|eth|et|ge|xe|ae|po|port|internal)\d", re.IGNORECASE)
_INTEGER_RE = re.compile(r"^\d+$")
_POWER_RE = re.compile(r"(\d+(?:\.\d+)?)\s*w?$", re.IGNORECASE)

_DEFAULT_COMMAND_RETRIES = 0
_PRIMARY_COMMAND_RETRIES = 1
_SLOW_COMMAND_TIMEOUT_FACTOR = 2


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


def _looks_like_port(token: str) -> bool:
    value = token.strip().lower().rstrip(",")
    if not value:
        return False
    return bool(_PORT_HINT_RE.match(value) or "/" in value)


def _extract_neighbor_name(token: str) -> str | None:
    value = token.strip().strip(",")
    if not value:
        return None
    if _looks_like_port(value):
        return None
    if _VLAN_ID_RE.match(value):
        return None
    if _MAC_RE.match(value):
        return None
    if value in {"-", "--"}:
        return None
    return value


def _run_command(session: SshSession, command: str, timeout: int, retries: int = _DEFAULT_COMMAND_RETRIES) -> str:
    tries = max(1, retries + 1)
    effective_timeout = timeout * _SLOW_COMMAND_TIMEOUT_FACTOR if "extensive" in command else timeout
    last_error: SshError | None = None
    for _ in range(tries):
        try:
            return session.run(command, timeout=effective_timeout)
        except SshError as exc:
            last_error = exc
    if last_error:
        raise last_error
    raise SshError(f"failed to run command: {command}")


def _add_neighbor(
    table: dict[str, list[Neighbor]],
    local_port: str,
    device: str,
    protocol: str,
    remote_port: str | None = None,
) -> None:
    neighbors = table.setdefault(local_port, [])
    key = (device.lower(), (remote_port or "").lower(), protocol.lower())
    if any((n.device.lower(), (n.port or "").lower(), n.protocol.lower()) == key for n in neighbors):
        return
    neighbors.append(Neighbor(device=device, protocol=protocol, port=remote_port))


def _parse_neighbor_table(text: str, protocol: str) -> dict[str, list[Neighbor]]:
    neighbors_by_port: dict[str, list[Neighbor]] = {}
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        lower = line.lower()
        if lower.startswith(("local", "interface", "chassis", "----", "capability", "total", "name")):
            continue
        tokens = _WS_RE.split(line)
        if len(tokens) < 2:
            continue
        local_token = next((tok for tok in tokens if _looks_like_port(tok)), "")
        local = _canonical_port_name(local_token)
        if not local:
            continue
        remote_port = None
        for token in reversed(tokens):
            candidate = token.strip(",")
            if not _looks_like_port(candidate):
                continue
            if _canonical_port_name(candidate) == local:
                continue
            remote_port = candidate
            break
        neighbor = None
        for token in reversed(tokens):
            candidate = _extract_neighbor_name(token)
            if candidate:
                neighbor = candidate
                break
        if neighbor:
            _add_neighbor(neighbors_by_port, local, neighbor, protocol, remote_port=remote_port)
    return neighbors_by_port


def _parse_cisco_lldp_neighbors_detail(text: str) -> dict[str, list[Neighbor]]:
    neighbors_by_port: dict[str, list[Neighbor]] = {}
    current_local: str | None = None
    current_neighbor: str | None = None
    current_remote_port: str | None = None
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            if current_local and current_neighbor:
                _add_neighbor(
                    neighbors_by_port,
                    current_local,
                    current_neighbor,
                    "lldp",
                    remote_port=current_remote_port,
                )
            current_local = None
            current_neighbor = None
            current_remote_port = None
            continue
        lower = line.lower()
        if lower.startswith("local intf:") or lower.startswith("local interface:"):
            value = line.split(":", 1)[1].strip()
            current_local = _canonical_port_name(value)
            continue
        if lower.startswith("system name:"):
            current_neighbor = line.split(":", 1)[1].strip()
            continue
        if lower.startswith("port id:"):
            current_remote_port = line.split(":", 1)[1].strip()
            continue
    if current_local and current_neighbor:
        _add_neighbor(neighbors_by_port, current_local, current_neighbor, "lldp", remote_port=current_remote_port)
    return neighbors_by_port


def _parse_cisco_cdp_neighbors_detail(text: str) -> dict[str, list[Neighbor]]:
    neighbors_by_port: dict[str, list[Neighbor]] = {}
    current_local: str | None = None
    current_neighbor: str | None = None
    current_remote_port: str | None = None
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            if current_local and current_neighbor:
                _add_neighbor(
                    neighbors_by_port,
                    current_local,
                    current_neighbor,
                    "cdp",
                    remote_port=current_remote_port,
                )
            current_local = None
            current_neighbor = None
            current_remote_port = None
            continue
        lower = line.lower()
        if lower.startswith("device id:"):
            current_neighbor = line.split(":", 1)[1].strip()
            continue
        if lower.startswith("interface:"):
            rhs = line.split(":", 1)[1]
            value = rhs.split(",", 1)[0].strip()
            current_local = _canonical_port_name(value)
            if "port id" in lower:
                tail = rhs.split("Port ID", 1)[1]
                current_remote_port = tail.split(":", 1)[1].strip() if ":" in tail else None
            continue
    if current_local and current_neighbor:
        _add_neighbor(neighbors_by_port, current_local, current_neighbor, "cdp", remote_port=current_remote_port)
    return neighbors_by_port


def _parse_cisco_like_error_counters(text: str) -> dict[str, tuple[int, int]]:
    errors_by_port: dict[str, tuple[int, int]] = {}
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        lower = line.lower()
        if lower.startswith(("port", "interface", "----")):
            continue
        tokens = _WS_RE.split(line)
        if len(tokens) < 3:
            continue
        port_token = tokens[0]
        if not _looks_like_port(port_token):
            continue
        counters = [int(token) for token in tokens[1:] if _INTEGER_RE.match(token)]
        if len(counters) >= 4:
            # Common Cisco/Arista layout: Align-Err FCS-Err Xmit-Err Rcv-Err ...
            output_errors = counters[2]
            input_errors = counters[3]
        elif len(counters) >= 2:
            output_errors = counters[0]
            input_errors = counters[1]
        else:
            continue
        errors_by_port[_canonical_port_name(port_token)] = (input_errors, output_errors)
    return errors_by_port


def _parse_juniper_error_counters(text: str) -> dict[str, tuple[int, int]]:
    errors_by_port: dict[str, tuple[int, int]] = {}
    current_port: str | None = None
    input_errors: int | None = None
    output_errors: int | None = None
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        lower = line.lower()
        if lower.startswith("physical interface:"):
            if current_port and input_errors is not None and output_errors is not None:
                errors_by_port[current_port] = (input_errors, output_errors)
            port_name = line.split(":", 1)[1].split(",", 1)[0].strip()
            current_port = _canonical_port_name(port_name)
            input_errors = None
            output_errors = None
            continue
        if lower.startswith("input errors:"):
            match = re.search(r"input errors:\s*(\d+)", line, flags=re.IGNORECASE)
            if match:
                input_errors = int(match.group(1))
            continue
        if lower.startswith("output errors:"):
            match = re.search(r"output errors:\s*(\d+)", line, flags=re.IGNORECASE)
            if match:
                output_errors = int(match.group(1))
            continue
    if current_port and input_errors is not None and output_errors is not None:
        errors_by_port[current_port] = (input_errors, output_errors)
    return errors_by_port


def _parse_fortiswitch_error_counters(text: str) -> dict[str, tuple[int, int]]:
    errors_by_port: dict[str, tuple[int, int]] = {}
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        lower = line.lower()
        if lower.startswith(("port ", "interface ", "name ", "----")):
            continue
        tokens = _WS_RE.split(line)
        if len(tokens) < 3:
            continue
        port_token = tokens[0]
        if not re.match(r"^(port|internal)\d+", port_token.lower()):
            continue
        counters = [int(token) for token in tokens[1:] if _INTEGER_RE.match(token)]
        if len(counters) < 2:
            continue
        errors_by_port[_canonical_port_name(port_token)] = (counters[0], counters[1])
    return errors_by_port


def _parse_power_value(token: str) -> float | None:
    match = _POWER_RE.search(token.strip())
    if not match:
        return None
    try:
        return float(match.group(1))
    except ValueError:
        return None


def _parse_cisco_like_poe(text: str) -> dict[str, tuple[str, float | None]]:
    poe_by_port: dict[str, tuple[str, float | None]] = {}
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        lower = line.lower()
        if lower.startswith(("interface", "port", "----", "available")):
            continue
        tokens = _WS_RE.split(line)
        if len(tokens) < 3:
            continue
        port_token = tokens[0]
        if not _looks_like_port(port_token):
            continue
        status = tokens[2].lower()
        power = None
        for token in tokens[3:]:
            parsed = _parse_power_value(token)
            if parsed is not None:
                power = parsed
                break
        poe_by_port[_canonical_port_name(port_token)] = (status, power)
    return poe_by_port


def _parse_juniper_poe(text: str) -> dict[str, tuple[str, float | None]]:
    poe_by_port: dict[str, tuple[str, float | None]] = {}
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        lower = line.lower()
        if lower.startswith(("interface", "----")):
            continue
        tokens = _WS_RE.split(line)
        if len(tokens) < 3:
            continue
        port_token = tokens[0]
        if "/" not in port_token:
            continue
        status = " ".join(tokens[2:4]).lower() if len(tokens) > 3 else tokens[2].lower()
        power = None
        for token in tokens[1:]:
            if "w" not in token.lower():
                continue
            parsed = _parse_power_value(token)
            if parsed is not None:
                power = parsed
                break
        poe_by_port[_canonical_port_name(port_token)] = (status, power)
    return poe_by_port


def _parse_fortiswitch_poe(text: str) -> dict[str, tuple[str, float | None]]:
    poe_by_port: dict[str, tuple[str, float | None]] = {}
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        lower = line.lower()
        if lower.startswith(("port ", "name ", "interface ", "----")):
            continue
        tokens = _WS_RE.split(line)
        if len(tokens) < 3:
            continue
        port_token = tokens[0]
        if not re.match(r"^(port|internal)\d+", port_token.lower()):
            continue
        status = tokens[2].lower()
        power = None
        for token in tokens[3:]:
            parsed = _parse_power_value(token)
            if parsed is not None:
                power = parsed
                break
        poe_by_port[_canonical_port_name(port_token)] = (status, power)
    return poe_by_port


def _collect_interface_output(session: SshSession, switch: SwitchConfig, timeout: int) -> str:
    profile = _vendor_profile(switch.vendor)
    if profile == "juniper":
        command = "show interfaces terse"
    elif profile == "fortiswitch":
        command = "get switch interface status"
    else:
        command = "show interfaces status"
    return _run_command(session, command, timeout=timeout, retries=_PRIMARY_COMMAND_RETRIES)


def _collect_mac_output(session: SshSession, switch: SwitchConfig, timeout: int) -> str:
    profile = _vendor_profile(switch.vendor)
    if profile == "juniper":
        command = "show ethernet-switching table"
    elif profile == "fortiswitch":
        command = "get switch mac-address-table"
    else:
        command = "show mac address-table"
    return _run_command(session, command, timeout=timeout)


def _collect_vlan_output(session: SshSession, switch: SwitchConfig, timeout: int) -> str:
    profile = _vendor_profile(switch.vendor)
    if profile == "juniper":
        command = "show vlans"
    elif profile == "fortiswitch":
        command = "show switch vlan"
    else:
        command = "show vlan brief"
    return _run_command(session, command, timeout=timeout)


def _collect_neighbors(session: SshSession, switch: SwitchConfig, timeout: int) -> dict[str, list[Neighbor]]:
    profile = _vendor_profile(switch.vendor)
    if profile == "juniper":
        return _parse_neighbor_table(_run_command(session, "show lldp neighbors", timeout=timeout), "lldp")
    if profile == "fortiswitch":
        output = _run_command(session, "get switch lldp neighbors-detail", timeout=timeout)
        return _parse_neighbor_table(output, "lldp")

    lldp_neighbors: dict[str, list[Neighbor]] = {}
    try:
        lldp_output = _run_command(session, "show lldp neighbors detail", timeout=timeout)
        lldp_neighbors = _parse_cisco_lldp_neighbors_detail(lldp_output)
    except SshError:
        lldp_neighbors = {}
    if lldp_neighbors:
        return lldp_neighbors

    cdp_output = _run_command(session, "show cdp neighbors detail", timeout=timeout)
    return _parse_cisco_cdp_neighbors_detail(cdp_output)


def _collect_error_counters(session: SshSession, switch: SwitchConfig, timeout: int) -> dict[str, tuple[int, int]]:
    profile = _vendor_profile(switch.vendor)
    if profile == "juniper":
        output = _run_command(
            session,
            'show interfaces extensive | match "Physical interface|Input errors|Output errors"',
            timeout=timeout,
        )
        return _parse_juniper_error_counters(output)
    if profile == "fortiswitch":
        output = _run_command(session, "diagnose switch physical-ports error-counters", timeout=timeout)
        return _parse_fortiswitch_error_counters(output)

    output = _run_command(session, "show interfaces counters errors", timeout=timeout)
    return _parse_cisco_like_error_counters(output)


def _collect_poe_status(session: SshSession, switch: SwitchConfig, timeout: int) -> dict[str, tuple[str, float | None]]:
    profile = _vendor_profile(switch.vendor)
    if profile == "juniper":
        output = _run_command(session, "show poe interface", timeout=timeout)
        return _parse_juniper_poe(output)
    if profile == "fortiswitch":
        output = _run_command(session, "get switch poe inline-status", timeout=timeout)
        return _parse_fortiswitch_poe(output)

    output = _run_command(session, "show power inline", timeout=timeout)
    return _parse_cisco_like_poe(output)


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
        try:
            neighbors_by_port = _collect_neighbors(session, switch, timeout=timeout)
            for port in ports:
                canonical = _canonical_port_name(port.name)
                port.neighbors = neighbors_by_port.get(canonical, [])
        except SshError:
            logger.warning(
                "SSH neighbor collection command failed for switch %s; continuing without neighbors.",
                switch.name,
                exc_info=True,
            )
        try:
            errors_by_port = _collect_error_counters(session, switch, timeout=timeout)
            for port in ports:
                canonical = _canonical_port_name(port.name)
                counters = errors_by_port.get(canonical)
                if not counters:
                    continue
                port.input_errors = counters[0]
                port.output_errors = counters[1]
        except SshError:
            logger.warning(
                "SSH error counter collection command failed for switch %s; continuing without counters.",
                switch.name,
                exc_info=True,
            )
        try:
            poe_by_port = _collect_poe_status(session, switch, timeout=timeout)
            for port in ports:
                canonical = _canonical_port_name(port.name)
                poe_state = poe_by_port.get(canonical)
                if not poe_state:
                    continue
                port.poe_status = poe_state[0]
                port.poe_power_w = poe_state[1]
        except SshError:
            logger.warning(
                "SSH PoE collection command failed for switch %s; continuing without PoE data.",
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
