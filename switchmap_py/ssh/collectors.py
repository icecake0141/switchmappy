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
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from switchmap_py.artifacts import CollectorArtifactRecorder
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


class RecordingSshSession:
    def __init__(self, session: SshSession, recorder: CollectorArtifactRecorder) -> None:
        self.session = session
        self.recorder = recorder

    def run(self, command: str, timeout: int) -> str:
        try:
            output = self.session.run(command, timeout=timeout)
        except SshError as exc:
            self.recorder.record_text(kind="ssh-command", name=command, content=str(exc), status="error")
            raise
        self.recorder.record_text(kind="ssh-command", name=command, content=output)
        return output


@dataclass
class SwitchInventory:
    platform: str = ""
    serial_number: str = ""
    os_version: str = ""
    uptime: str = ""


@dataclass
class SwitchportInfo:
    mode: str = ""
    access_vlan: str = ""
    voice_vlan: str = ""
    native_vlan: str = ""
    allowed_vlans: str = ""
    description: str = ""
    fortilink: bool = False


@dataclass
class TransceiverInfo:
    model: str = ""
    tx_power_dbm: float | None = None
    rx_power_dbm: float | None = None
    current_ma: float | None = None


def _normalize_oper_status(status: str) -> str:
    value = status.lower()
    if value in {"connected", "up"}:
        return "up"
    if value in {"notconnect", "down", "disabled", "err-disabled", "inactive"}:
        return "down"
    return value


def _parse_speed(token: str) -> int | None:
    match = re.search(r"(\d+)", token)
    if not match:
        return None
    try:
        value = int(match.group(1))
    except ValueError:
        return None
    lower = token.lower()
    if "g" in lower:
        return value * 1000
    return value


def _normalize_mac(value: str) -> str | None:
    token = value.strip().lower().replace("-", "").replace(":", "").replace(".", "")
    if len(token) != 12 or not all(ch in "0123456789abcdef" for ch in token):
        return None
    return ":".join(token[index : index + 2] for index in range(0, 12, 2))


def _canonical_port_name(value: str) -> str:
    normalized = value.strip().lower().split(".")[0]
    aliases = {
        "gigabitethernet": "gi",
        "fastethernet": "fa",
        "tengigabitethernet": "te",
        "twentyfivegige": "twe",
        "fortygigabitethernet": "fo",
        "hundredgige": "hu",
        "ethernet": "et",
        "port-channel": "po",
    }
    for long_name, short_name in aliases.items():
        if normalized.startswith(long_name):
            return f"{short_name}{normalized[len(long_name) :]}"
    return normalized


def _is_trunk_port(name: str, switch: SwitchConfig) -> bool:
    canonical_trunks = {_canonical_port_name(port) for port in switch.trunk_ports}
    return _canonical_port_name(name) in canonical_trunks


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
        duplex = None
        if status_index + 2 < len(tokens):
            duplex = tokens[status_index + 2]
        if status_index + 3 < len(tokens):
            speed = _parse_speed(tokens[status_index + 3])
        media = " ".join(tokens[status_index + 4 :]) if status_index + 4 < len(tokens) else ""
        ports.append(
            Port(
                name=name,
                descr=descr,
                admin_status=admin_status,
                oper_status=oper_status,
                speed=speed,
                vlan=vlan,
                duplex=duplex,
                media=media,
                macs=[],
                is_trunk=_is_trunk_port(name, switch),
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
                is_trunk=_is_trunk_port(name, switch),
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
        if not re.match(r"^(?:port\d+|internal\d*)$", name.lower()):
            continue
        raw_status = tokens[1]
        vlan = None
        speed_token = tokens[2] if len(tokens) > 2 else ""
        descr_start = 3
        media = ""
        switchport_mode = None
        access_vlan = None
        if len(tokens) >= 6 and re.fullmatch(r"[0-9a-fA-F]{4}", tokens[2]) and _VLAN_ID_RE.match(tokens[3]):
            vlan = tokens[3]
            access_vlan = vlan
            speed_token = tokens[5]
            descr_start = 7
            known_flags = {"QS", "QE", "QI", "TS", "TF", "TL", "MD", "MI", "ME", "MB", "CF", "CC"}
            flag_tokens = {
                flag.strip().upper()
                for token in tokens[6:]
                for flag in token.split(",")
                if flag.strip().upper() in known_flags
            }
            for token in tokens[6:]:
                candidate = token.strip(" ,")
                if not candidate or candidate.upper() in flag_tokens or candidate.lower() == "none":
                    continue
                candidate_flags = {part.strip().upper() for part in candidate.split(",") if part.strip()}
                if candidate_flags and candidate_flags <= known_flags:
                    continue
                media = candidate
                break
            switchport_mode = "trunk" if flag_tokens & {"QS", "QE", "QI", "TS", "TF", "TL"} else "access"
        oper_status = _normalize_oper_status(raw_status)
        admin_status = "down" if oper_status == "down" else "up"
        speed = _parse_speed(speed_token) if speed_token and speed_token != "-" else None
        descr = " ".join(tokens[descr_start:]) if len(tokens) > descr_start else ""
        if descr.replace(" ", "") in {",,none", ",none", "none"}:
            descr = ""
        ports.append(
            Port(
                name=name,
                descr=descr,
                admin_status=admin_status,
                oper_status=oper_status,
                speed=speed,
                vlan=vlan,
                media=media,
                macs=[],
                switchport_mode=switchport_mode,
                access_vlan=access_vlan,
                is_trunk=_is_trunk_port(name, switch),
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
        if lower.startswith(("vlan", "----")) or lower.startswith("mac address"):
            continue
        if lower.startswith("mac:"):
            mac_match = re.search(r"\bMAC:\s+([0-9a-fA-F:.-]{12,17})", line, flags=re.IGNORECASE)
            port_match = re.search(r"\bPort:\s+([^\s(]+)", line, flags=re.IGNORECASE)
            canonical = _canonical_port_name(port_match.group(1)) if port_match else ""
            normalized_mac = _normalize_mac(mac_match.group(1) if mac_match else "")
            if canonical and normalized_mac:
                macs_by_port.setdefault(canonical, set()).add(normalized_mac)
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
    vlans_by_port: dict[str, list[str]] = {}
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
                if not re.match(r"^(?:port\d+|internal\d*)$", candidate.lower()):
                    continue
                canonical = _canonical_port_name(candidate)
                if canonical:
                    vlan_by_port[canonical] = vlan_id
                    vlans_by_port.setdefault(canonical, []).append(vlan_id)
    for canonical, vlan_ids in vlans_by_port.items():
        unique_vlan_ids = sorted(set(vlan_ids), key=lambda vlan_id: int(vlan_id))
        if len(unique_vlan_ids) > 1:
            vlan_by_port[canonical] = ",".join(unique_vlan_ids)
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
            output = session.run(command, timeout=effective_timeout)
            if _is_rejected_command_output(output):
                raise SshError(output.strip())
            return output
        except SshError as exc:
            last_error = exc
    if last_error:
        raise last_error
    raise SshError(f"failed to run command: {command}")


def _is_rejected_command_output(output: str) -> bool:
    lowered = output.lower()
    return (
        "% invalid input detected" in lowered
        or "% invalid command" in lowered
        or "command parse error" in lowered
        or "line has invalid autocommand" in lowered
    )


def _is_unsupported_optional_command(exc: SshError) -> bool:
    return _is_rejected_command_output(str(exc))


def _add_neighbor(
    table: dict[str, list[Neighbor]],
    local_port: str,
    device: str,
    protocol: str,
    remote_port: str | None = None,
    capabilities: list[str] | None = None,
) -> None:
    neighbors = table.setdefault(local_port, [])
    key = (device.lower(), (remote_port or "").lower(), protocol.lower())
    if any((n.device.lower(), (n.port or "").lower(), n.protocol.lower()) == key for n in neighbors):
        return
    neighbors.append(
        Neighbor(device=device, protocol=protocol, port=remote_port, capabilities=list(capabilities or []))
    )


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
    current_capabilities: list[str] = []
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
                    capabilities=current_capabilities,
                )
            current_local = None
            current_neighbor = None
            current_remote_port = None
            current_capabilities = []
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
        if "capabilities:" in lower:
            current_capabilities = _parse_capabilities(line.split(":", 1)[1])
            continue
    if current_local and current_neighbor:
        _add_neighbor(
            neighbors_by_port,
            current_local,
            current_neighbor,
            "lldp",
            remote_port=current_remote_port,
            capabilities=current_capabilities,
        )
    return neighbors_by_port


def _parse_fortiswitch_lldp_neighbors_detail(text: str) -> dict[str, list[Neighbor]]:
    neighbors_by_port: dict[str, list[Neighbor]] = {}
    current_local: str | None = None
    current_neighbor: str | None = None
    current_remote_port: str | None = None

    def flush_current() -> None:
        nonlocal current_local, current_neighbor, current_remote_port
        if current_local and current_neighbor:
            _add_neighbor(neighbors_by_port, current_local, current_neighbor, "lldp", remote_port=current_remote_port)
        current_local = None
        current_neighbor = None
        current_remote_port = None

    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        lower = line.lower()
        if lower.startswith("neighbor learned on port"):
            flush_current()
            match = re.search(r"\bport\s+(\S+)\s+by\s+lldp", line, flags=re.IGNORECASE)
            current_local = _canonical_port_name(match.group(1)) if match else None
            continue
        if lower.startswith("system name:"):
            current_neighbor = line.split(":", 1)[1].strip()
            continue
        if lower.startswith("port id:"):
            current_remote_port = line.split(":", 1)[1].strip().split(None, 1)[0]
            continue
    flush_current()
    return neighbors_by_port


def _parse_capabilities(value: str) -> list[str]:
    tokens = [token.strip(" ,") for token in re.split(r"[\s,]+", value) if token.strip(" ,")]
    ignored = {"capabilities", "enabled", "system", "bridge:"}
    return [token.lower() for token in tokens if token.lower() not in ignored]


def _parse_cisco_cdp_neighbors_detail(text: str) -> dict[str, list[Neighbor]]:
    neighbors_by_port: dict[str, list[Neighbor]] = {}
    current_local: str | None = None
    current_neighbor: str | None = None
    current_remote_port: str | None = None
    current_capabilities: list[str] = []

    def flush_current() -> None:
        nonlocal current_local, current_neighbor, current_remote_port
        if current_local and current_neighbor:
            _add_neighbor(
                neighbors_by_port,
                current_local,
                current_neighbor,
                "cdp",
                remote_port=current_remote_port,
                capabilities=current_capabilities,
            )
        current_local = None
        current_neighbor = None
        current_remote_port = None
        current_capabilities.clear()

    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        lower = line.lower()
        if line.startswith("-------------------------"):
            flush_current()
            continue
        if lower.startswith("device id:"):
            flush_current()
            current_neighbor = line.split(":", 1)[1].strip()
            continue
        if "capabilities:" in lower:
            current_capabilities[:] = _parse_capabilities(line.split("Capabilities:", 1)[1])
            continue
        if lower.startswith("interface:"):
            rhs = line.split(":", 1)[1]
            value = rhs.split(",", 1)[0].strip()
            current_local = _canonical_port_name(value)
            if "port id" in lower:
                tail = rhs.split("Port ID", 1)[1]
                current_remote_port = tail.split(":", 1)[1].strip() if ":" in tail else None
            continue
    flush_current()
    return neighbors_by_port


def _parse_cisco_show_version(text: str) -> SwitchInventory:
    inventory = SwitchInventory()
    for raw_line in text.splitlines():
        line = raw_line.strip()
        lower = line.lower()
        if not inventory.os_version and "version" in lower:
            match = re.search(r"\bversion\s+([^,\s]+)", line, flags=re.IGNORECASE)
            if match:
                inventory.os_version = match.group(1)
        if not inventory.uptime and " uptime is " in lower:
            inventory.uptime = line.split(" uptime is ", 1)[1].strip()
        if lower.startswith("model number"):
            inventory.platform = line.split(":", 1)[1].strip() if ":" in line else line
        elif not inventory.platform and "software (" in lower:
            match = re.search(r"software\s+\(([^)]+)\)", line, flags=re.IGNORECASE)
            if match:
                inventory.platform = match.group(1)
        elif not inventory.platform and lower.startswith("cisco "):
            tokens = line.split()
            if len(tokens) > 1:
                inventory.platform = tokens[1].strip(",")
        if lower.startswith("system serial number"):
            inventory.serial_number = line.split(":", 1)[1].strip() if ":" in line else line.split()[-1]
        elif not inventory.serial_number and lower.startswith("processor board id"):
            inventory.serial_number = line.split()[-1]
    return inventory


def _parse_fortiswitch_system_status(text: str) -> SwitchInventory:
    inventory = SwitchInventory()
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if "# " in line:
            line = line.rsplit("# ", 1)[1].strip()
        if not line or ":" not in line:
            continue
        key, value = line.split(":", 1)
        key = key.strip().lower()
        value = value.strip()
        if key == "version":
            inventory.os_version = value
            platform_match = re.match(r"([^,\s]+)", value)
            if platform_match:
                inventory.platform = platform_match.group(1)
        elif key == "serial-number":
            inventory.serial_number = value
    return inventory


def _parse_switchport_mode_line(value: str) -> str:
    cleaned = value.strip().lower()
    if cleaned in {"static access", "access"}:
        return "access"
    if "trunk" in cleaned:
        return "trunk"
    return cleaned


def _parse_float(value: str) -> float | None:
    try:
        return float(value)
    except ValueError:
        return None


def _set_transceiver_value(info: TransceiverInfo, label: str, value: str) -> None:
    numeric_match = re.search(r"(-?\d+(?:\.\d+)?)", value)
    numeric_value = _parse_float(numeric_match.group(1)) if numeric_match else None
    lower = label.lower()
    if "part" in lower or "model" in lower or lower in {"name", "type"}:
        info.model = value.strip()
    elif "tx" in lower or "transmit" in lower:
        info.tx_power_dbm = numeric_value
    elif "rx" in lower or "receive" in lower:
        info.rx_power_dbm = numeric_value
    elif "current" in lower or "bias" in lower:
        info.current_ma = numeric_value


def _parse_cisco_transceivers(text: str) -> dict[str, TransceiverInfo]:
    details: dict[str, TransceiverInfo] = {}
    current_port: str | None = None
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        lower = line.lower()
        if lower.startswith(("port ", "interface ", "---", "temperature ", "name ")):
            continue
        present_match = re.match(r"^(\S+)\s+(?:transceiver|sfp)\s+is\s+present", line, flags=re.IGNORECASE)
        if present_match:
            current_port = _canonical_port_name(present_match.group(1))
            details.setdefault(current_port, TransceiverInfo())
            continue
        port_match = re.match(r"^(?:port|interface)\s*:\s*(\S+)", line, flags=re.IGNORECASE)
        if port_match:
            current_port = _canonical_port_name(port_match.group(1))
            details.setdefault(current_port, TransceiverInfo())
            continue
        key_value_match = re.match(
            r"^(name|type|model|part(?:\s+number)?|tx\s+power|transmit(?:\s+optical)?\s+power|rx\s+power|receive(?:\s+optical)?\s+power|current|(?:laser\s+)?bias(?:\s+current)?)\s*(?::|\bis\b)\s*(.+)$",
            line,
            flags=re.IGNORECASE,
        )
        if key_value_match and current_port:
            _set_transceiver_value(
                details.setdefault(current_port, TransceiverInfo()), key_value_match.group(1), key_value_match.group(2)
            )
            continue
        tokens = _WS_RE.split(line)
        if len(tokens) >= 2 and _PORT_HINT_RE.match(tokens[0]):
            port_key = _canonical_port_name(tokens[0])
            info = details.setdefault(port_key, TransceiverInfo())
            numeric_tokens = [_parse_float(token) for token in tokens[1:]]
            numeric_values = [value for value in numeric_tokens if value is not None]
            if len(numeric_values) >= 5:
                info.current_ma = numeric_values[-3]
                info.tx_power_dbm = numeric_values[-2]
                info.rx_power_dbm = numeric_values[-1]
                continue
            if len(tokens) == 2 and _parse_float(tokens[1]) is None:
                info.model = tokens[1]
    return details


def _parse_juniper_optics(text: str) -> dict[str, TransceiverInfo]:
    details: dict[str, TransceiverInfo] = {}
    current_port: str | None = None
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        lower = line.lower()
        if lower.startswith("physical interface:"):
            current_port = _canonical_port_name(line.split(":", 1)[1].strip())
            details.setdefault(current_port, TransceiverInfo())
            continue
        if current_port is None or ":" not in line:
            continue
        label, value = line.split(":", 1)
        info = details.setdefault(current_port, TransceiverInfo())
        lower_label = label.strip().lower()
        dbm_match = re.search(r"/\s*(-?\d+(?:\.\d+)?)\s*dBm\b", value, flags=re.IGNORECASE)
        numeric_match = re.search(r"(-?\d+(?:\.\d+)?)", value)
        if "laser bias current" in lower_label:
            info.current_ma = _parse_float(numeric_match.group(1)) if numeric_match else None
        elif "laser output power" in lower_label:
            info.tx_power_dbm = _parse_float(dbm_match.group(1)) if dbm_match else None
        elif "receiver signal average optical power" in lower_label or "laser rx power" in lower_label:
            info.rx_power_dbm = _parse_float(dbm_match.group(1)) if dbm_match else None
    return details


def _weakest_dbm(values: list[float]) -> float | None:
    if not values:
        return None
    return round(min(values), 4)


def _highest_current(values: list[float]) -> float | None:
    if not values:
        return None
    return round(max(values), 4)


def _parse_fortiswitch_module_summary(text: str) -> dict[str, TransceiverInfo]:
    details: dict[str, TransceiverInfo] = {}
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        lower = line.lower()
        if lower.startswith(("portname", "____", "----")):
            continue
        tokens = _WS_RE.split(line)
        if len(tokens) < 4 or not tokens[0].lower().startswith("port"):
            continue
        info = details.setdefault(_canonical_port_name(tokens[0]), TransceiverInfo())
        if len(tokens) >= 8:
            info.model = tokens[-2]
        elif len(tokens) >= 4:
            info.model = tokens[3]
    return details


def _parse_fortiswitch_module_status(text: str) -> dict[str, TransceiverInfo]:
    details: dict[str, TransceiverInfo] = {}
    current_port: str | None = None
    lane_values: dict[str, dict[str, list[float]]] = {}
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        port_match = re.match(r"^Port\(([^)]+)\)", line, flags=re.IGNORECASE)
        if port_match:
            current_port = _canonical_port_name(port_match.group(1))
            details.setdefault(current_port, TransceiverInfo())
            lane_values.setdefault(current_port, {"bias": [], "tx": [], "rx": []})
            continue
        if current_port is None:
            continue
        key_value = _WS_RE.split(line, maxsplit=1)
        if len(key_value) != 2:
            continue
        key = key_value[0].lower()
        numeric_match = re.search(r"(-?\d+(?:\.\d+)?)", key_value[1])
        if not numeric_match:
            continue
        value = float(numeric_match.group(1))
        if key.startswith("laser_bias") or key.startswith("bias_current"):
            lane_values[current_port]["bias"].append(value)
        elif key.startswith("tx_power"):
            lane_values[current_port]["tx"].append(value)
        elif key.startswith("rx_power"):
            lane_values[current_port]["rx"].append(value)
    for port, values in lane_values.items():
        info = details.setdefault(port, TransceiverInfo())
        info.current_ma = _highest_current(values["bias"])
        info.tx_power_dbm = _weakest_dbm(values["tx"])
        info.rx_power_dbm = _weakest_dbm(values["rx"])
    return details


def _parse_cisco_switchport(text: str) -> dict[str, SwitchportInfo]:
    details: dict[str, SwitchportInfo] = {}
    current_port: str | None = None
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        lower = line.lower()
        if lower.startswith("name:"):
            current_port = _canonical_port_name(line.split(":", 1)[1].strip())
            details.setdefault(current_port, SwitchportInfo())
            continue
        if current_port is None:
            continue
        info = details[current_port]
        if lower.startswith("operational mode:"):
            info.mode = _parse_switchport_mode_line(line.split(":", 1)[1])
        elif lower.startswith("access mode vlan:"):
            info.access_vlan = line.split(":", 1)[1].strip()
        elif lower.startswith("voice vlan:"):
            value = line.split(":", 1)[1].strip()
            info.voice_vlan = "" if value.lower() in {"none", "none configured"} else value
        elif lower.startswith("trunking native mode vlan:"):
            info.native_vlan = line.split(":", 1)[1].strip()
        elif lower.startswith("trunking vlans enabled:"):
            info.allowed_vlans = line.split(":", 1)[1].strip()
    return details


def _parse_fortiswitch_switch_interface(text: str) -> dict[str, SwitchportInfo]:
    details: dict[str, SwitchportInfo] = {}
    current_port: str | None = None
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        lower = line.lower()
        edit_match = re.match(r'edit\s+"?([^"]+)"?', line, flags=re.IGNORECASE)
        if edit_match:
            current_port = _canonical_port_name(edit_match.group(1))
            details.setdefault(current_port, SwitchportInfo())
            continue
        if lower == "next":
            current_port = None
            continue
        if current_port is None:
            continue
        info = details[current_port]
        allowed_match = re.match(r"set\s+allowed-vlans\s+(.+)", line, flags=re.IGNORECASE)
        if allowed_match:
            info.allowed_vlans = allowed_match.group(1).strip().replace(" ", ",")
            if "," in info.allowed_vlans:
                info.mode = "trunk"
            continue
        if re.match(r"set\s+allowed-vlans-all\s+enable\b", line, flags=re.IGNORECASE):
            info.allowed_vlans = "all"
            info.mode = "trunk"
            continue
        mode_match = re.match(r"set\s+mode\s+(\S+)", line, flags=re.IGNORECASE)
        if mode_match:
            info.mode = _parse_switchport_mode_line(mode_match.group(1))
            continue
        native_match = re.match(r"set\s+native-vlan\s+(\d+)", line, flags=re.IGNORECASE)
        if native_match:
            info.native_vlan = native_match.group(1)
            continue
        access_match = re.match(r"set\s+(?:access-vlan|vlan)\s+(\d+)", line, flags=re.IGNORECASE)
        if access_match:
            info.access_vlan = access_match.group(1)
            if not info.mode:
                info.mode = "access"
            continue
        description_match = re.match(r"set\s+(?:description|alias)\s+(.+)", line, flags=re.IGNORECASE)
        if description_match:
            info.description = description_match.group(1).strip().strip('"')
            continue
        fortilink_match = re.match(r"set\s+auto-discovery-fortilink\s+(\S+)", line, flags=re.IGNORECASE)
        if fortilink_match and fortilink_match.group(1).lower() == "enable":
            info.fortilink = True
            if not info.mode:
                info.mode = "trunk"
    return details


def _parse_juniper_ethernet_switching_interfaces(text: str) -> dict[str, SwitchportInfo]:
    details: dict[str, SwitchportInfo] = {}
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        lower = line.lower()
        if lower.startswith(("interface", "---")):
            continue
        tokens = _WS_RE.split(line)
        if len(tokens) < 2 or "/" not in tokens[0]:
            continue
        port_name = _canonical_port_name(tokens[0])
        info = details.setdefault(port_name, SwitchportInfo())
        mode_token = next((token for token in tokens[1:] if token.lower() in {"access", "trunk"}), "")
        if mode_token:
            info.mode = mode_token.lower()
        vlan_tokens = [
            token.strip("[]")
            for token in tokens[1:]
            if token.strip("[]").lower().replace(",", "").replace("-", "").isalnum()
        ]
        if info.mode == "access":
            vlan = next((token for token in vlan_tokens if token.isdigit()), "")
            info.access_vlan = vlan
        elif info.mode == "trunk":
            allowed = [token for token in vlan_tokens if token.isdigit()]
            if allowed:
                info.allowed_vlans = ",".join(allowed)
    return details


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
        command = "diagnose switch physical-ports summary"
    else:
        command = "show interfaces status"
    return _run_command(session, command, timeout=timeout, retries=_PRIMARY_COMMAND_RETRIES)


def _collect_mac_output(session: SshSession, switch: SwitchConfig, timeout: int) -> str:
    profile = _vendor_profile(switch.vendor)
    if profile == "juniper":
        command = "show ethernet-switching table"
    elif profile == "fortiswitch":
        command = "diagnose switch mac-address list"
    else:
        command = "show mac address-table"
    return _run_command(session, command, timeout=timeout)


def _collect_vlan_output(session: SshSession, switch: SwitchConfig, timeout: int) -> str:
    profile = _vendor_profile(switch.vendor)
    if profile == "juniper":
        command = "show vlans"
    elif profile == "fortiswitch":
        command = "diagnose switch vlan list"
    else:
        command = "show vlan brief"
    return _run_command(session, command, timeout=timeout)


def _collect_neighbors(session: SshSession, switch: SwitchConfig, timeout: int) -> dict[str, list[Neighbor]]:
    profile = _vendor_profile(switch.vendor)
    if profile == "juniper":
        return _parse_neighbor_table(_run_command(session, "show lldp neighbors", timeout=timeout), "lldp")
    if profile == "fortiswitch":
        output = _run_command(session, "get switch lldp neighbors-detail", timeout=timeout)
        return _parse_fortiswitch_lldp_neighbors_detail(output) or _parse_neighbor_table(output, "lldp")

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


def _collect_switchport_details(session: SshSession, switch: SwitchConfig, timeout: int) -> dict[str, SwitchportInfo]:
    profile = _vendor_profile(switch.vendor)
    if profile == "fortiswitch":
        output = _run_command(session, "show switch interface", timeout=timeout)
        return _parse_fortiswitch_switch_interface(output)
    if profile == "juniper":
        output = _run_command(session, "show ethernet-switching interfaces", timeout=timeout)
        return _parse_juniper_ethernet_switching_interfaces(output)
    if profile not in {"cisco_like", "arista"}:
        return {}
    output = _run_command(session, "show interfaces switchport", timeout=timeout)
    return _parse_cisco_switchport(output)


def _collect_transceiver_details(session: SshSession, switch: SwitchConfig, timeout: int) -> dict[str, TransceiverInfo]:
    profile = _vendor_profile(switch.vendor)
    if profile == "fortiswitch":
        summary = _run_command(session, "get switch modules summary", timeout=timeout)
        details = _parse_fortiswitch_module_summary(summary)
        try:
            status = _run_command(session, "get switch modules status", timeout=timeout * _SLOW_COMMAND_TIMEOUT_FACTOR)
        except SshError as exc:
            if _is_unsupported_optional_command(exc):
                return details
            raise
        for port, status_info in _parse_fortiswitch_module_status(status).items():
            info = details.setdefault(port, TransceiverInfo())
            info.tx_power_dbm = status_info.tx_power_dbm
            info.rx_power_dbm = status_info.rx_power_dbm
            info.current_ma = status_info.current_ma
        return details
    if profile == "juniper":
        output = _run_command(
            session,
            "show interfaces diagnostics optics",
            timeout=timeout * _SLOW_COMMAND_TIMEOUT_FACTOR,
        )
        return _parse_juniper_optics(output)
    if profile not in {"cisco_like", "arista"}:
        return {}
    output = _run_command(session, "show interfaces transceiver", timeout=timeout * _SLOW_COMMAND_TIMEOUT_FACTOR)
    return _parse_cisco_transceivers(output)


def _collect_inventory(session: SshSession, switch: SwitchConfig, timeout: int) -> SwitchInventory:
    profile = _vendor_profile(switch.vendor)
    if profile == "fortiswitch":
        output = _run_command(session, "get system status", timeout=timeout)
        return _parse_fortiswitch_system_status(output)
    if profile in {"cisco_like", "arista"}:
        output = _run_command(session, "show version", timeout=timeout)
        return _parse_cisco_show_version(output)
    return SwitchInventory()


def collect_switch_state(switch: SwitchConfig, timeout: int, artifact_dir: Path | None = None) -> Switch:
    session: Any = build_session(switch, timeout=timeout)
    if artifact_dir is not None:
        session = RecordingSshSession(session, CollectorArtifactRecorder(artifact_dir, switch.name, "ssh"))
    ports: list[Port] = []
    inventory = SwitchInventory()
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
                canonical = _canonical_port_name(port.name)
                mapped_vlan = vlan_by_port.get(canonical)
                if profile == "fortiswitch" and mapped_vlan and "," in mapped_vlan:
                    port.allowed_vlans = mapped_vlan
                if port.vlan:
                    continue
                if mapped_vlan:
                    port.vlan = mapped_vlan.split(",", maxsplit=1)[0]
        except SshError:
            logger.warning(
                "SSH VLAN collection command failed for switch %s; continuing without VLAN table.",
                switch.name,
                exc_info=True,
            )
        try:
            switchport_by_port = _collect_switchport_details(session, switch, timeout=timeout)
            for port in ports:
                details = switchport_by_port.get(_canonical_port_name(port.name))
                if not details:
                    continue
                port.switchport_mode = details.mode or port.switchport_mode
                port.access_vlan = details.access_vlan or port.access_vlan
                port.voice_vlan = details.voice_vlan or port.voice_vlan
                port.native_vlan = details.native_vlan or port.native_vlan
                port.allowed_vlans = details.allowed_vlans or port.allowed_vlans
                port.descr = details.description or port.descr
                if details.fortilink:
                    port.is_trunk = True
        except SshError as exc:
            if _is_unsupported_optional_command(exc):
                logger.debug(
                    "SSH switchport detail command is unsupported on switch %s; continuing without switchport data.",
                    switch.name,
                )
            else:
                logger.warning(
                    "SSH switchport detail command failed for switch %s; continuing without switchport data.",
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
            transceiver_by_port = _collect_transceiver_details(session, switch, timeout=timeout)
            for port in ports:
                transceiver_details = transceiver_by_port.get(_canonical_port_name(port.name))
                if not transceiver_details:
                    continue
                port.transceiver_model = transceiver_details.model or port.transceiver_model
                port.transceiver_tx_power_dbm = transceiver_details.tx_power_dbm
                port.transceiver_rx_power_dbm = transceiver_details.rx_power_dbm
                port.transceiver_current_ma = transceiver_details.current_ma
        except SshError as exc:
            if _is_unsupported_optional_command(exc):
                logger.debug(
                    "SSH transceiver detail command is unsupported on switch %s; continuing without transceiver data.",
                    switch.name,
                )
            else:
                logger.warning(
                    "SSH transceiver detail command failed for switch %s; continuing without transceiver data.",
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
        except SshError as exc:
            if _is_unsupported_optional_command(exc):
                logger.debug(
                    "SSH error counter collection command is unsupported on switch %s; continuing without counters.",
                    switch.name,
                )
            else:
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
        except SshError as exc:
            if _is_unsupported_optional_command(exc):
                logger.debug(
                    "SSH PoE collection command is unsupported on switch %s; continuing without PoE data.",
                    switch.name,
                )
            else:
                logger.warning(
                    "SSH PoE collection command failed for switch %s; continuing without PoE data.",
                    switch.name,
                    exc_info=True,
                )
        try:
            inventory = _collect_inventory(session, switch, timeout=timeout)
        except SshError:
            logger.warning(
                "SSH inventory collection command failed for switch %s; continuing without inventory.",
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
        platform=inventory.platform,
        serial_number=inventory.serial_number,
        os_version=inventory.os_version,
        uptime=inventory.uptime,
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
