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

"""SNMP data collection for network switches.

This module collects port and MAC information from network switches via SNMP.
Error handling strategy:
- SnmpError: Expected operational errors (timeouts, auth failures, etc.) are caught
  and logged where appropriate, allowing collection to continue with partial data.
- Other exceptions: Programming errors propagate to fail fast, ensuring bugs are
  not masked as operational errors.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from switchmap_py.artifacts import CollectorArtifactRecorder
from switchmap_py.config import SwitchConfig
from switchmap_py.model.neighbor import Neighbor
from switchmap_py.model.port import Port
from switchmap_py.model.switch import Switch
from switchmap_py.model.vlan import Vlan
from switchmap_py.snmp import mibs
from switchmap_py.snmp.session import SnmpConfig, SnmpError, SnmpSession

logger = logging.getLogger(__name__)


@dataclass
class PortSnapshot:
    name: str
    is_active: bool
    mac_count: int
    oper_status: str


_LLDP_CAPABILITIES = {
    1: "other",
    2: "repeater",
    3: "bridge",
    4: "wlan",
    5: "router",
    6: "telephone",
    7: "docsis",
    8: "station",
}


def build_session(switch: SwitchConfig, timeout: int, retries: int) -> SnmpSession:
    return SnmpSession(
        SnmpConfig(
            hostname=switch.management_ip,
            version=str(switch.snmp_version),
            community=switch.community,
            username=switch.username,
            security_level=switch.security_level,
            auth_protocol=switch.auth_protocol,
            auth_password=switch.auth_password,
            priv_protocol=switch.priv_protocol,
            priv_password=switch.priv_password,
            timeout=timeout,
            retries=retries,
        )
    )


class RecordingSnmpSession:
    def __init__(self, session: SnmpSession, recorder: CollectorArtifactRecorder) -> None:
        self.session = session
        self.recorder = recorder

    def get_table(self, oid: str) -> Mapping[str, str]:
        try:
            rows = self.session.get_table(oid)
        except SnmpError:
            self.recorder.record_table(oid=oid, rows={}, status="error")
            raise
        self.recorder.record_table(oid=oid, rows=rows)
        return rows


def _normalize_status(value: str) -> str:
    return {"1": "up", "2": "down"}.get(value, value)


def _normalize_if_type(value: str) -> str:
    return {
        "6": "ethernetCsmacd",
        "24": "softwareLoopback",
        "53": "propVirtual",
        "161": "ieee8023adLag",
    }.get(value, value)


def _format_mac(parts: list[str]) -> str:
    return ":".join(f"{int(part):02x}" for part in parts)


def _select_port_name(if_name: str, if_descr: str, ifindex: int | None) -> str:
    # Priority: IF_NAME (if non-empty) → IF_DESCR → ifIndex as a last resort.
    if if_name:
        return if_name
    if if_descr:
        return if_descr
    return str(ifindex) if ifindex is not None else ""


def _parse_mac_from_oid(oid: str, prefix: str, *, vlan_aware: bool) -> tuple[str, str | None] | None:
    prefix_parts = prefix.split(".")
    oid_parts = oid.split(".")
    if oid_parts[: len(prefix_parts)] != prefix_parts:
        return None
    suffix = oid_parts[len(prefix_parts) :]
    if vlan_aware:
        if len(suffix) < 7:
            return None
        vlan_id = suffix[0]
        mac_parts = suffix[1:7]
    else:
        if len(suffix) < 6:
            return None
        vlan_id = None
        mac_parts = suffix[:6]
    try:
        mac = _format_mac(mac_parts)
    except ValueError:
        return None
    return mac, vlan_id


def _is_invalid_fdb_status(status: str | None) -> bool:
    return status == "2"


def _bridge_port_map(session: SnmpSession) -> dict[str, int]:
    try:
        base_ports = session.get_table(mibs.DOT1D_BASE_PORT_IFINDEX)
    except SnmpError:
        logger.warning(
            "Failed to fetch OID %s for bridge port map.",
            mibs.DOT1D_BASE_PORT_IFINDEX,
            exc_info=True,
        )
        return {}
    mapping: dict[str, int] = {}
    for oid, ifindex in base_ports.items():
        bridge_port = oid.split(".")[-1]
        if ifindex.isdigit():
            mapping[bridge_port] = int(ifindex)
    return mapping


def _status_oid(source_base: str, status_base: str, source_oid: str) -> str:
    base_parts = source_base.split(".")
    source_parts = source_oid.split(".")
    suffix = source_parts[len(base_parts) :]
    return f"{status_base}.{'.'.join(suffix)}" if suffix else status_base


def _vlan_sort_key(vlan_id: str) -> tuple[int, str]:
    try:
        return (0, f"{int(vlan_id):08d}")
    except ValueError:
        return (1, vlan_id)


def _diagnostic(kind: str, label: str, detail: str) -> dict[str, str]:
    return {"kind": kind, "label": label, "detail": detail}


def _collect_macs(session: SnmpSession) -> tuple[dict[int, set[str]], dict[int, set[str]], list[dict[str, str]]]:
    diagnostics: list[dict[str, str]] = []
    bridge_port_to_ifindex = _bridge_port_map(session)
    if not bridge_port_to_ifindex:
        diagnostics.append(_diagnostic("snmp_fdb", "collection error", "BRIDGE-MIB port to ifIndex map is empty"))
        return {}, {}, diagnostics

    macs_by_ifindex: dict[int, set[str]] = {}
    vlan_ids_by_ifindex: dict[int, set[str]] = {}
    try:
        vlan_fdb_ports = session.get_table(mibs.QBRIDGE_VLAN_FDB_PORT)
    except SnmpError:
        logger.warning(
            "Failed to fetch OID %s for VLAN FDB ports.",
            mibs.QBRIDGE_VLAN_FDB_PORT,
            exc_info=True,
        )
        diagnostics.append(_diagnostic("snmp_fdb", "Q-BRIDGE unavailable", "Q-BRIDGE VLAN FDB table collection failed"))
        vlan_fdb_ports = {}

    if vlan_fdb_ports:
        diagnostics.append(
            _diagnostic("snmp_fdb", "Q-BRIDGE populated", f"Q-BRIDGE VLAN FDB rows: {len(vlan_fdb_ports)}")
        )
        try:
            vlan_fdb_status = session.get_table(mibs.QBRIDGE_VLAN_FDB_STATUS)
        except SnmpError:
            logger.warning(
                "Failed to fetch OID %s for VLAN FDB status.",
                mibs.QBRIDGE_VLAN_FDB_STATUS,
                exc_info=True,
            )
            vlan_fdb_status = {}
        for oid, bridge_port in vlan_fdb_ports.items():
            status_oid = _status_oid(mibs.QBRIDGE_VLAN_FDB_PORT, mibs.QBRIDGE_VLAN_FDB_STATUS, oid)
            if _is_invalid_fdb_status(vlan_fdb_status.get(status_oid)):
                continue
            parsed = _parse_mac_from_oid(oid, mibs.QBRIDGE_VLAN_FDB_PORT, vlan_aware=True)
            if not parsed:
                continue
            mac, vlan_id = parsed
            ifindex = bridge_port_to_ifindex.get(bridge_port)
            if ifindex is None:
                continue
            macs_by_ifindex.setdefault(ifindex, set()).add(mac)
            if vlan_id:
                vlan_ids_by_ifindex.setdefault(ifindex, set()).add(vlan_id)
        return macs_by_ifindex, vlan_ids_by_ifindex, diagnostics

    diagnostics.append(_diagnostic("snmp_fdb", "Q-BRIDGE empty", "Q-BRIDGE VLAN FDB table returned no rows"))

    try:
        fdb_ports = session.get_table(mibs.DOT1D_TP_FDB_PORT)
    except SnmpError:
        logger.warning(
            "Failed to fetch OID %s for FDB ports.",
            mibs.DOT1D_TP_FDB_PORT,
            exc_info=True,
        )
        diagnostics.append(_diagnostic("snmp_fdb", "BRIDGE FDB unavailable", "BRIDGE-MIB FDB table collection failed"))
        return {}, {}, diagnostics
    if not fdb_ports:
        diagnostics.append(_diagnostic("snmp_fdb", "FDB empty", "BRIDGE-MIB FDB table returned no rows"))
        return {}, {}, diagnostics
    diagnostics.append(_diagnostic("snmp_fdb", "FDB populated", f"BRIDGE-MIB FDB rows: {len(fdb_ports)}"))
    diagnostics.append(
        _diagnostic(
            "snmp_fdb",
            "VLAN-indexed community may be required",
            "Legacy FDB has MACs but VLAN-aware Q-BRIDGE data is empty",
        )
    )
    try:
        fdb_status = session.get_table(mibs.DOT1D_TP_FDB_STATUS)
    except SnmpError:
        logger.warning(
            "Failed to fetch OID %s for FDB status.",
            mibs.DOT1D_TP_FDB_STATUS,
            exc_info=True,
        )
        fdb_status = {}

    for oid, bridge_port in fdb_ports.items():
        status_oid = _status_oid(mibs.DOT1D_TP_FDB_PORT, mibs.DOT1D_TP_FDB_STATUS, oid)
        if _is_invalid_fdb_status(fdb_status.get(status_oid)):
            continue
        parsed = _parse_mac_from_oid(oid, mibs.DOT1D_TP_FDB_PORT, vlan_aware=False)
        if not parsed:
            continue
        mac, _ = parsed
        ifindex = bridge_port_to_ifindex.get(bridge_port)
        if ifindex is None:
            continue
        macs_by_ifindex.setdefault(ifindex, set()).add(mac)
    return macs_by_ifindex, vlan_ids_by_ifindex, diagnostics


def _first_table_value(session: SnmpSession, oid: str) -> str:
    try:
        values = session.get_table(oid)
    except SnmpError:
        return ""
    for value in values.values():
        if str(value).strip():
            return str(value).strip()
    return ""


def _collect_error_counters(session: SnmpSession, ports_by_ifindex: dict[int, Port]) -> None:
    try:
        in_errors = session.get_table(mibs.IF_IN_ERRORS)
        out_errors = session.get_table(mibs.IF_OUT_ERRORS)
    except SnmpError:
        return
    for ifindex, port in ports_by_ifindex.items():
        input_value = in_errors.get(f"{mibs.IF_IN_ERRORS}.{ifindex}")
        output_value = out_errors.get(f"{mibs.IF_OUT_ERRORS}.{ifindex}")
        if input_value and input_value.isdigit():
            port.input_errors = int(input_value)
        if output_value and output_value.isdigit():
            port.output_errors = int(output_value)


def _poe_ifindex_from_oid(oid: str, base_oid: str) -> int | None:
    suffix = oid.removeprefix(f"{base_oid}.").split(".")
    if not suffix:
        return None
    candidate = suffix[-1]
    return int(candidate) if candidate.isdigit() else None


def _collect_poe_status(session: SnmpSession, ports_by_ifindex: dict[int, Port]) -> None:
    status_labels = {
        "1": "disabled",
        "2": "searching",
        "3": "delivering",
        "4": "fault",
        "5": "test",
        "6": "other-fault",
    }
    try:
        statuses = session.get_table(mibs.PETH_PSE_PORT_DETECTION_STATUS)
    except SnmpError:
        statuses = {}
    try:
        powers = session.get_table(mibs.PETH_PSE_PORT_POWER)
    except SnmpError:
        powers = {}
    for oid, status in statuses.items():
        ifindex = _poe_ifindex_from_oid(oid, mibs.PETH_PSE_PORT_DETECTION_STATUS)
        port = ports_by_ifindex.get(ifindex or -1)
        if port is None:
            continue
        port.poe_status = status_labels.get(status, status)
        status_prefix_len = len(mibs.PETH_PSE_PORT_DETECTION_STATUS.split("."))
        power_suffix = ".".join(oid.split(".")[status_prefix_len:])
        power_oid = f"{mibs.PETH_PSE_PORT_POWER}.{power_suffix}"
        power = powers.get(power_oid)
        if power and power.isdigit():
            port.poe_power_w = int(power) / 10.0


def _lldp_local_port_number(oid: str, prefix: str) -> str | None:
    prefix_parts = prefix.split(".")
    oid_parts = oid.split(".")
    if oid_parts[: len(prefix_parts)] != prefix_parts:
        return None
    suffix = oid_parts[len(prefix_parts) :]
    return suffix[0] if suffix else None


def _lldp_remote_index(oid: str, prefix: str) -> tuple[str, str, str] | None:
    prefix_parts = prefix.split(".")
    oid_parts = oid.split(".")
    if oid_parts[: len(prefix_parts)] != prefix_parts:
        return None
    suffix = oid_parts[len(prefix_parts) :]
    if len(suffix) < 3:
        return None
    return suffix[0], suffix[1], suffix[2]


def _collect_lldp_neighbors(session: SnmpSession, ports_by_ifindex: dict[int, Port]) -> None:
    try:
        local_port_ids = session.get_table(mibs.LLDP_LOC_PORT_ID)
        remote_systems = session.get_table(mibs.LLDP_REM_SYS_NAME)
        remote_ports = session.get_table(mibs.LLDP_REM_PORT_ID)
    except SnmpError:
        logger.debug("Failed to fetch LLDP tables.", exc_info=True)
        return
    try:
        remote_capabilities = session.get_table(mibs.LLDP_REM_SYS_CAP_ENABLED)
    except SnmpError:
        logger.debug("Failed to fetch LLDP capability table.", exc_info=True)
        remote_capabilities = {}

    local_port_to_ifindex: dict[str, int] = {}
    canonical_ifnames = {port.name.lower(): ifindex for ifindex, port in ports_by_ifindex.items()}
    for oid, port_id in local_port_ids.items():
        local_number = _lldp_local_port_number(oid, mibs.LLDP_LOC_PORT_ID)
        if local_number is None:
            continue
        if port_id.isdigit():
            local_port_to_ifindex[local_number] = int(port_id)
            continue
        ifindex = canonical_ifnames.get(port_id.lower())
        if ifindex is not None:
            local_port_to_ifindex[local_number] = ifindex

    for oid, system_name in remote_systems.items():
        index = _lldp_remote_index(oid, mibs.LLDP_REM_SYS_NAME)
        if index is None:
            continue
        _time_mark, local_port_num, remote_index = index
        ifindex = local_port_to_ifindex.get(local_port_num)
        if ifindex is None:
            continue
        port = ports_by_ifindex.get(ifindex)
        if port is None:
            continue
        remote_port_oid = f"{mibs.LLDP_REM_PORT_ID}.{'.'.join(index)}"
        remote_capability_oid = f"{mibs.LLDP_REM_SYS_CAP_ENABLED}.{'.'.join(index)}"
        port.neighbors.append(
            Neighbor(
                device=system_name,
                protocol="lldp",
                port=remote_ports.get(remote_port_oid) or remote_index,
                capabilities=_parse_lldp_capabilities(remote_capabilities.get(remote_capability_oid, "")),
            )
        )


def _parse_lldp_capabilities(value: str) -> list[str]:
    token = value.strip()
    if not token:
        return []
    try:
        numeric = int(token, 0)
    except ValueError:
        return [part.lower() for part in token.replace(",", " ").split() if part]
    return [label for bit, label in _LLDP_CAPABILITIES.items() if numeric & (1 << (bit - 1))]


def collect_switch_state(switch: SwitchConfig, timeout: int, retries: int, artifact_dir: Path | None = None) -> Switch:
    session: Any = build_session(switch, timeout, retries)
    if artifact_dir is not None:
        session = RecordingSnmpSession(session, CollectorArtifactRecorder(artifact_dir, switch.name, "snmp"))
    names = session.get_table(mibs.IF_NAME)
    aliases = session.get_table(mibs.IF_ALIAS)
    descrs = session.get_table(mibs.IF_DESCR)
    if_types = session.get_table(mibs.IF_TYPE)
    admin = session.get_table(mibs.IF_ADMIN_STATUS)
    oper = session.get_table(mibs.IF_OPER_STATUS)
    last_changes = session.get_table(mibs.IF_LAST_CHANGE)
    speeds = session.get_table(mibs.IF_SPEED)
    try:
        sys_descr = session.get_table(mibs.SYS_DESCR)
    except SnmpError:
        sys_descr = {}
    try:
        sys_uptime = session.get_table(mibs.SYS_UPTIME)
    except SnmpError:
        sys_uptime = {}

    ports: list[Port] = []
    ports_by_ifindex: dict[int, Port] = {}
    for oid, name in names.items():
        index = oid.split(".")[-1]
        ifindex = int(index) if index.isdigit() else None
        descr = aliases.get(f"{mibs.IF_ALIAS}.{index}", "") or descrs.get(f"{mibs.IF_DESCR}.{index}", "")
        resolved_name = _select_port_name(
            (name or "").strip(),
            (descr or "").strip(),
            ifindex,
        )
        admin_status = _normalize_status(admin.get(f"{mibs.IF_ADMIN_STATUS}.{index}", ""))
        oper_status = _normalize_status(oper.get(f"{mibs.IF_OPER_STATUS}.{index}", ""))
        speed = speeds.get(f"{mibs.IF_SPEED}.{index}")
        port = Port(
            name=resolved_name,
            descr=descr,
            admin_status=admin_status,
            oper_status=oper_status,
            speed=int(speed) if speed and speed.isdigit() else None,
            vlan=None,
            last_change=last_changes.get(f"{mibs.IF_LAST_CHANGE}.{index}"),
            media=_normalize_if_type(if_types.get(f"{mibs.IF_TYPE}.{index}", "")),
            macs=[],
            idle_since=None,
            last_active=None,
            is_trunk=resolved_name in switch.trunk_ports,
        )
        ports.append(port)
        if ifindex is not None:
            ports_by_ifindex[ifindex] = port

    macs_by_ifindex, vlan_ids_by_ifindex, diagnostics = _collect_macs(session)
    for ifindex, macs in macs_by_ifindex.items():
        mapped_port = ports_by_ifindex.get(ifindex)
        if mapped_port:
            mapped_port.macs = sorted(macs)
    for ifindex, vlan_ids in vlan_ids_by_ifindex.items():
        mapped_port = ports_by_ifindex.get(ifindex)
        if mapped_port and vlan_ids:
            mapped_port.vlan = ",".join(sorted(vlan_ids, key=_vlan_sort_key))
    _collect_lldp_neighbors(session, ports_by_ifindex)
    _collect_error_counters(session, ports_by_ifindex)
    _collect_poe_status(session, ports_by_ifindex)

    vlans: list[Vlan] = []
    try:
        vlan_names = session.get_table(mibs.QBRIDGE_VLAN_NAME)
    except SnmpError:
        vlan_names = {}
    vlan_to_ports: dict[str, set[str]] = {}
    for ifindex, vlan_ids in vlan_ids_by_ifindex.items():
        mapped_port = ports_by_ifindex.get(ifindex)
        if not mapped_port:
            continue
        for vlan_id in vlan_ids:
            vlan_to_ports.setdefault(vlan_id, set()).add(mapped_port.name)

    known_vlan_ids: set[str] = set()
    for oid, vlan_name in vlan_names.items():
        vlan_id = oid.split(".")[-1]
        known_vlan_ids.add(vlan_id)
        vlans.append(
            Vlan(
                vlan_id=vlan_id,
                name=vlan_name,
                ports=sorted(vlan_to_ports.get(vlan_id, set())),
                source="named",
            )
        )
    for vlan_id in sorted(set(vlan_to_ports) - known_vlan_ids, key=_vlan_sort_key):
        vlans.append(
            Vlan(
                vlan_id=vlan_id,
                name=f"VLAN {vlan_id}",
                ports=sorted(vlan_to_ports.get(vlan_id, set())),
                source="derived",
            )
        )

    return Switch(
        name=switch.name,
        management_ip=switch.management_ip,
        vendor=switch.vendor,
        platform=_first_table_value(session, mibs.ENT_PHYSICAL_MODEL_NAME) or next(iter(sys_descr.values()), ""),
        serial_number=_first_table_value(session, mibs.ENT_PHYSICAL_SERIAL_NUM),
        os_version=_first_table_value(session, mibs.ENT_PHYSICAL_SOFTWARE_REV),
        uptime=next(iter(sys_uptime.values()), ""),
        ports=ports,
        vlans=vlans,
        diagnostics=diagnostics,
    )


def collect_port_snapshots(switch: SwitchConfig, timeout: int, retries: int) -> list[PortSnapshot]:
    state = collect_switch_state(switch, timeout, retries)
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
