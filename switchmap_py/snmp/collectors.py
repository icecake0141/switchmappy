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

from switchmap_py.config import SwitchConfig
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


def build_session(switch: SwitchConfig, timeout: int, retries: int) -> SnmpSession:
    return SnmpSession(
        SnmpConfig(
            hostname=switch.management_ip,
            version=switch.snmp_version,
            community=switch.community,
            timeout=timeout,
            retries=retries,
        )
    )


def _normalize_status(value: str) -> str:
    return {"1": "up", "2": "down"}.get(value, value)


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
    if oid_parts[:len(prefix_parts)] != prefix_parts:
        return None
    suffix = oid_parts[len(prefix_parts):]
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
    suffix = source_parts[len(base_parts):]
    return f"{status_base}.{'.'.join(suffix)}" if suffix else status_base


def _vlan_sort_key(vlan_id: str) -> tuple[int, str]:
    try:
        return (0, f"{int(vlan_id):08d}")
    except ValueError:
        return (1, vlan_id)


def _collect_macs(session: SnmpSession) -> tuple[dict[int, set[str]], dict[int, set[str]]]:
    bridge_port_to_ifindex = _bridge_port_map(session)
    if not bridge_port_to_ifindex:
        return {}, {}

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
        vlan_fdb_ports = {}

    if vlan_fdb_ports:
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
            status_oid = _status_oid(
                mibs.QBRIDGE_VLAN_FDB_PORT, mibs.QBRIDGE_VLAN_FDB_STATUS, oid
            )
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
        return macs_by_ifindex, vlan_ids_by_ifindex

    try:
        fdb_ports = session.get_table(mibs.DOT1D_TP_FDB_PORT)
    except SnmpError:
        logger.warning(
            "Failed to fetch OID %s for FDB ports.",
            mibs.DOT1D_TP_FDB_PORT,
            exc_info=True,
        )
        return {}, {}
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
    return macs_by_ifindex, vlan_ids_by_ifindex


def collect_switch_state(
    switch: SwitchConfig, timeout: int, retries: int
) -> Switch:
    session = build_session(switch, timeout, retries)
    names = session.get_table(mibs.IF_NAME)
    descrs = session.get_table(mibs.IF_DESCR)
    admin = session.get_table(mibs.IF_ADMIN_STATUS)
    oper = session.get_table(mibs.IF_OPER_STATUS)
    speeds = session.get_table(mibs.IF_SPEED)

    ports: list[Port] = []
    ports_by_ifindex: dict[int, Port] = {}
    for oid, name in names.items():
        index = oid.split(".")[-1]
        ifindex = int(index) if index.isdigit() else None
        descr = descrs.get(f"{mibs.IF_DESCR}.{index}", "")
        resolved_name = _select_port_name(
            (name or "").strip(),
            (descr or "").strip(),
            ifindex,
        )
        admin_status = _normalize_status(
            admin.get(f"{mibs.IF_ADMIN_STATUS}.{index}", "")
        )
        oper_status = _normalize_status(oper.get(f"{mibs.IF_OPER_STATUS}.{index}", ""))
        speed = speeds.get(f"{mibs.IF_SPEED}.{index}")
        port = Port(
            name=resolved_name,
            descr=descr,
            admin_status=admin_status,
            oper_status=oper_status,
            speed=int(speed) if speed and speed.isdigit() else None,
            vlan=None,
            macs=[],
            idle_since=None,
            last_active=None,
            is_trunk=resolved_name in switch.trunk_ports,
        )
        ports.append(port)
        if ifindex is not None:
            ports_by_ifindex[ifindex] = port

    macs_by_ifindex, vlan_ids_by_ifindex = _collect_macs(session)
    for ifindex, macs in macs_by_ifindex.items():
        port = ports_by_ifindex.get(ifindex)
        if port:
            port.macs = sorted(macs)
    for ifindex, vlan_ids in vlan_ids_by_ifindex.items():
        port = ports_by_ifindex.get(ifindex)
        if port and vlan_ids:
            port.vlan = ",".join(sorted(vlan_ids, key=_vlan_sort_key))

    vlans: list[Vlan] = []
    try:
        vlan_names = session.get_table(mibs.QBRIDGE_VLAN_NAME)
    except SnmpError:
        vlan_names = {}
    vlan_to_ports: dict[str, set[str]] = {}
    for ifindex, vlan_ids in vlan_ids_by_ifindex.items():
        port = ports_by_ifindex.get(ifindex)
        if not port:
            continue
        for vlan_id in vlan_ids:
            vlan_to_ports.setdefault(vlan_id, set()).add(port.name)

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
        ports=ports,
        vlans=vlans,
    )


def collect_port_snapshots(
    switch: SwitchConfig, timeout: int, retries: int
) -> list[PortSnapshot]:
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
