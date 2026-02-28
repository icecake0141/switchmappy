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

import ipaddress
import logging
import re
import time
from typing import Iterable

from switchmap_py.config import RouterConfig
from switchmap_py.model.mac import MacEntry
from switchmap_py.snmp import mibs
from switchmap_py.snmp.session import SnmpConfig, SnmpError, SnmpSession

logger = logging.getLogger(__name__)

_HEX_PAIR_RE = re.compile(r"^[0-9a-fA-F]{2}$")


def _bytes_to_mac(parts: list[int]) -> str | None:
    if len(parts) != 6:
        return None
    if not all(0 <= part <= 255 for part in parts):
        return None
    return ":".join(f"{part:02x}" for part in parts)


def _normalize_mac(raw: str) -> str | None:
    value = raw.strip()
    if not value:
        return None

    # Some SNMP implementations return dotted-decimal byte arrays.
    if "." in value and ":" not in value and "-" not in value:
        dotted_parts = value.split(".")
        if len(dotted_parts) == 6 and all(part.isdigit() for part in dotted_parts):
            return _bytes_to_mac([int(part) for part in dotted_parts])

    # Some implementations return whitespace-separated bytes.
    if " " in value and ":" not in value and "-" not in value and "." not in value:
        ws_parts = [part for part in value.split() if part]
        if len(ws_parts) == 6:
            parsed: list[int] = []
            for part in ws_parts:
                if part.isdigit():
                    parsed.append(int(part))
                elif _HEX_PAIR_RE.fullmatch(part):
                    parsed.append(int(part, 16))
                else:
                    parsed = []
                    break
            if parsed:
                return _bytes_to_mac(parsed)

    if value.lower().startswith("0x"):
        value = value[2:]
    value = value.replace("-", "").replace(":", "").replace(".", "").replace(" ", "")
    if len(value) != 12:
        return None
    pairs = [value[i : i + 2] for i in range(0, 12, 2)]
    if not all(_HEX_PAIR_RE.fullmatch(pair) for pair in pairs):
        return None
    return ":".join(pair.lower() for pair in pairs)


def _is_valid_ip(value: str) -> bool:
    try:
        parsed = ipaddress.ip_address(value)
    except ValueError:
        return False
    return parsed.version == 4


def _build_session(router: RouterConfig, timeout: int, retries: int) -> SnmpSession:
    return SnmpSession(
        SnmpConfig(
            hostname=router.management_ip,
            version=router.snmp_version,
            community=router.community,
            username=router.username,
            security_level=router.security_level,
            auth_protocol=router.auth_protocol,
            auth_password=router.auth_password,
            priv_protocol=router.priv_protocol,
            priv_password=router.priv_password,
            timeout=timeout,
            retries=retries,
        )
    )


def load_arp_snmp(
    routers: Iterable[RouterConfig], timeout: int, retries: int
) -> list[MacEntry]:
    seen: set[tuple[str, str, str | None]] = set()
    entries: list[MacEntry] = []
    for router in routers:
        started = time.monotonic()
        before = len(entries)
        try:
            session = _build_session(router, timeout, retries)
            mac_by_oid = session.get_table(mibs.IP_NET_TO_MEDIA_PHYS_ADDRESS)
            ip_by_oid = session.get_table(mibs.IP_NET_TO_MEDIA_NET_ADDRESS)
            phys_oid_base = mibs.IP_NET_TO_MEDIA_PHYS_ADDRESS
            ip_oid_base = mibs.IP_NET_TO_MEDIA_NET_ADDRESS
            if not mac_by_oid:
                mac_by_oid = session.get_table(mibs.IP_NET_TO_PHYSICAL_PHYS_ADDRESS)
                ip_by_oid = session.get_table(mibs.IP_NET_TO_PHYSICAL_NET_ADDRESS)
                state_by_oid = session.get_table(mibs.IP_NET_TO_PHYSICAL_STATE)
                phys_oid_base = mibs.IP_NET_TO_PHYSICAL_PHYS_ADDRESS
                ip_oid_base = mibs.IP_NET_TO_PHYSICAL_NET_ADDRESS
                state_oid_base = mibs.IP_NET_TO_PHYSICAL_STATE
            else:
                state_by_oid = {}
                state_oid_base = ""
        except SnmpError:
            logger.warning(
                "Failed to collect ARP entries from router %s",
                router.name,
                extra={
                    "event": "get_arp_snmp_router",
                    "command": "get-arp",
                    "status": "error",
                    "target": router.name,
                    "router": router.name,
                    "elapsed_ms": int((time.monotonic() - started) * 1000),
                    "error_code": "SNMP_ERROR",
                    "error_type": "SnmpError",
                },
                exc_info=True,
            )
            continue

        for oid, raw_mac in mac_by_oid.items():
            suffix = oid.removeprefix(f"{phys_oid_base}.")
            if state_oid_base:
                state_oid = f"{state_oid_base}.{suffix}"
                # RFC 4293 ipNetToPhysicalState: 1=reachable
                if state_by_oid.get(state_oid) != "1":
                    continue
            ip_oid = f"{ip_oid_base}.{suffix}"
            ip = ip_by_oid.get(ip_oid)
            if not ip or not _is_valid_ip(ip):
                continue
            mac = _normalize_mac(raw_mac)
            if not mac:
                continue
            key = (mac, ip, router.name)
            if key in seen:
                continue
            seen.add(key)
            entries.append(
                MacEntry(mac=mac, ip=ip, hostname=None, switch=router.name, port=None)
            )
        logger.info(
            "Collected ARP entries from router",
            extra={
                "event": "get_arp_snmp_router",
                "command": "get-arp",
                "status": "success",
                "target": router.name,
                "router": router.name,
                "entries_count": len(entries) - before,
                "elapsed_ms": int((time.monotonic() - started) * 1000),
            },
        )
    entries.sort(key=lambda entry: (entry.switch or "", entry.ip or "", entry.mac))
    return entries
