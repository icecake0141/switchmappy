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
from typing import Iterable

from switchmap_py.config import RouterConfig
from switchmap_py.model.mac import MacEntry
from switchmap_py.snmp import mibs
from switchmap_py.snmp.session import SnmpConfig, SnmpError, SnmpSession

logger = logging.getLogger(__name__)

_HEX_PAIR_RE = re.compile(r"^[0-9a-fA-F]{2}$")


def _normalize_mac(raw: str) -> str | None:
    value = raw.strip()
    if not value:
        return None
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
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def _build_session(router: RouterConfig, timeout: int, retries: int) -> SnmpSession:
    return SnmpSession(
        SnmpConfig(
            hostname=router.management_ip,
            version=router.snmp_version,
            community=router.community,
            timeout=timeout,
            retries=retries,
        )
    )


def load_arp_snmp(
    routers: Iterable[RouterConfig], timeout: int, retries: int
) -> list[MacEntry]:
    entries: list[MacEntry] = []
    for router in routers:
        try:
            session = _build_session(router, timeout, retries)
            mac_by_oid = session.get_table(mibs.IP_NET_TO_MEDIA_PHYS_ADDRESS)
            ip_by_oid = session.get_table(mibs.IP_NET_TO_MEDIA_NET_ADDRESS)
        except SnmpError:
            logger.warning(
                "Failed to collect ARP entries from router %s",
                router.name,
                exc_info=True,
            )
            continue

        for oid, raw_mac in mac_by_oid.items():
            suffix = oid.removeprefix(f"{mibs.IP_NET_TO_MEDIA_PHYS_ADDRESS}.")
            ip_oid = f"{mibs.IP_NET_TO_MEDIA_NET_ADDRESS}.{suffix}"
            ip = ip_by_oid.get(ip_oid)
            if not ip or not _is_valid_ip(ip):
                continue
            mac = _normalize_mac(raw_mac)
            if not mac:
                continue
            entries.append(
                MacEntry(
                    mac=mac,
                    ip=ip,
                    hostname=None,
                    switch=router.name,
                    port=None,
                )
            )
    return entries
