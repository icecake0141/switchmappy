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
import socket
from collections.abc import Callable, Iterable

from switchmap_py.model.mac import MacEntry

logger = logging.getLogger(__name__)

Resolver = Callable[[str], tuple[str, list[str], list[str]]]


def resolve_missing_hostnames(
    entries: Iterable[MacEntry],
    *,
    timeout: float = 1.0,
    resolver: Resolver = socket.gethostbyaddr,
) -> list[MacEntry]:
    previous_timeout = socket.getdefaulttimeout()
    socket.setdefaulttimeout(timeout)
    try:
        return [_resolve_entry(entry, resolver=resolver) for entry in entries]
    finally:
        socket.setdefaulttimeout(previous_timeout)


def _resolve_entry(entry: MacEntry, *, resolver: Resolver) -> MacEntry:
    if entry.hostname or not entry.ip:
        return entry
    try:
        hostname, _aliases, _addresses = resolver(entry.ip)
    except (OSError, socket.herror, socket.gaierror, TimeoutError) as exc:
        logger.debug("Failed to resolve hostname for %s: %s", entry.ip, exc)
        return entry
    hostname = hostname.rstrip(".")
    if not hostname:
        return entry
    return MacEntry(
        mac=entry.mac,
        ip=entry.ip,
        hostname=hostname,
        switch=entry.switch,
        port=entry.port,
    )
