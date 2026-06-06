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

import socket

from switchmap_py.importers.hostname_resolver import resolve_missing_hostnames
from switchmap_py.model.mac import MacEntry


def test_resolve_missing_hostnames_fills_blank_hostname():
    entries = [
        MacEntry(
            mac="00:11:22:33:44:55",
            ip="192.0.2.10",
            hostname=None,
            switch=None,
            port=None,
        )
    ]

    resolved = resolve_missing_hostnames(
        entries,
        resolver=lambda ip: (f"host-{ip}.example.", [], [ip]),
    )

    assert resolved[0].hostname == "host-192.0.2.10.example"


def test_resolve_missing_hostnames_keeps_existing_hostname():
    entries = [
        MacEntry(
            mac="00:11:22:33:44:55",
            ip="192.0.2.10",
            hostname="existing-host",
            switch="sw1",
            port="Gi1/0/1",
        )
    ]

    resolved = resolve_missing_hostnames(
        entries,
        resolver=lambda ip: (f"host-{ip}.example", [], [ip]),
    )

    assert resolved == entries


def test_resolve_missing_hostnames_ignores_lookup_failures():
    def fail(_ip: str):
        raise socket.herror("not found")

    entries = [
        MacEntry(
            mac="00:11:22:33:44:55",
            ip="192.0.2.10",
            hostname=None,
            switch=None,
            port=None,
        )
    ]

    resolved = resolve_missing_hostnames(entries, resolver=fail)

    assert resolved == entries
