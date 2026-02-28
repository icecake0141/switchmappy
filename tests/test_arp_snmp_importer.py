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

from switchmap_py.config import RouterConfig
from switchmap_py.importers import arp_snmp
from switchmap_py.snmp import mibs
from switchmap_py.snmp.session import SnmpError


class FakeSession:
    def __init__(self, tables: dict[str, dict[str, str]]) -> None:
        self.tables = tables

    def get_table(self, oid: str) -> dict[str, str]:
        return self.tables.get(oid, {})


def test_load_arp_snmp_collects_entries(monkeypatch):
    routers = [
        RouterConfig(
            name="r1",
            management_ip="192.0.2.1",
            community="public",
        )
    ]

    phys = {
        f"{mibs.IP_NET_TO_MEDIA_PHYS_ADDRESS}.1.192.0.2.10": "00:11:22:33:44:55",
        f"{mibs.IP_NET_TO_MEDIA_PHYS_ADDRESS}.1.192.0.2.11": "0x001122334466",
    }
    ips = {
        f"{mibs.IP_NET_TO_MEDIA_NET_ADDRESS}.1.192.0.2.10": "192.0.2.10",
        f"{mibs.IP_NET_TO_MEDIA_NET_ADDRESS}.1.192.0.2.11": "192.0.2.11",
    }
    fake_session = FakeSession(
        {
            mibs.IP_NET_TO_MEDIA_PHYS_ADDRESS: phys,
            mibs.IP_NET_TO_MEDIA_NET_ADDRESS: ips,
        }
    )

    monkeypatch.setattr(arp_snmp, "_build_session", lambda *_args, **_kwargs: fake_session)
    entries = arp_snmp.load_arp_snmp(routers, timeout=2, retries=1)

    assert len(entries) == 2
    assert entries[0].mac == "00:11:22:33:44:55"
    assert entries[0].ip == "192.0.2.10"
    assert entries[0].switch == "r1"
    assert entries[1].mac == "00:11:22:33:44:66"
    assert entries[1].ip == "192.0.2.11"


def test_load_arp_snmp_skips_invalid_rows(monkeypatch):
    routers = [
        RouterConfig(
            name="r1",
            management_ip="192.0.2.1",
            community="public",
        )
    ]
    fake_session = FakeSession(
        {
            mibs.IP_NET_TO_MEDIA_PHYS_ADDRESS: {
                f"{mibs.IP_NET_TO_MEDIA_PHYS_ADDRESS}.1.192.0.2.10": "not-a-mac",
            },
            mibs.IP_NET_TO_MEDIA_NET_ADDRESS: {
                f"{mibs.IP_NET_TO_MEDIA_NET_ADDRESS}.1.192.0.2.10": "bad-ip",
            },
        }
    )

    monkeypatch.setattr(arp_snmp, "_build_session", lambda *_args, **_kwargs: fake_session)
    entries = arp_snmp.load_arp_snmp(routers, timeout=2, retries=1)
    assert entries == []


def test_load_arp_snmp_continues_on_snmp_error(monkeypatch):
    routers = [
        RouterConfig(name="r1", management_ip="192.0.2.1", community="public"),
        RouterConfig(name="r2", management_ip="192.0.2.2", community="public"),
    ]

    calls = {"count": 0}

    def fake_build_session(router, _timeout, _retries):
        calls["count"] += 1
        if router.name == "r1":
            raise SnmpError("boom")
        return FakeSession(
            {
                mibs.IP_NET_TO_MEDIA_PHYS_ADDRESS: {
                    f"{mibs.IP_NET_TO_MEDIA_PHYS_ADDRESS}.1.192.0.2.20": "00-11-22-33-44-77",
                },
                mibs.IP_NET_TO_MEDIA_NET_ADDRESS: {
                    f"{mibs.IP_NET_TO_MEDIA_NET_ADDRESS}.1.192.0.2.20": "192.0.2.20",
                },
            }
        )

    monkeypatch.setattr(arp_snmp, "_build_session", fake_build_session)
    entries = arp_snmp.load_arp_snmp(routers, timeout=2, retries=1)

    assert calls["count"] == 2
    assert len(entries) == 1
    assert entries[0].switch == "r2"


def test_load_arp_snmp_deduplicates_entries(monkeypatch):
    routers = [
        RouterConfig(name="r1", management_ip="192.0.2.1", community="public"),
    ]
    fake_session = FakeSession(
        {
            mibs.IP_NET_TO_MEDIA_PHYS_ADDRESS: {
                f"{mibs.IP_NET_TO_MEDIA_PHYS_ADDRESS}.1.192.0.2.10": "00:11:22:33:44:55",
                f"{mibs.IP_NET_TO_MEDIA_PHYS_ADDRESS}.2.192.0.2.10": "00:11:22:33:44:55",
            },
            mibs.IP_NET_TO_MEDIA_NET_ADDRESS: {
                f"{mibs.IP_NET_TO_MEDIA_NET_ADDRESS}.1.192.0.2.10": "192.0.2.10",
                f"{mibs.IP_NET_TO_MEDIA_NET_ADDRESS}.2.192.0.2.10": "192.0.2.10",
            },
        }
    )
    monkeypatch.setattr(arp_snmp, "_build_session", lambda *_args, **_kwargs: fake_session)

    entries = arp_snmp.load_arp_snmp(routers, timeout=2, retries=1)
    assert len(entries) == 1
    assert entries[0].mac == "00:11:22:33:44:55"
    assert entries[0].ip == "192.0.2.10"


def test_load_arp_snmp_falls_back_to_ip_net_to_physical(monkeypatch):
    routers = [
        RouterConfig(name="r1", management_ip="192.0.2.1", community="public"),
    ]
    fake_session = FakeSession(
        {
            mibs.IP_NET_TO_MEDIA_PHYS_ADDRESS: {},
            mibs.IP_NET_TO_MEDIA_NET_ADDRESS: {},
            mibs.IP_NET_TO_PHYSICAL_PHYS_ADDRESS: {
                f"{mibs.IP_NET_TO_PHYSICAL_PHYS_ADDRESS}.1.1.192.0.2.30": "00:11:22:33:44:88",
            },
            mibs.IP_NET_TO_PHYSICAL_NET_ADDRESS: {
                f"{mibs.IP_NET_TO_PHYSICAL_NET_ADDRESS}.1.1.192.0.2.30": "192.0.2.30",
            },
            mibs.IP_NET_TO_PHYSICAL_STATE: {
                f"{mibs.IP_NET_TO_PHYSICAL_STATE}.1.1.192.0.2.30": "1",
            },
        }
    )
    monkeypatch.setattr(arp_snmp, "_build_session", lambda *_args, **_kwargs: fake_session)

    entries = arp_snmp.load_arp_snmp(routers, timeout=2, retries=1)
    assert len(entries) == 1
    assert entries[0].mac == "00:11:22:33:44:88"
    assert entries[0].ip == "192.0.2.30"


def test_load_arp_snmp_accepts_only_reachable_from_ip_net_to_physical(monkeypatch):
    routers = [
        RouterConfig(name="r1", management_ip="192.0.2.1", community="public"),
    ]
    fake_session = FakeSession(
        {
            mibs.IP_NET_TO_MEDIA_PHYS_ADDRESS: {},
            mibs.IP_NET_TO_MEDIA_NET_ADDRESS: {},
            mibs.IP_NET_TO_PHYSICAL_PHYS_ADDRESS: {
                f"{mibs.IP_NET_TO_PHYSICAL_PHYS_ADDRESS}.1.1.192.0.2.30": "00:11:22:33:44:88",
                f"{mibs.IP_NET_TO_PHYSICAL_PHYS_ADDRESS}.1.1.192.0.2.31": "00:11:22:33:44:99",
            },
            mibs.IP_NET_TO_PHYSICAL_NET_ADDRESS: {
                f"{mibs.IP_NET_TO_PHYSICAL_NET_ADDRESS}.1.1.192.0.2.30": "192.0.2.30",
                f"{mibs.IP_NET_TO_PHYSICAL_NET_ADDRESS}.1.1.192.0.2.31": "192.0.2.31",
            },
            mibs.IP_NET_TO_PHYSICAL_STATE: {
                f"{mibs.IP_NET_TO_PHYSICAL_STATE}.1.1.192.0.2.30": "1",
                f"{mibs.IP_NET_TO_PHYSICAL_STATE}.1.1.192.0.2.31": "2",
            },
        }
    )
    monkeypatch.setattr(arp_snmp, "_build_session", lambda *_args, **_kwargs: fake_session)

    entries = arp_snmp.load_arp_snmp(routers, timeout=2, retries=1)
    assert len(entries) == 1
    assert entries[0].ip == "192.0.2.30"


def test_load_arp_snmp_skips_ipv6_entries(monkeypatch):
    routers = [
        RouterConfig(name="r1", management_ip="192.0.2.1", community="public"),
    ]
    fake_session = FakeSession(
        {
            mibs.IP_NET_TO_MEDIA_PHYS_ADDRESS: {
                f"{mibs.IP_NET_TO_MEDIA_PHYS_ADDRESS}.1.2001:db8::1": "00:11:22:33:44:55",
            },
            mibs.IP_NET_TO_MEDIA_NET_ADDRESS: {
                f"{mibs.IP_NET_TO_MEDIA_NET_ADDRESS}.1.2001:db8::1": "2001:db8::1",
            },
        }
    )
    monkeypatch.setattr(arp_snmp, "_build_session", lambda *_args, **_kwargs: fake_session)

    entries = arp_snmp.load_arp_snmp(routers, timeout=2, retries=1)
    assert entries == []
