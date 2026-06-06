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

import json
from datetime import datetime, timezone
from pathlib import Path

from switchmap_py.model.neighbor import Neighbor
from switchmap_py.model.port import Port
from switchmap_py.model.switch import Switch
from switchmap_py.render.build import build_site
from switchmap_py.storage.idlesince_store import IdleSinceStore
from switchmap_py.storage.maclist_store import MacListStore


def test_build_site_renders_arp_correlation_from_maclist(tmp_path):
    template_dir = Path(__file__).resolve().parents[1] / "switchmap_py" / "render" / "templates"
    static_dir = tmp_path / "static"
    static_dir.mkdir()

    maclist_path = tmp_path / "maclist.json"
    maclist_path.write_text(
        json.dumps(
            [
                {
                    "mac": "00:11:22:33:44:55",
                    "ip": "192.0.2.100",
                    "hostname": "host-a",
                    "switch": None,
                    "port": None,
                }
            ]
        ),
        encoding="utf-8",
    )

    output_dir = tmp_path / "output"
    build_site(
        switches=[
            Switch(
                name="sw1",
                management_ip="192.0.2.1",
                vendor="test",
                ports=[
                    Port(
                        name="Gi1/0/1",
                        descr="Uplink",
                        admin_status="up",
                        oper_status="up",
                        speed=1000,
                        vlan="10",
                        macs=["00:11:22:33:44:55"],
                    )
                ],
            )
        ],
        failed_switches=[],
        output_dir=output_dir,
        template_dir=template_dir,
        static_dir=static_dir,
        idlesince_store=IdleSinceStore(tmp_path / "idlesince"),
        maclist_store=MacListStore(maclist_path),
        build_date=datetime(2024, 1, 1, tzinfo=timezone.utc),
    )

    switch_html = (output_dir / "switches" / "sw1.html").read_text(encoding="utf-8")
    ports_html = (output_dir / "ports" / "index.html").read_text(encoding="utf-8")
    endpoints_html = (output_dir / "endpoints" / "index.html").read_text(encoding="utf-8")
    search_index = json.loads((output_dir / "search" / "index.json").read_text(encoding="utf-8"))
    assert "192.0.2.100 (host-a)" in switch_html
    assert "192.0.2.100 (host-a)" in ports_html
    assert "Endpoints - SwitchMappy" in endpoints_html
    assert "host-a" in endpoints_html
    assert search_index["endpoint_correlations"] == [
        {
            "hostname": "host-a",
            "ip": "192.0.2.100",
            "mac": "00:11:22:33:44:55",
            "port": "Gi1/0/1",
            "port_role": "unknown",
            "switch": "sw1",
            "vendor": "",
            "warning": "",
        }
    ]


def test_build_site_deduplicates_arp_entries_and_prefers_hostname(tmp_path):
    template_dir = Path(__file__).resolve().parents[1] / "switchmap_py" / "render" / "templates"
    static_dir = tmp_path / "static"
    static_dir.mkdir()

    maclist_path = tmp_path / "maclist.json"
    maclist_path.write_text(
        json.dumps(
            [
                {
                    "mac": "00:11:22:33:44:55",
                    "ip": "192.0.2.100",
                    "hostname": None,
                    "switch": None,
                    "port": None,
                },
                {
                    "mac": "00:11:22:33:44:55",
                    "ip": "192.0.2.100",
                    "hostname": "host-a",
                    "switch": None,
                    "port": None,
                },
                {
                    "mac": "00:11:22:33:44:55",
                    "ip": "192.0.2.101",
                    "hostname": "host-b",
                    "switch": None,
                    "port": None,
                },
                {
                    "mac": "00:11:22:33:44:55",
                    "ip": "192.0.2.101",
                    "hostname": "host-b",
                    "switch": None,
                    "port": None,
                },
            ]
        ),
        encoding="utf-8",
    )

    output_dir = tmp_path / "output"
    build_site(
        switches=[
            Switch(
                name="sw1",
                management_ip="192.0.2.1",
                vendor="test",
                ports=[
                    Port(
                        name="Gi1/0/1",
                        descr="Uplink",
                        admin_status="up",
                        oper_status="up",
                        speed=1000,
                        vlan="10",
                        macs=["00:11:22:33:44:55"],
                    )
                ],
            )
        ],
        failed_switches=[],
        output_dir=output_dir,
        template_dir=template_dir,
        static_dir=static_dir,
        idlesince_store=IdleSinceStore(tmp_path / "idlesince"),
        maclist_store=MacListStore(maclist_path),
        build_date=datetime(2024, 1, 1, tzinfo=timezone.utc),
    )

    switch_html = (output_dir / "switches" / "sw1.html").read_text(encoding="utf-8")
    search_index = json.loads((output_dir / "search" / "index.json").read_text(encoding="utf-8"))
    assert switch_html.count("192.0.2.100 (host-a)") == 1
    assert switch_html.count("192.0.2.101 (host-b)") == 1
    assert search_index["endpoint_correlations"] == [
        {
            "hostname": "host-a",
            "ip": "192.0.2.100",
            "mac": "00:11:22:33:44:55",
            "port": "Gi1/0/1",
            "port_role": "unknown",
            "switch": "sw1",
            "vendor": "",
            "warning": "",
        },
        {
            "hostname": "host-b",
            "ip": "192.0.2.101",
            "mac": "00:11:22:33:44:55",
            "port": "Gi1/0/1",
            "port_role": "unknown",
            "switch": "sw1",
            "vendor": "",
            "warning": "",
        },
    ]


def test_build_site_marks_duplicate_endpoint_macs(tmp_path):
    template_dir = Path(__file__).resolve().parents[1] / "switchmap_py" / "render" / "templates"
    static_dir = tmp_path / "static"
    static_dir.mkdir()

    maclist_path = tmp_path / "maclist.json"
    maclist_path.write_text(
        json.dumps(
            [
                {
                    "mac": "00:11:22:33:44:55",
                    "ip": "192.0.2.100",
                    "hostname": "host-a",
                    "switch": None,
                    "port": None,
                }
            ]
        ),
        encoding="utf-8",
    )

    output_dir = tmp_path / "output"
    build_site(
        switches=[
            Switch(
                name="sw1",
                management_ip="192.0.2.1",
                vendor="test",
                ports=[
                    Port(
                        name="Gi1/0/1",
                        descr="Access",
                        admin_status="up",
                        oper_status="up",
                        speed=1000,
                        vlan="10",
                        macs=["00:11:22:33:44:55"],
                    )
                ],
            ),
            Switch(
                name="sw2",
                management_ip="192.0.2.2",
                vendor="test",
                ports=[
                    Port(
                        name="Gi1/0/2",
                        descr="Access",
                        admin_status="up",
                        oper_status="up",
                        speed=1000,
                        vlan="10",
                        macs=["00:11:22:33:44:55"],
                    )
                ],
            ),
        ],
        failed_switches=[],
        output_dir=output_dir,
        template_dir=template_dir,
        static_dir=static_dir,
        idlesince_store=IdleSinceStore(tmp_path / "idlesince"),
        maclist_store=MacListStore(maclist_path),
        build_date=datetime(2024, 1, 1, tzinfo=timezone.utc),
    )

    search_index = json.loads((output_dir / "search" / "index.json").read_text(encoding="utf-8"))
    warnings = {entry["warning"] for entry in search_index["endpoint_correlations"]}
    assert warnings == {"duplicate MAC"}


def test_build_site_marks_configured_trunk_and_network_neighbor_roles(tmp_path):
    template_dir = Path(__file__).resolve().parents[1] / "switchmap_py" / "render" / "templates"
    static_dir = tmp_path / "static"
    static_dir.mkdir()
    maclist_path = tmp_path / "maclist.json"
    maclist_path.write_text(
        json.dumps(
            [
                {
                    "mac": "00:11:22:33:44:55",
                    "ip": "192.0.2.100",
                    "hostname": "host-a",
                    "switch": None,
                    "port": None,
                }
            ]
        ),
        encoding="utf-8",
    )

    output_dir = tmp_path / "output"
    build_site(
        switches=[
            Switch(
                name="sw1",
                management_ip="192.0.2.1",
                vendor="test",
                ports=[
                    Port(
                        name="Gi1/0/1",
                        descr="Configured",
                        admin_status="up",
                        oper_status="up",
                        speed=1000,
                        vlan="10",
                        macs=["00:11:22:33:44:55"],
                        is_trunk=True,
                    ),
                    Port(
                        name="Gi1/0/2",
                        descr="Neighbor",
                        admin_status="up",
                        oper_status="up",
                        speed=1000,
                        vlan="10",
                        neighbors=[Neighbor(device="dist-sw1", protocol="lldp", port="Gi1/0/48")],
                    ),
                ],
            )
        ],
        failed_switches=[],
        output_dir=output_dir,
        template_dir=template_dir,
        static_dir=static_dir,
        idlesince_store=IdleSinceStore(tmp_path / "idlesince"),
        maclist_store=MacListStore(maclist_path),
        build_date=datetime(2024, 1, 1, tzinfo=timezone.utc),
    )

    switch_html = (output_dir / "switches" / "sw1.html").read_text(encoding="utf-8")
    endpoints_html = (output_dir / "endpoints" / "index.html").read_text(encoding="utf-8")
    search_index = json.loads((output_dir / "search" / "index.json").read_text(encoding="utf-8"))
    ports = {port["name"]: port for port in search_index["switches"][0]["ports"]}
    assert ports["Gi1/0/1"]["role"] == "configured_trunk"
    assert ports["Gi1/0/1"]["role_confidence"] == "configured"
    assert ports["Gi1/0/2"]["role"] == "network_neighbor"
    assert ports["Gi1/0/2"]["role_confidence"] == "medium"
    assert search_index["endpoint_correlations"][0]["port_role"] == "configured_trunk"
    assert "configured_trunk" in switch_html
    assert "network_neighbor" in switch_html
    assert "configured_trunk" in endpoints_html
