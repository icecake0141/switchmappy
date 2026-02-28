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

from switchmap_py.model.port import Port
from switchmap_py.model.switch import Switch
from switchmap_py.model.vlan import Vlan
from switchmap_py.render.build import build_site
from switchmap_py.storage.idlesince_store import IdleSinceStore, PortIdleState
from switchmap_py.storage.maclist_store import MacListStore


def test_build_site_integration_failed_switch_vlan_and_arp(tmp_path):
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
                    "switch": "sw-ok",
                    "port": "Gi1/0/1",
                }
            ]
        ),
        encoding="utf-8",
    )

    idlesince_store = IdleSinceStore(tmp_path / "idlesince")
    idlesince_store.save(
        "sw-ok",
        {
            "Gi1/0/1": PortIdleState(
                port="Gi1/0/1",
                idle_since=datetime(2023, 11, 1, tzinfo=timezone.utc),
                last_active=None,
            )
        },
    )

    build_site(
        switches=[
            Switch(
                name="sw-ok",
                management_ip="192.0.2.10",
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
                        is_trunk=True,
                    )
                ],
                vlans=[Vlan(vlan_id="10", name="Users", ports=["Gi1/0/1"])],
            )
        ],
        failed_switches=["sw-failed"],
        output_dir=tmp_path / "output",
        template_dir=template_dir,
        static_dir=static_dir,
        idlesince_store=idlesince_store,
        maclist_store=MacListStore(maclist_path),
        build_date=datetime(2024, 1, 1, tzinfo=timezone.utc),
        unused_after_days=30,
    )

    index_html = (tmp_path / "output" / "index.html").read_text(encoding="utf-8")
    vlan_html = (tmp_path / "output" / "vlans" / "index.html").read_text(encoding="utf-8")
    switch_html = (tmp_path / "output" / "switches" / "sw-ok.html").read_text(encoding="utf-8")
    ports_html = (tmp_path / "output" / "ports" / "index.html").read_text(encoding="utf-8")
    assert "sw-failed" in index_html
    assert "Users" in vlan_html
    assert "192.0.2.100 (host-a)" in switch_html
    assert "Unused (>= 30d)" in switch_html
    assert "Unused (>= 30d)" in ports_html
    assert "yes" in switch_html
    assert "yes" in ports_html
