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
from switchmap_py.storage.idlesince_store import IdleSinceStore
from switchmap_py.storage.maclist_store import MacListStore


def test_build_site_generates_vlans_page(tmp_path):
    template_dir = Path(__file__).resolve().parents[1] / "switchmap_py" / "render" / "templates"
    static_dir = tmp_path / "static"
    static_dir.mkdir()
    maclist_path = tmp_path / "maclist.json"
    maclist_path.write_text(
        json.dumps(
            [
                {
                    "mac": "00:11:22:33:44:55",
                    "ip": "192.0.2.10",
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
                        descr="User",
                        admin_status="up",
                        oper_status="up",
                        speed=1000,
                        vlan="10",
                        macs=["00:11:22:33:44:55"],
                    )
                ],
                vlans=[
                    Vlan(
                        vlan_id="10",
                        name="Users",
                        ports=["Gi1/0/1", "Gi1/0/2"],
                        source="named",
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

    vlan_page = (output_dir / "vlans" / "index.html").read_text(encoding="utf-8")
    assert "VLANs" in vlan_page
    assert "Users" in vlan_page
    assert "named" in vlan_page
    assert "<th>MACs</th>" in vlan_page
    assert "<th>Endpoints</th>" in vlan_page
    assert 'id="vlanFilter"' in vlan_page
    assert 'href="/switches/sw1.html"' in vlan_page
    assert 'href="/switches/sw1.html#port-Gi1-0-1"' in vlan_page
    assert 'href="/switches/sw1.html#port-Gi1-0-2"' in vlan_page
