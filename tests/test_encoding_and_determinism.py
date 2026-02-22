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

"""
Tests for UTF-8 encoding and deterministic JSON output.

This test suite verifies that:
1. All file writes use explicit UTF-8 encoding
2. JSON output is deterministic (sort_keys=True)
3. JSON serialization uses consistent approach (asdict for dataclasses)
"""

import json
from datetime import datetime, timezone
from pathlib import Path

from switchmap_py.model.mac import MacEntry
from switchmap_py.model.port import Port
from switchmap_py.model.switch import Switch
from switchmap_py.render.build import build_site
from switchmap_py.search.index_builder import load_index
from switchmap_py.storage.idlesince_store import IdleSinceStore, PortIdleState
from switchmap_py.storage.maclist_store import MacListStore


def test_html_files_use_utf8_encoding(tmp_path):
    """
    Verify that all HTML files are written with UTF-8 encoding.

    This test creates HTML with UTF-8 characters (Japanese, emoji, etc.)
    and verifies they are correctly preserved in the output.
    """
    template_dir = Path(__file__).resolve().parents[1] / "switchmap_py" / "render" / "templates"
    static_dir = tmp_path / "static"
    static_dir.mkdir()

    # UTF-8 test data: Japanese katakana (スイッチ), kanji (説明), and emoji (🔧📡)
    # for comprehensive multi-byte character encoding verification
    utf8_switch_name = "スイッチ-switch-🔧"
    utf8_port_descr = "ポート説明 - Port Description 📡"

    output_dir = tmp_path / "output"
    build_site(
        switches=[
            Switch(
                name=utf8_switch_name,
                management_ip="192.0.2.10",
                vendor="テストベンダー",
                ports=[
                    Port(
                        name="eth0",
                        descr=utf8_port_descr,
                        admin_status="up",
                        oper_status="up",
                        speed=1000,
                        vlan="1",
                    ),
                ],
            )
        ],
        failed_switches=[],
        output_dir=output_dir,
        template_dir=template_dir,
        static_dir=static_dir,
        idlesince_store=IdleSinceStore(tmp_path / "idlesince"),
        maclist_store=MacListStore(tmp_path / "maclist.json"),
        build_date=datetime(2024, 1, 1, tzinfo=timezone.utc),
    )

    # Verify index.html contains UTF-8 characters
    index_html = (output_dir / "index.html").read_text(encoding="utf-8")
    assert "スイッチ" in index_html
    assert "🔧" in index_html

    # Verify switch HTML contains UTF-8 characters
    switch_html = (output_dir / "switches" / f"{utf8_switch_name}.html").read_text(encoding="utf-8")
    assert "ポート説明" in switch_html
    assert "📡" in switch_html

    # Verify ports HTML contains UTF-8 characters
    ports_html = (output_dir / "ports" / "index.html").read_text(encoding="utf-8")
    assert "ポート説明" in ports_html


def test_search_json_uses_utf8_encoding(tmp_path):
    """
    Verify that search index JSON is written with UTF-8 encoding.

    This test ensures JSON files with UTF-8 content are properly encoded.
    """
    template_dir = Path(__file__).resolve().parents[1] / "switchmap_py" / "render" / "templates"
    static_dir = tmp_path / "static"
    static_dir.mkdir()

    # MAC list with UTF-8 characters
    maclist_file = tmp_path / "maclist.json"
    maclist_data = [
        {
            "mac": "00:11:22:33:44:55",
            "ip": "192.0.2.100",
            "hostname": "ホスト名-host-🖥️",
            "switch": "sw1",
            "port": "eth0",
        }
    ]
    maclist_file.write_text(json.dumps(maclist_data), encoding="utf-8")

    output_dir = tmp_path / "output"
    build_site(
        switches=[
            Switch(
                name="sw1",
                management_ip="192.0.2.1",
                vendor="vendor",
            )
        ],
        failed_switches=[],
        output_dir=output_dir,
        template_dir=template_dir,
        static_dir=static_dir,
        idlesince_store=IdleSinceStore(tmp_path / "idlesince"),
        maclist_store=MacListStore(maclist_file),
        build_date=datetime(2024, 1, 1, tzinfo=timezone.utc),
    )

    # Verify search index JSON contains UTF-8 characters
    search_json_text = (output_dir / "search" / "index.json").read_text(encoding="utf-8")
    assert "ホスト名" in search_json_text
    assert "🖥️" in search_json_text

    # Verify it can be loaded as JSON
    search_data = json.loads(search_json_text)
    assert search_data["maclist"][0]["hostname"] == "ホスト名-host-🖥️"


def test_search_json_is_deterministic(tmp_path):
    """
    Verify that search index JSON has deterministic output (keys are sorted).

    This test builds the site twice with the same data and verifies that
    the JSON output is identical (byte-for-byte).
    """
    template_dir = Path(__file__).resolve().parents[1] / "switchmap_py" / "render" / "templates"
    static_dir = tmp_path / "static"
    static_dir.mkdir()

    # Create deterministic test data
    switches = [
        Switch(
            name="zulu-switch",
            management_ip="192.0.2.26",
            vendor="vendor-z",
            ports=[
                Port(
                    name="eth2",
                    descr="port-2",
                    admin_status="up",
                    oper_status="up",
                    speed=100,
                    vlan="2",
                ),
                Port(
                    name="eth1",
                    descr="port-1",
                    admin_status="up",
                    oper_status="down",
                    speed=1000,
                    vlan="1",
                ),
            ],
        ),
        Switch(
            name="alpha-switch",
            management_ip="192.0.2.1",
            vendor="vendor-a",
        ),
    ]

    build_date = datetime(2024, 6, 15, 12, 30, 45, tzinfo=timezone.utc)

    # Build site first time
    output_dir1 = tmp_path / "output1"
    build_site(
        switches=switches,
        failed_switches=["zeta-switch", "beta-switch"],
        output_dir=output_dir1,
        template_dir=template_dir,
        static_dir=static_dir,
        idlesince_store=IdleSinceStore(tmp_path / "idlesince1"),
        maclist_store=MacListStore(tmp_path / "maclist1.json"),
        build_date=build_date,
    )

    # Build site second time with same data
    output_dir2 = tmp_path / "output2"
    build_site(
        switches=switches,
        failed_switches=["zeta-switch", "beta-switch"],
        output_dir=output_dir2,
        template_dir=template_dir,
        static_dir=static_dir,
        idlesince_store=IdleSinceStore(tmp_path / "idlesince2"),
        maclist_store=MacListStore(tmp_path / "maclist2.json"),
        build_date=build_date,
    )

    # Read both JSON files
    json1 = (output_dir1 / "search" / "index.json").read_bytes()
    json2 = (output_dir2 / "search" / "index.json").read_bytes()

    # Verify byte-for-byte identical output
    assert json1 == json2, "JSON output should be deterministic (identical across builds)"

    # Parse and verify keys are sorted
    data = json.loads(json1)

    # Check top-level keys are sorted
    top_keys = list(data.keys())
    assert top_keys == sorted(top_keys), "Top-level JSON keys should be sorted"

    # Check switch object keys are sorted
    if data["switches"]:
        switch_keys = list(data["switches"][0].keys())
        assert switch_keys == sorted(switch_keys), "Switch keys should be sorted"


def test_maclist_store_uses_utf8_and_asdict(tmp_path):
    """
    Verify that MacListStore uses UTF-8 encoding and asdict for serialization.
    """
    maclist_file = tmp_path / "maclist.json"
    store = MacListStore(maclist_file)

    # Create entries with UTF-8 characters
    entries = [
        MacEntry(
            mac="00:11:22:33:44:55",
            ip="192.0.2.1",
            hostname="ホスト-A-🖥️",
            switch="sw1",
            port="eth0",
        ),
        MacEntry(
            mac="aa:bb:cc:dd:ee:ff",
            ip="192.0.2.2",
            hostname="ホスト-B-💻",
            switch="sw2",
            port="eth1",
        ),
    ]

    # Save entries
    store.save(entries)

    # Verify file was written with UTF-8
    content = maclist_file.read_text(encoding="utf-8")
    assert "ホスト-A-🖥️" in content
    assert "ホスト-B-💻" in content

    # Verify JSON is valid and keys are sorted
    data = json.loads(content)
    assert len(data) == 2

    # Check that keys are sorted in the JSON output
    for entry in data:
        keys = list(entry.keys())
        assert keys == sorted(keys), "MacEntry keys should be sorted in JSON"

    # Verify roundtrip
    loaded_entries = store.load()
    assert len(loaded_entries) == 2
    assert loaded_entries[0].hostname == "ホスト-A-🖥️"
    assert loaded_entries[1].hostname == "ホスト-B-💻"


def test_idlesince_store_uses_utf8_encoding(tmp_path):
    """
    Verify that IdleSinceStore uses UTF-8 encoding.
    """
    store = IdleSinceStore(tmp_path / "idlesince")

    # Create idle state data
    switch_name = "スイッチ-1"
    data = {
        "ポート-1": PortIdleState(
            port="ポート-1",
            idle_since=datetime(2024, 1, 1, tzinfo=timezone.utc),
            last_active=None,
        ),
        "ポート-2": PortIdleState(
            port="ポート-2",
            idle_since=None,
            last_active=datetime(2024, 1, 2, tzinfo=timezone.utc),
        ),
    }

    # Save data
    store.save(switch_name, data)

    # Verify file was written with UTF-8
    idle_file = tmp_path / "idlesince" / f"{switch_name}.json"
    content = idle_file.read_text(encoding="utf-8")
    assert "ポート-1" in content
    assert "ポート-2" in content

    # Verify JSON keys are sorted
    json_data = json.loads(content)
    keys = list(json_data.keys())
    assert keys == sorted(keys), "Port keys should be sorted in JSON"

    # Verify roundtrip
    loaded_data = store.load(switch_name)
    assert "ポート-1" in loaded_data
    assert "ポート-2" in loaded_data


def test_search_index_loader_uses_utf8_encoding(tmp_path):
    """
    Verify that load_index function uses UTF-8 encoding.
    """
    output_dir = tmp_path / "output"
    output_dir.mkdir()
    (output_dir / "search").mkdir()

    # Create search index with UTF-8 content
    search_data = {
        "generated_at": "2024-01-01T00:00:00+00:00",
        "switches": [
            {
                "name": "スイッチ-1",
                "management_ip": "192.0.2.1",
                "vendor": "ベンダー",
                "ports": [],
                "vlans": [],
            }
        ],
        "maclist": [],
        "failed_switches": [],
    }

    search_file = output_dir / "search" / "index.json"
    search_file.write_text(json.dumps(search_data), encoding="utf-8")

    # Load using the function
    loaded_data = load_index(output_dir)

    # Verify UTF-8 characters are preserved
    assert loaded_data["switches"][0]["name"] == "スイッチ-1"
    assert loaded_data["switches"][0]["vendor"] == "ベンダー"


def test_json_schema_consistency_with_asdict(tmp_path):
    """
    Verify that search JSON uses asdict() for both switches and maclist.

    This ensures consistent JSON schema representation across all dataclasses.
    """
    template_dir = Path(__file__).resolve().parents[1] / "switchmap_py" / "render" / "templates"
    static_dir = tmp_path / "static"
    static_dir.mkdir()

    # Create MAC list
    maclist_file = tmp_path / "maclist.json"
    maclist_data = [
        {
            "mac": "00:11:22:33:44:55",
            "ip": "192.0.2.100",
            "hostname": "host1",
            "switch": "sw1",
            "port": "eth0",
        }
    ]
    maclist_file.write_text(json.dumps(maclist_data), encoding="utf-8")

    output_dir = tmp_path / "output"
    build_site(
        switches=[
            Switch(
                name="sw1",
                management_ip="192.0.2.1",
                vendor="vendor1",
                ports=[
                    Port(
                        name="eth0",
                        descr="Test Port",
                        admin_status="up",
                        oper_status="up",
                        speed=1000,
                        vlan="1",
                    ),
                ],
            )
        ],
        failed_switches=[],
        output_dir=output_dir,
        template_dir=template_dir,
        static_dir=static_dir,
        idlesince_store=IdleSinceStore(tmp_path / "idlesince"),
        maclist_store=MacListStore(maclist_file),
        build_date=datetime(2024, 1, 1, tzinfo=timezone.utc),
    )

    # Load and verify JSON structure
    search_json = json.loads((output_dir / "search" / "index.json").read_text(encoding="utf-8"))

    # Verify switches are properly serialized
    assert "switches" in search_json
    assert len(search_json["switches"]) == 1
    switch = search_json["switches"][0]
    assert "name" in switch
    assert "management_ip" in switch
    assert "vendor" in switch
    assert "ports" in switch
    assert "vlans" in switch

    # Verify ports within switch are properly serialized
    assert len(switch["ports"]) == 1
    port = switch["ports"][0]
    assert "name" in port
    assert "descr" in port
    assert "admin_status" in port
    assert "oper_status" in port
    assert "speed" in port
    assert "vlan" in port

    # Verify maclist entries are properly serialized
    assert "maclist" in search_json
    assert len(search_json["maclist"]) == 1
    mac_entry = search_json["maclist"][0]
    assert "mac" in mac_entry
    assert "ip" in mac_entry
    assert "hostname" in mac_entry
    assert "switch" in mac_entry
    assert "port" in mac_entry

    # Verify all expected fields are present (asdict includes all dataclass fields)
    # MacEntry has exactly these 5 fields
    assert set(mac_entry.keys()) == {"mac", "ip", "hostname", "switch", "port"}
