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

from datetime import datetime, timezone
from pathlib import Path

from switchmap_py.model.port import Port
from switchmap_py.model.switch import Switch
from switchmap_py.render.build import build_site
from switchmap_py.storage.idlesince_store import IdleSinceStore
from switchmap_py.storage.maclist_store import MacListStore


def test_build_site_copies_binary_assets(tmp_path):
    template_dir = Path(__file__).resolve().parents[1] / "switchmap_py" / "render" / "templates"
    static_dir = tmp_path / "static"
    static_dir.mkdir()

    binary_data = b"\x00\x01\xffbinary"
    (static_dir / "asset.bin").write_bytes(binary_data)

    nested_dir = static_dir / "nested"
    nested_dir.mkdir()
    nested_data = b"\x10\x11nested"
    (nested_dir / "nested.bin").write_bytes(nested_data)

    output_dir = tmp_path / "output"
    build_site(
        switches=[
            Switch(
                name="sw1",
                management_ip="192.0.2.1",
                vendor="test",
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

    assert (output_dir / "asset.bin").read_bytes() == binary_data
    assert (output_dir / "nested" / "nested.bin").read_bytes() == nested_data


def test_build_site_escapes_xss_in_user_controlled_data(tmp_path):
    """
    Regression test for XSS vulnerability in Jinja2 autoescape configuration.
    
    Previously, templates with .html.j2 extension were NOT autoescaped because
    select_autoescape(["html"]) did not match the .j2 extension.
    
    This test ensures that XSS-prone data from SNMP, CSV, or user input
    (switch names, port descriptions, failed switch names) is properly escaped
    in the generated HTML to prevent stored XSS attacks.
    
    Tests multiple XSS vectors: script tags, event handlers, HTML attributes.
    """
    template_dir = Path(__file__).resolve().parents[1] / "switchmap_py" / "render" / "templates"
    static_dir = tmp_path / "static"
    static_dir.mkdir()
    
    # Multiple XSS payloads that should be escaped
    xss_script = '<script>alert("XSS")</script>'
    xss_img = '<img src=x onerror=alert(1)>'
    xss_event = '<div onclick="alert(2)">click</div>'
    
    output_dir = tmp_path / "output"
    build_site(
        switches=[
            Switch(
                name="test-switch",
                management_ip="192.0.2.10",
                vendor=f"Evil Vendor {xss_script}",
                ports=[
                    Port(
                        name="eth0",
                        descr=xss_img,
                        admin_status="up",
                        oper_status="up",
                        speed=1000,
                        vlan="1",
                    ),
                    Port(
                        name="eth1",
                        descr=xss_event,
                        admin_status="up",
                        oper_status="down",
                        speed=100,
                        vlan="2",
                    ),
                ],
            )
        ],
        failed_switches=[f"bad-switch{xss_script}"],
        output_dir=output_dir,
        template_dir=template_dir,
        static_dir=static_dir,
        idlesince_store=IdleSinceStore(tmp_path / "idlesince"),
        maclist_store=MacListStore(tmp_path / "maclist.json"),
        build_date=datetime(2024, 1, 1, tzinfo=timezone.utc),
    )
    
    # Check index.html - should escape failed switch name
    index_html = (output_dir / "index.html").read_text()
    assert xss_script not in index_html, "Script tag should not appear unescaped in index.html"
    assert "&lt;script&gt;" in index_html, "Script tags should be HTML-escaped in index.html"
    
    # Check switch page - should escape all XSS vectors in port descriptions
    switch_html = (output_dir / "switches" / "test-switch.html").read_text()
    assert xss_script not in switch_html, "Script tag should not appear unescaped in switch.html"
    assert xss_img not in switch_html, "Img onerror should not appear unescaped in switch.html"
    assert xss_event not in switch_html, "Event handler should not appear unescaped in switch.html"
    assert "&lt;img" in switch_html, "Img tags should be HTML-escaped"
    assert "&lt;div" in switch_html, "Div tags should be HTML-escaped"
    
    # Check ports page - should escape all XSS vectors
    ports_html = (output_dir / "ports" / "index.html").read_text()
    assert xss_script not in ports_html, "Script tag should not appear unescaped in ports.html"
    assert xss_img not in ports_html, "Img onerror should not appear unescaped in ports.html"
    assert xss_event not in ports_html, "Event handler should not appear unescaped in ports.html"
    assert "&lt;img" in ports_html, "Img tags should be HTML-escaped"
    assert "&lt;div" in ports_html, "Div tags should be HTML-escaped"
