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
Security regression tests for XSS and injection protection in HTML rendering.

This test suite ensures that the Jinja2 autoescape configuration properly
escapes all user-controlled data to prevent Cross-Site Scripting (XSS) attacks.

Background:
-----------
Previously, the autoescape configuration used select_autoescape(["html"]), which
only matched files ending in .html. Since the templates use .html.j2 extension,
they were NOT autoescaped, creating an XSS vulnerability.

The fix (in build.py) changed the configuration to:
    select_autoescape(["html", "j2"])

This ensures all templates with .j2 extension are autoescaped.

Test Coverage:
--------------
These tests verify that XSS payloads are properly escaped in:
1. Switch names (in titles, headers, links, href attributes)
2. Port fields (name, description, admin_status, oper_status, vlan)
3. Switch vendor and management IP fields
4. Failed switch names in the index page
5. MAC list data (hostname, IP, MAC) in search JSON
6. All HTML contexts (text content, attributes, JSON)

Regression Verification:
------------------------
To verify these tests catch the vulnerability:
- With OLD config (["html"]): XSS payloads are NOT escaped, tests would FAIL
- With NEW config (["html", "j2"]): XSS payloads ARE escaped, tests PASS

User-Controlled Data Sources:
------------------------------
The following fields can contain malicious data from external sources:
- SNMP responses: switch names, port descriptions, vendor strings
- CSV/ARP data: MAC addresses, hostnames, IP addresses
- Configuration files: switch names, management IPs

All of these are tested for proper HTML escaping.
"""

import json
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


def test_build_site_escapes_switch_name_in_multiple_contexts(tmp_path):
    """
    Regression test for XSS in switch name across multiple HTML contexts.

    Switch names appear in:
    - Page titles (<title> tag)
    - Headers (h1, h2 tags)
    - Link text (<a> tags)
    - href attributes

    This test ensures switch names with XSS-like content are properly escaped
    in all HTML contexts. We use ampersands and quotes which are valid in
    filenames but need HTML escaping.
    """
    template_dir = Path(__file__).resolve().parents[1] / "switchmap_py" / "render" / "templates"
    static_dir = tmp_path / "static"
    static_dir.mkdir()

    # XSS payload using characters that need HTML escaping but are valid in filenames
    xss_in_name = 'sw&test"name\'test'

    output_dir = tmp_path / "output"
    build_site(
        switches=[
            Switch(
                name=xss_in_name,
                management_ip="192.0.2.10",
                vendor="test",
                ports=[],
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

    # Check index.html - ampersands and quotes should be escaped
    index_html = (output_dir / "index.html").read_text()
    # Ampersands should be escaped to &amp;
    assert '&amp;' in index_html, "Ampersands should be HTML-escaped"
    # Quotes in href context should be escaped
    assert '&quot;' in index_html or '&#34;' in index_html, "Quotes should be escaped"

    # Check switch page exists and has proper escaping
    switch_html = (output_dir / "switches" / f"{xss_in_name}.html").read_text()
    assert '&amp;' in switch_html, "Ampersands should be escaped in switch page"


def test_build_site_escapes_mac_list_in_search_json(tmp_path):
    """
    Regression test for XSS in MAC list data used by search interface.

    The search.html.j2 template loads index.json and renders MAC list entries
    using JavaScript. While JavaScript uses textContent (safe by default),
    the JSON itself should not contain unescaped HTML that could be exploited
    if the JavaScript rendering changes.

    This test ensures MAC hostnames, IPs, and other fields are properly
    represented in the JSON output without XSS payloads.
    """
    template_dir = Path(__file__).resolve().parents[1] / "switchmap_py" / "render" / "templates"
    static_dir = tmp_path / "static"
    static_dir.mkdir()

    # XSS payloads in MAC list data
    xss_hostname = '<script>alert("hostname")</script>'
    xss_ip = '1.2.3.4<img src=x onerror=alert(1)>'

    # Create MAC list with XSS payloads
    maclist_file = tmp_path / "maclist.json"
    maclist_data = [
        {
            "mac": "00:11:22:33:44:55",
            "ip": xss_ip,
            "hostname": xss_hostname,
            "switch": "test-switch",
            "port": "eth0",
        }
    ]
    maclist_file.write_text(json.dumps(maclist_data))

    output_dir = tmp_path / "output"
    build_site(
        switches=[
            Switch(
                name="test-switch",
                management_ip="192.0.2.10",
                vendor="test",
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

    # Check search index.json - data should be JSON-encoded (which escapes HTML)
    search_json = json.loads((output_dir / "search" / "index.json").read_text())
    maclist = search_json["maclist"]
    assert len(maclist) == 1, "One MAC entry should be present"

    # JSON encoding naturally escapes HTML, but verify the raw strings are preserved
    # (they'll be safely rendered by JavaScript textContent)
    assert maclist[0]["hostname"] == xss_hostname
    assert maclist[0]["ip"] == xss_ip

    # Ensure search.html itself doesn't contain unescaped XSS
    # (it's a static template, but failed_switches could inject)
    search_html = (output_dir / "search" / "index.html").read_text()
    assert '<script>alert(' not in search_html, "No script tags should appear in search.html"


def test_build_site_escapes_all_port_fields(tmp_path):
    """
    Regression test for XSS in all port-related fields.

    Ports have multiple user-controlled fields from SNMP:
    - port.name (interface name)
    - port.descr (description)
    - port.admin_status
    - port.oper_status
    - port.speed
    - port.vlan

    This test ensures all fields are properly escaped to prevent XSS.
    """
    template_dir = Path(__file__).resolve().parents[1] / "switchmap_py" / "render" / "templates"
    static_dir = tmp_path / "static"
    static_dir.mkdir()

    # XSS payloads in various port fields
    output_dir = tmp_path / "output"
    build_site(
        switches=[
            Switch(
                name="test-sw",
                management_ip="192.0.2.10",
                vendor="test",
                ports=[
                    Port(
                        name='eth0<script>alert(1)</script>',
                        descr='Port <img src=x onerror=alert(2)>',
                        admin_status='up<script>alert(3)</script>',
                        oper_status='down" onclick="alert(4)"',
                        speed=1000,
                        vlan='100<script>alert(5)</script>',
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

    # Check switch page
    switch_html = (output_dir / "switches" / "test-sw.html").read_text()
    assert '<script>alert(1)</script>' not in switch_html
    assert '<script>alert(2)</script>' not in switch_html
    assert '<script>alert(3)</script>' not in switch_html
    assert 'onclick="alert(4)"' not in switch_html
    assert '<script>alert(5)</script>' not in switch_html
    assert '&lt;script&gt;' in switch_html, "Script tags should be escaped"
    assert '&lt;img' in switch_html, "Img tags should be escaped"
    # Check that onclick is properly escaped (either &quot; or &#34; are valid)
    # The key is that onclick= should not appear as an unescaped attribute
    assert 'onclick=' not in switch_html or (
        '&quot; onclick=' in switch_html or '&#34; onclick=' in switch_html
    ), "Event handlers should be escaped"

    # Check ports page
    ports_html = (output_dir / "ports" / "index.html").read_text()
    assert '<script>alert(' not in ports_html
    assert '&lt;script&gt;' in ports_html, "Script tags should be escaped in ports page"


def test_build_site_escapes_management_ip_and_vendor(tmp_path):
    """
    Regression test for XSS in switch management IP and vendor fields.

    While management IPs are typically validated, vendor strings from SNMP
    could potentially contain malicious content. This test ensures both
    fields are properly escaped.
    """
    template_dir = Path(__file__).resolve().parents[1] / "switchmap_py" / "render" / "templates"
    static_dir = tmp_path / "static"
    static_dir.mkdir()

    xss_payload = '<script>alert("vendor")</script>'

    output_dir = tmp_path / "output"
    build_site(
        switches=[
            Switch(
                name="test-sw",
                management_ip='192.0.2.10"><script>alert(1)</script>',
                vendor=xss_payload,
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

    switch_html = (output_dir / "switches" / "test-sw.html").read_text()
    assert '<script>alert(' not in switch_html, "Unescaped script tags should not be present"
    # Check that script tags are properly escaped (both forms are valid)
    assert '&lt;script&gt;' in switch_html, "Script tags should be HTML-escaped"


def test_build_site_escapes_failed_switches_list(tmp_path):
    """
    Regression test for XSS in failed switches list on index page.

    Failed switch names are displayed in a list on the index page.
    This test ensures malicious switch names in the failed list are escaped.
    """
    template_dir = Path(__file__).resolve().parents[1] / "switchmap_py" / "render" / "templates"
    static_dir = tmp_path / "static"
    static_dir.mkdir()

    xss_failed = 'evil-switch<script>alert("failed")</script>'

    output_dir = tmp_path / "output"
    build_site(
        switches=[],
        failed_switches=[xss_failed, 'normal-switch'],
        output_dir=output_dir,
        template_dir=template_dir,
        static_dir=static_dir,
        idlesince_store=IdleSinceStore(tmp_path / "idlesince"),
        maclist_store=MacListStore(tmp_path / "maclist.json"),
        build_date=datetime(2024, 1, 1, tzinfo=timezone.utc),
    )

    index_html = (output_dir / "index.html").read_text()
    assert '<script>alert("failed")</script>' not in index_html
    assert '&lt;script&gt;' in index_html, "Script tags in failed switches should be escaped"
    assert 'evil-switch' in index_html, "Failed switch name should still appear (escaped)"


def test_build_site_prevents_attribute_injection_in_links(tmp_path):
    """
    Regression test for attribute injection in href attributes.

    Switch names are used in href attributes (href="/switches/{{ switch.name }}.html").
    This test ensures that malicious switch names cannot break out of the
    attribute context to inject additional HTML attributes or JavaScript.
    """
    template_dir = Path(__file__).resolve().parents[1] / "switchmap_py" / "render" / "templates"
    static_dir = tmp_path / "static"
    static_dir.mkdir()

    # Payload attempts to close href and inject onclick
    injection_payload = 'test.html" onclick="alert(1)'

    output_dir = tmp_path / "output"
    build_site(
        switches=[
            Switch(
                name=injection_payload,
                management_ip="192.0.2.10",
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

    index_html = (output_dir / "index.html").read_text()
    # The critical check: unescaped onclick should not appear
    assert 'onclick="alert(1)' not in index_html, "Unescaped onclick should not be injected"
    # Verify the quotes are properly escaped - both &quot; and &#34; are valid
    # The escaped quotes prevent breaking out of the href attribute
    # Example: href="/switches/test.html&#34; onclick=&#34;alert(1).html"
    # This is SAFE because &#34; inside an attribute value is still part of the value
    assert '&#34; onclick=&#34;' in index_html or '&quot; onclick=&quot;' in index_html, \
        "Quotes should be HTML-escaped to prevent attribute injection"


def test_search_page_includes_switch_port_search_logic(tmp_path):
    template_dir = Path(__file__).resolve().parents[1] / "switchmap_py" / "render" / "templates"
    static_dir = tmp_path / "static"
    static_dir.mkdir()
    output_dir = tmp_path / "output"

    build_site(
        switches=[
            Switch(
                name="sw1",
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
                    )
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

    search_html = (output_dir / "search" / "index.html").read_text(encoding="utf-8")
    assert "Search by switch, port, status, VLAN" in search_html
    assert "<th>Type</th>" in search_html
    assert "<th>Status</th>" in search_html
    assert "<th>VLAN</th>" in search_html
    assert "switchPortEntries(index)" in search_html
    assert "buildEntries(index)" in search_html
    assert 'id="typeFilter"' in search_html
    assert 'id="statusFilter"' in search_html
    assert 'id="vlanFilter"' in search_html
    assert 'id="sortBy"' in search_html
    assert 'id="resultCount"' in search_html
    assert "applyFilters(entries)" in search_html
    assert "sortEntries(entries)" in search_html
    assert "readFiltersFromUrl()" in search_html
    assert "writeFiltersToUrl()" in search_html
    assert "window.history.replaceState" in search_html
    assert "window.location.href = entry.target_url" in search_html
    assert 'id="resetFilters"' in search_html
    assert 'id="emptyState"' in search_html
    assert "No matching entries." in search_html
