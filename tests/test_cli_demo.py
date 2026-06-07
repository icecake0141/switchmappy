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

import pytest

pytest.importorskip("typer")

from typer.testing import CliRunner

from switchmap_py.cli import app


def test_demo_generates_full_report_without_serving(tmp_path):
    output_dir = tmp_path / "demo"

    result = CliRunner().invoke(
        app,
        [
            "demo",
            "--output",
            str(output_dir),
            "--date",
            "2024-01-02T03:04:05+00:00",
            "--no-serve",
        ],
    )

    assert result.exit_code == 0
    assert (output_dir / "index.html").exists()
    assert (output_dir / "ports" / "index.html").exists()
    assert (output_dir / "vlans" / "index.html").exists()
    assert (output_dir / "debug" / "index.html").exists()
    assert (output_dir / "history" / "index.html").exists()
    assert (output_dir / "search" / "index.json").exists()
    assert (output_dir / ".demo-state" / "maclist.json").exists()
    assert (output_dir / ".demo-state" / "history" / "20240101T030405Z.json").exists()
    assert "Demo report generated" in result.stdout
    assert "switchmap serve-search" in result.stdout
    for relative_path in [
        "index.html",
        "switches/core-1.html",
        "ports/index.html",
        "transceivers/index.html",
        "vlans/index.html",
        "endpoints/index.html",
        "history/index.html",
        "search/index.html",
        "debug/index.html",
    ]:
        html = (output_dir / relative_path).read_text(encoding="utf-8")
        assert 'class="report-nav"' in html
        assert 'href="/index.html"' in html
        assert 'href="/search/index.html"' in html
        assert 'href="/transceivers/index.html"' in html
    transceivers_html = (output_dir / "transceivers" / "index.html").read_text(encoding="utf-8")
    assert "QSFP28-LR4" in transceivers_html
    assert "SFP-10GLR-31" in transceivers_html
    assert "-3.3003" in transceivers_html
    ports_html = (output_dir / "ports" / "index.html").read_text(encoding="utf-8")
    switch_html = (output_dir / "switches" / "core-1.html").read_text(encoding="utf-8")
    search_html = (output_dir / "search" / "index.html").read_text(encoding="utf-8")
    for html in (ports_html, switch_html, search_html):
        assert "<th>Optic</th>" not in html
        assert "<th>Tx dBm</th>" not in html
        assert "<th>Rx dBm</th>" not in html
        assert "<th>Current mA</th>" not in html
    assert "entry.transceiver_model" in search_html

    search_index = json.loads((output_dir / "search" / "index.json").read_text(encoding="utf-8"))
    switch_names = {switch["name"] for switch in search_index["switches"]}
    assert {"core-1", "access-forti-1", "leaf-1"} <= switch_names
    assert search_index["failed_switches"] == ["demo-snmp-failed"]
    assert search_index["debug"]["snmp_fdb_diagnostics"]
    assert search_index["history_diff"]["moved_endpoints"]
    assert search_index["history_diff"]["port_changes"]

    ports = [port for switch in search_index["switches"] for port in switch["ports"]]
    assert any(port.get("transceiver_model") == "QSFP28-LR4" for port in ports)
    assert any(port.get("transceiver_rx_power_dbm") == -3.3003 for port in ports)
    endpoints = search_index["endpoint_correlations"]
    assert any(endpoint["hostname"] == "workstation-a.example.test" for endpoint in endpoints)
    assert any(endpoint["warning"] == "duplicate MAC via configured trunk port" for endpoint in endpoints)
    unmatched = search_index["debug"]["unmatched_maclist"]
    assert any(row["hostname"] == "stale-arp.example.test" for row in unmatched)


def test_demo_serves_generated_report(monkeypatch, tmp_path):
    captured: dict[str, object] = {}

    class FakeSearchServer:
        def __init__(self, output_dir, host, port):
            captured["output_dir"] = output_dir
            captured["host"] = host
            captured["port"] = port

        def serve(self):
            captured["served"] = True

    monkeypatch.setattr("switchmap_py.cli.SearchServer", FakeSearchServer)
    output_dir = tmp_path / "demo"

    result = CliRunner().invoke(
        app,
        [
            "demo",
            "--output",
            str(output_dir),
            "--host",
            "0.0.0.0",
            "--port",
            "18000",
            "--date",
            "2024-01-02T03:04:05+00:00",
        ],
    )

    assert result.exit_code == 0
    assert captured == {"output_dir": output_dir, "host": "0.0.0.0", "port": 18000, "served": True}
    assert "Serving demo report: http://0.0.0.0:18000/" in result.stdout


def test_demo_surfaces_search_server_dependency_error(monkeypatch, tmp_path):
    class MissingSearchServer:
        def __init__(self, _output_dir, _host, _port):
            pass

        def serve(self):
            raise RuntimeError("Install with: pip install -e .[search]")

    monkeypatch.setattr("switchmap_py.cli.SearchServer", MissingSearchServer)

    result = CliRunner().invoke(app, ["demo", "--output", str(tmp_path / "demo")])

    assert result.exit_code != 0
    assert "Install with: pip install -e .[search]" in str(result.exception)
