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

import logging

from typer.testing import CliRunner

from switchmap_py.cli import app
from switchmap_py.model.switch import Switch
from switchmap_py.snmp.session import SnmpError


def test_build_html_logs_failed_switches_and_passes_successful(tmp_path, monkeypatch, caplog):
    config_path = tmp_path / "site.yml"
    config_path.write_text(
        "\n".join(
            [
                f"destination_directory: {tmp_path / 'output'}",
                f"idlesince_directory: {tmp_path / 'idlesince'}",
                f"maclist_file: {tmp_path / 'maclist.json'}",
                "switches:",
                "  - name: sw-ok",
                "    management_ip: 192.0.2.10",
                "    community: public",
                "  - name: sw-bad",
                "    management_ip: 192.0.2.11",
                "    community: public",
            ]
        )
    )

    def fake_collect_switch_state(sw, _timeout, _retries):
        if sw.name == "sw-bad":
            raise SnmpError("SNMP failure")
        return Switch(
            name=sw.name,
            management_ip=sw.management_ip,
            vendor=sw.vendor,
        )

    captured = {}

    def fake_build_site(**kwargs):
        captured.update(kwargs)

    monkeypatch.setattr("switchmap_py.cli.collect_switch_state", fake_collect_switch_state)
    monkeypatch.setattr("switchmap_py.cli.build_site", fake_build_site)

    caplog.set_level(logging.ERROR)

    runner = CliRunner()
    result = runner.invoke(app, ["build-html", "--config", str(config_path)])

    assert result.exit_code == 0
    assert [sw.name for sw in captured["switches"]] == ["sw-ok"]
    assert captured["failed_switches"] == ["sw-bad"]
    assert captured["failed_switch_reasons"] == {"sw-bad": "[SNMP_ERROR] SNMP failure"}
    assert "sw-bad" in caplog.text


def test_build_html_propagates_unexpected_errors(tmp_path, monkeypatch):
    """Verify that non-SNMP errors cause the command to fail fast."""
    config_path = tmp_path / "site.yml"
    config_path.write_text(
        "\n".join(
            [
                f"destination_directory: {tmp_path / 'output'}",
                f"idlesince_directory: {tmp_path / 'idlesince'}",
                f"maclist_file: {tmp_path / 'maclist.json'}",
                "switches:",
                "  - name: sw-programming-error",
                "    management_ip: 192.0.2.10",
                "    community: public",
            ]
        )
    )

    def fake_collect_switch_state(sw, _timeout, _retries):
        # This represents a programming error that should not be caught
        raise ValueError("Unexpected programming error")

    monkeypatch.setattr("switchmap_py.cli.collect_switch_state", fake_collect_switch_state)

    runner = CliRunner()
    result = runner.invoke(app, ["build-html", "--config", str(config_path)])

    # The command should fail (non-zero exit code) for unexpected errors
    assert result.exit_code != 0
    assert isinstance(result.exception, ValueError)
