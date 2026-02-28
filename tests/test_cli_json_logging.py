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

import importlib
import json
import sys
from pathlib import Path
from types import ModuleType

from switchmap_py.model.mac import MacEntry
from switchmap_py.snmp.collectors import PortSnapshot
from switchmap_py.snmp.session import SnmpError


def _load_cli_with_fake_typer():
    fake_typer = ModuleType("typer")

    class FakeTyperApp:
        def command(self, *_args, **_kwargs):
            def decorator(func):
                return func

            return decorator

    class FakeBadParameter(ValueError):
        pass

    def fake_option(default=None, *_args, **_kwargs):
        return default

    fake_typer.Typer = lambda **_kwargs: FakeTyperApp()
    fake_typer.Option = fake_option
    fake_typer.BadParameter = FakeBadParameter
    sys.modules["typer"] = fake_typer
    return importlib.import_module("switchmap_py.cli")


def _parse_log_lines(path: Path) -> list[dict]:
    lines = [line for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    return [json.loads(line) for line in lines]


def test_scan_switch_json_logs_success_and_error(tmp_path, monkeypatch):
    cli = _load_cli_with_fake_typer()

    config_path = tmp_path / "site.yml"
    config_path.write_text(
        "\n".join(
            [
                f"destination_directory: {tmp_path / 'output'}",
                f"idlesince_directory: {tmp_path / 'idlesince'}",
                f"maclist_file: {tmp_path / 'maclist.json'}",
                "switches:",
                "  - name: sw1",
                "    management_ip: 192.0.2.1",
                "    community: public",
            ]
        ),
        encoding="utf-8",
    )

    success_log = tmp_path / "scan-success.log"

    monkeypatch.setattr(
        cli,
        "collect_port_snapshots",
        lambda *_args, **_kwargs: [PortSnapshot(name="Gi1/0/1", is_active=True, mac_count=1, oper_status="up")],
    )
    cli.scan_switch(config=config_path, logfile=success_log, log_format="json")
    payloads = _parse_log_lines(success_log)
    assert any(entry["event"] == "scan_switch" and entry["status"] == "success" for entry in payloads)
    assert all("command" in entry and "elapsed_ms" in entry for entry in payloads)

    error_log = tmp_path / "scan-error.log"

    def raise_timeout(*_args, **_kwargs):
        raise SnmpError("timeout")

    monkeypatch.setattr(cli, "collect_port_snapshots", raise_timeout)
    try:
        cli.scan_switch(config=config_path, logfile=error_log, log_format="json")
        assert False, "scan_switch should propagate SnmpError"
    except SnmpError:
        pass

    error_payloads = _parse_log_lines(error_log)
    assert any(
        entry["event"] == "scan_switch"
        and entry["status"] == "error"
        and entry["error_code"] == "SNMP_TIMEOUT"
        for entry in error_payloads
    )


def test_get_arp_json_logs_success(tmp_path, monkeypatch):
    cli = _load_cli_with_fake_typer()

    log_path = tmp_path / "get-arp.log"
    config_path = tmp_path / "site.yml"
    config_path.write_text(f"maclist_file: {tmp_path / 'maclist.json'}\n", encoding="utf-8")

    monkeypatch.setattr(
        cli,
        "load_arp_csv",
        lambda *_args, **_kwargs: [
            MacEntry(
                mac="00:11:22:33:44:55",
                ip="192.0.2.10",
                hostname="host-a",
                switch=None,
                port=None,
            )
        ],
    )
    cli.get_arp(
        source="csv",
        csv_path=tmp_path / "dummy.csv",
        config=config_path,
        logfile=log_path,
        log_format="json",
    )
    payloads = _parse_log_lines(log_path)
    assert any(entry["event"] == "get_arp" and entry["status"] == "success" for entry in payloads)
