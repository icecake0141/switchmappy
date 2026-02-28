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
from types import ModuleType

from switchmap_py.model.mac import MacEntry


def test_get_arp_snmp_uses_router_config(tmp_path, monkeypatch):
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
    monkeypatch.setitem(sys.modules, "typer", fake_typer)
    cli = importlib.import_module("switchmap_py.cli")

    maclist_path = tmp_path / "maclist.json"
    config_path = tmp_path / "site.yml"
    config_path.write_text(
        "\n".join(
            [
                f"maclist_file: {maclist_path}",
                "routers:",
                "  - name: r1",
                "    management_ip: 192.0.2.1",
                "    community: public",
            ]
        )
    )

    def fake_load_arp_snmp(routers, timeout, retries):
        assert len(routers) == 1
        assert routers[0].name == "r1"
        assert timeout == 2
        assert retries == 1
        return [
            MacEntry(
                mac="00:11:22:33:44:55",
                ip="192.0.2.10",
                hostname=None,
                switch="r1",
                port=None,
            )
        ]

    monkeypatch.setattr(cli, "load_arp_snmp", fake_load_arp_snmp)
    cli.get_arp(source="snmp", csv_path=None, config=config_path, logfile=None)

    saved = json.loads(maclist_path.read_text())
    assert len(saved) == 1
    assert saved[0]["mac"] == "00:11:22:33:44:55"
    assert saved[0]["switch"] == "r1"
