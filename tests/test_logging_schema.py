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
import logging
import sys
from types import ModuleType


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


def test_json_log_formatter_has_fixed_schema():
    cli = _load_cli_with_fake_typer()

    formatter = cli.JsonLogFormatter()
    record = logging.LogRecord(
        name="switchmap_py.cli",
        level=logging.INFO,
        pathname=__file__,
        lineno=1,
        msg="test message",
        args=(),
        exc_info=None,
    )
    record.event = "scan_switch"
    record.command = "scan-switch"
    record.target = "sw1"
    record.status = "success"
    record.elapsed_ms = 123
    record.error_code = None
    payload = json.loads(formatter.format(record))

    for key in (
        "timestamp",
        "level",
        "logger",
        "message",
        "event",
        "command",
        "target",
        "status",
        "elapsed_ms",
        "error_code",
    ):
        assert key in payload


def test_error_classification_codes():
    cli = _load_cli_with_fake_typer()
    snmp_error = cli.SnmpError("timeout while querying OID")
    assert cli._classify_error(snmp_error) == "SNMP_TIMEOUT"

    auth_error = cli.SnmpError("community string rejected")
    assert cli._classify_error(auth_error) == "SNMP_AUTH"

    oid_error = cli.SnmpError("no such oid")
    assert cli._classify_error(oid_error) == "SNMP_OID"

    config_error = ValueError("bad config")
    assert cli._classify_error(config_error) == "CONFIG_ERROR"
