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

from switchmap_py.snmp import collectors, mibs


class FakeSession:
    def __init__(self, failures: set[str]) -> None:
        self.failures = failures

    def get_table(self, oid: str) -> dict[str, str]:
        if oid in self.failures:
            raise RuntimeError("boom")
        if oid == mibs.DOT1D_BASE_PORT_IFINDEX:
            return {f"{mibs.DOT1D_BASE_PORT_IFINDEX}.1": "10"}
        return {}


def test_bridge_port_map_logs_warning_on_exception(caplog):
    session = FakeSession({mibs.DOT1D_BASE_PORT_IFINDEX})

    with caplog.at_level(logging.WARNING):
        result = collectors._bridge_port_map(session)

    assert result == {}
    assert any(
        mibs.DOT1D_BASE_PORT_IFINDEX in record.message for record in caplog.records
    )


def test_collect_macs_logs_warning_on_exception(caplog):
    session = FakeSession({mibs.QBRIDGE_VLAN_FDB_PORT})

    with caplog.at_level(logging.WARNING):
        result = collectors._collect_macs(session)

    assert result == {}
    assert any(mibs.QBRIDGE_VLAN_FDB_PORT in record.message for record in caplog.records)
