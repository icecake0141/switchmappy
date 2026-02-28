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

from switchmap_py.config import SwitchConfig
from switchmap_py.model.switch import Switch
from switchmap_py.snmp.collectors import PortSnapshot
from switchmap_py.snmp.collectors import collect_port_snapshots as collect_port_snapshots_snmp
from switchmap_py.snmp.collectors import collect_switch_state as collect_switch_state_snmp
from switchmap_py.ssh.collectors import collect_port_snapshots as collect_port_snapshots_ssh
from switchmap_py.ssh.collectors import collect_switch_state as collect_switch_state_ssh


def collect_switch_state(switch: SwitchConfig, timeout: int, retries: int) -> Switch:
    if switch.collection_method == "ssh":
        return collect_switch_state_ssh(switch, timeout=timeout)
    return collect_switch_state_snmp(switch, timeout=timeout, retries=retries)


def collect_port_snapshots(switch: SwitchConfig, timeout: int, retries: int) -> list[PortSnapshot]:
    if switch.collection_method == "ssh":
        return collect_port_snapshots_ssh(switch, timeout=timeout)
    return collect_port_snapshots_snmp(switch, timeout=timeout, retries=retries)
