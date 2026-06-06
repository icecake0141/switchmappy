<!--
Copyright 2026 switchmappy
SPDX-License-Identifier: Apache-2.0

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

This file was created or modified with the assistance of an AI (Large Language Model).
Review required for correctness, security, and licensing.
-->

# SwitchMap Gap Analysis

- Japanese translation: [switchmap_gap_analysis.ja.md](switchmap_gap_analysis.ja.md)

This page compares switchmappy with the original Perl SwitchMap tool family as
used by `SwitchMap.pl`, `ScanSwitch.pl`, `GetArp.pl`, `FindOffice.pl`,
`SearchPortlists.html`, and site-specific `ThisSite.pm` logic.

## Status Legend

- `Implemented`: supported by switchmappy.
- `Partial`: supported with known scope limits.
- `Not yet`: not implemented.
- `Intentionally different`: switchmappy deliberately uses a different design.

## Capability Matrix

| Area | Status | switchmappy Support | Remaining Work |
| --- | --- | --- | --- |
| Static switch map generation | Implemented | `switchmap build-html` renders index, switch, ports, VLAN, endpoint, search, history, and debug pages. | Legacy HTML layout parity is not a goal unless explicitly required. |
| Idle-since tracking | Implemented | `scan-switch` updates per-switch idle state. | Broaden device fixtures if more vendors are added. |
| ARP import | Implemented | CSV and SNMP router ARP import are supported. | Add more router-family fixtures if needed. |
| MAC/IP/hostname correlation | Implemented | MAC list, ARP data, hostname import, reverse DNS, and OUI display are supported. | Keep SSH endpoint correlation covered by repeatable fixtures and integration tests. |
| Search UI | Implemented | Static search page backed by `search/index.json`; FastAPI serve command exists. | Office/location workflows need a dedicated view. |
| SSH switch collection | Implemented | Cisco-like, Juniper, FortiSwitch, and Arista-oriented command profiles exist. | Expand command fixtures for more platform variants. |
| SNMP switch collection | Partial | IF-MIB, BRIDGE-MIB fallback, VLAN names, LLDP, sysDescr, and sysUpTime are supported. | Add richer device-family OID support and VLAN-aware FDB validation on non-IOL-L2 labs. |
| VLAN-aware SNMP FDB | Partial | Q-BRIDGE FDB is parsed when devices expose it; VLAN-indexed community collection works when configured as the SNMP community. | Add repeatable fixtures for device families that expose VLAN-aware FDB data. |
| LLDP/CDP neighbors | Implemented | SSH LLDP/CDP and SNMP LLDP neighbors are rendered. | Add more capability fixtures for vendor-specific outputs. |
| Neighbor capabilities | Partial | CDP capabilities and SNMP LLDP capability bitmaps are retained when available. | Add fixtures for devices that omit or vary capability fields. |
| Trunk/uplink display | Intentionally different | Roles use explicit `trunk_ports` or LLDP/CDP neighbor evidence. | Do not use MAC count or endpoint count as role evidence. |
| Operational switchport evidence | Implemented | Cisco-like SSH captures mode, access VLAN, voice VLAN, native VLAN, and allowed VLANs. FortiSwitch SSH captures VLAN membership plus `show switch interface` description, mode, native VLAN, allowed VLANs, and FortiLink hints. | Add Juniper and Arista switchport detail fixtures where equivalent commands are available. |
| Switch inventory | Partial | SSH `show version` and SNMP `sysDescr`/`sysUpTime` are rendered. | Add structured model/serial/version OIDs per platform. |
| PoE and error counters | Partial | SSH collectors expose PoE status/power and input/output errors for supported profiles. | Add SNMP PoE/error OIDs and more device fixtures. |
| History and diffs | Implemented | History snapshots and diff pages are generated. | Consider retention controls if output grows. |
| Debug diagnostics | Implemented | Debug page shows correlation traces, unmatched data, anomalies, artifacts, port evidence, and SNMP FDB diagnostics such as Q-BRIDGE unavailable, FDB empty, and VLAN-indexed community hints. | Move SNMP FDB diagnostics from artifact inference into collector-owned diagnostic records if a richer API is needed. |
| Site configuration | Intentionally different | YAML replaces `ThisSite.pm`. | Publishing/scheduling remains external automation. |
| Office/location workflows | Not yet | Current search covers host/IP/MAC/switch/port. | Add location/office metadata import and views. |
| Exact Perl module compatibility | Intentionally different | Python modules split collection, rendering, storage, and search. | No direct Perl API compatibility planned. |

## Highest-Value Remaining Work

1. Office/location workflow PR: add metadata import, search index fields, and a location-oriented view.
2. SNMP FDB fixture PR: add repeatable Q-BRIDGE-capable fixtures and VLAN-indexed community examples.
3. SNMP diagnostics model PR: move FDB diagnostics from artifact inference into collector-owned diagnostic records.
4. Inventory OID PR: add structured model, serial, and version OIDs for common Cisco platforms.
5. Counter coverage PR: add SNMP PoE and interface error OID coverage with fixtures.
6. Switchport fixture PR: add Juniper and Arista switchport detail fixtures for mode/native/allowed VLAN evidence.
