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
| Static switch map generation | Implemented | `switchmap build-html` renders index, switch, ports, transceiver, VLAN, endpoint, search, history, and debug pages. | Legacy HTML layout parity is not a goal unless explicitly required. |
| Idle-since tracking | Implemented | `scan-switch` updates per-switch idle state. | Broaden device fixtures if more vendors are added. |
| ARP import | Implemented | CSV and SNMP router ARP import are supported. | Add more router-family fixtures if needed. |
| MAC/IP/hostname correlation | Implemented | MAC list, ARP data, hostname import, reverse DNS, and OUI display are supported. | Keep SSH endpoint correlation covered by repeatable fixtures and integration tests. |
| Search UI | Implemented | Static search page backed by `search/index.json`; FastAPI serve command exists. | Office/location workflows need a dedicated view. |
| SSH switch collection | Implemented | Cisco-like, Juniper, FortiSwitch, and Arista-oriented command profiles exist. | Expand command fixtures for more platform variants. |
| SNMP switch collection | Partial | IF-MIB, BRIDGE-MIB fallback, VLAN names, LLDP, sysDescr, sysUpTime, ENTITY-MIB inventory fields, interface errors, and basic PoE status/power are supported. | Add device-family-specific OIDs where standard tables are absent or sparse. |
| VLAN-aware SNMP FDB | Partial | Q-BRIDGE FDB is parsed when devices expose it; VLAN-indexed community collection works when configured as the SNMP community; diagnostics now distinguish Q-BRIDGE empty/unavailable from legacy FDB fallback. | Add live-lab validation on additional Q-BRIDGE-capable targets. |
| LLDP/CDP neighbors | Implemented | SSH LLDP/CDP and SNMP LLDP neighbors are rendered. | Add more capability fixtures for vendor-specific outputs. |
| Neighbor capabilities | Partial | CDP capabilities and SNMP LLDP capability bitmaps are retained when available. | Add fixtures for devices that omit or vary capability fields. |
| Trunk/uplink display | Intentionally different | Roles use explicit `trunk_ports` or LLDP/CDP neighbor evidence. | Do not use MAC count or endpoint count as role evidence. |
| Operational switchport evidence | Implemented | Cisco-like SSH captures mode, access VLAN, voice VLAN, native VLAN, allowed VLANs, speed, media/type labels, and transceiver model/Tx/Rx optical power/current when `show interfaces transceiver` is available. FortiSwitch SSH captures VLAN membership plus `show switch interface` details and module summary/status optic diagnostics. SNMP exposes speed and IF-MIB interface type. | Add more vendor-specific transceiver variants when platforms expose different optic diagnostics formats. |
| Switch inventory | Partial | SSH `show version` and SNMP `sysDescr`/`sysUpTime` are rendered. | Add structured model/serial/version OIDs per platform. |
| PoE and error counters | Partial | SSH collectors expose PoE status/power and input/output errors for supported profiles. SNMP collectors read IF-MIB error counters and basic POWER-ETHERNET-MIB PoE status/power. | Add vendor-specific PoE/error OIDs where standard MIBs are incomplete. |
| History and diffs | Implemented | History snapshots and diff pages are generated. | Consider retention controls if output grows. |
| Debug diagnostics | Implemented | Debug page shows correlation traces, unmatched data, anomalies, artifacts, port evidence, and SNMP FDB diagnostics from both collector records and artifact inference. | Add more diagnostic categories if future collectors expose them. |
| Site configuration | Intentionally different | YAML replaces `ThisSite.pm`. | Publishing/scheduling remains external automation. |
| Office/location workflows | Not yet | Current search covers host/IP/MAC/switch/port. | Add location/office metadata import and views. |
| Exact Perl module compatibility | Intentionally different | Python modules split collection, rendering, storage, and search. | No direct Perl API compatibility planned. |

## Highest-Value Remaining Work

1. Office/location workflow PR: add metadata import, search index fields, and a location-oriented view.
2. SNMP live-lab validation PR: validate Q-BRIDGE and VLAN-indexed community behavior against additional hardware or virtual targets.
3. Vendor OID PR: add device-family-specific inventory, PoE, and error OIDs where standard MIBs are incomplete.
4. Search/debug UX PR: expose collector diagnostics in more report surfaces beyond Debug if operators need them.
5. Switchport fixture PR: expand Juniper and Arista variants beyond the initial mode/native/allowed VLAN evidence fixtures.
