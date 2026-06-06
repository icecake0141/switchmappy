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

# Specification

- Japanese translation: [specification.ja.md](specification.ja.md)

## Supported Runtime

- Python 3.12+

## Core Capabilities

- Collect per-port state from switches using SNMP or SSH.
- Collect switch inventory details where available, including platform, serial
  number, OS version, and uptime.
- Track idle-since timestamps in per-switch JSON files.
- Import ARP data from CSV or SNMP-enabled routers.
- Build static HTML pages (`index`, `switches`, `ports`, `vlans`, `search`).
- Serve the static search UI using FastAPI/Uvicorn extras.

## Data Outputs

- `destination_directory`: generated HTML and search index files.
- `idlesince_directory`: idle-since history by switch and port.
- `maclist_file`: normalized MAC/IP/hostname mapping used for ARP correlation.

## Port Role Display

- `configured_trunk`: port is explicitly listed in `trunk_ports`.
- `network_neighbor`: port has an LLDP/CDP neighbor and is shown as a network-adjacent port.
- `unknown`: no explicit trunk configuration or neighbor evidence is present.
- MAC count, endpoint count, and multi-VLAN observations are not used for role assignment.

## Switchport Evidence

For Cisco-like SSH collection, `show interfaces switchport` is used when
available to expose operational mode, access VLAN, voice VLAN, native VLAN, and
allowed VLANs. Speed and media/type evidence, such as SFP/QSFP optics labels
when collectors expose them, are rendered in switch, ports, search, and debug
views. These values are evidence fields in reports and search output;
they do not override explicit `trunk_ports` role assignment.

## Neighbor Capabilities

LLDP/CDP neighbor capability data is preserved when the collector can obtain it.
SNMP LLDP capability bitmaps are decoded to readable labels such as `bridge` and
`router`.

## Error Handling Policy

- `scan-switch` fails fast when a target switch collection fails.
- `build-html` continues on per-switch SNMP/SSH failures and records failed switches in report output.
- `get-arp --source snmp` requires at least one router in `site.yml`.
