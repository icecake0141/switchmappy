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
- Track idle-since timestamps in per-switch JSON files.
- Import ARP data from CSV or SNMP-enabled routers.
- Build static HTML pages (`index`, `switches`, `ports`, `vlans`, `search`).
- Serve the static search UI using FastAPI/Uvicorn extras.

## Data Outputs

- `destination_directory`: generated HTML and search index files.
- `idlesince_directory`: idle-since history by switch and port.
- `maclist_file`: normalized MAC/IP/hostname mapping used for ARP correlation.

## Error Handling Policy

- `scan-switch` fails fast when a target switch collection fails.
- `build-html` continues on per-switch SNMP/SSH failures and records failed switches in report output.
- `get-arp --source snmp` requires at least one router in `site.yml`.
