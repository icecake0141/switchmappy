<!--
Copyright 2024 switchmappy
SPDX-License-Identifier: Apache-2.0

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

This file was created or modified with the assistance of an AI (Large Language Model).
Review required for correctness, security, and licensing.
-->

# Switchmap Python Usage

## Install

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e .
```

Optional dependencies:

```bash
pip install -e .[snmp,search]
```

Development validation dependencies:

```bash
pip install -e .[dev]
```

## Configuration

Create `site.yml` in the repository root (or pass `--config`).
SNMP v2c is the only supported version.
If the file is missing or invalid, the CLI reports a configuration error. An empty file
is treated as an empty configuration that uses defaults.

```yaml
destination_directory: output
idlesince_directory: idlesince
maclist_file: maclist.json
unused_after_days: 30
snmp_timeout: 2
snmp_retries: 1
switches:
  - name: core-sw1
    management_ip: 192.0.2.10
    vendor: cisco
    snmp_version: 2c  # v2c only
    community: public
    trunk_ports: ["Gi1/0/48"]
routers:
  - name: edge-router
    management_ip: 192.0.2.1
    snmp_version: 2c  # v2c only
    community: public
```

## CLI

```bash
switchmap scan-switch
switchmap get-arp --source csv --csv maclist.csv
switchmap get-arp --source snmp
switchmap build-html
switchmap serve-search --host 0.0.0.0 --port 8000
```

## Validation (local, same as CI)

```bash
python -m ruff check .
python -m pytest -q
python -m pre_commit run --all-files
```

## Generated Pages

- `index.html`: switch list and failed switch summary
- `switches/<switch>.html`: per-port state, VLAN, idle-since, and ARP correlation (`IP (hostname)`)
- `ports/index.html`: cross-switch port summary with ARP correlation
- `vlans/index.html`: VLAN summary with client-side VLAN filter and links to switch detail anchors
- `search/index.html`: searchable UI for MAC/IP/host/switch/port data

### ARP CSV format

The `get-arp` command expects one entry per line with at least MAC and IP columns.
Optional hostname values may follow. Invalid or incomplete rows are skipped with a warning.

```csv
aa:bb:cc:dd:ee:ff,192.0.2.10,example-host
11:22:33:44:55:66,192.0.2.20
```

### ARP SNMP source

`switchmap get-arp --source snmp` reads ARP tables from routers defined under
`routers:` in `site.yml` via SNMP v2c. If `routers` is empty, the command exits
with a configuration error. The implementation first reads legacy
`ipNetToMedia` and falls back to `ipNetToPhysical` when needed. For
`ipNetToPhysical`, only `reachable(1)` entries are imported. ARP import is
currently limited to IPv4 entries.

## Cron example

```cron
# Scan switches hourly
0 * * * * /usr/bin/env bash -lc 'cd /opt/switchmap && . .venv/bin/activate && switchmap scan-switch'

# Build HTML nightly
0 2 * * * /usr/bin/env bash -lc 'cd /opt/switchmap && . .venv/bin/activate && switchmap build-html'
```

## Troubleshooting

- `RuntimeError: Search server requires optional dependencies`
  - Install search extras: `pip install -e .[search]`
- `No routers configured in site.yml; add routers or use --source csv`
  - Add at least one router entry under `routers:` for `get-arp --source snmp`
- SNMP collection fails for specific switches/routers
  - Verify `management_ip`, `snmp_version: 2c`, `community`, timeout/retry
  - Check network reachability and ACL/firewall to UDP/161
- Generated report is missing a switch
  - Open `output/index.html` and check the failed switch section/reason
- VLAN page has limited names (e.g. `VLAN 20`)
  - Device did not expose VLAN name table; IDs are derived from FDB entries
