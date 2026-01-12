<!--
Copyright 2025 OpenAI
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

## Configuration

Create `site.yml` in the repository root (or pass `--config`).
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
switchmap build-html
switchmap serve-search --host 0.0.0.0 --port 8000
```

`scan-switch` keeps idle port entries for ports missing from the latest snapshot. Use
`--prune-missing` to remove ports that are no longer observed.

## Cron example

```cron
# Scan switches hourly
0 * * * * /usr/bin/env bash -lc 'cd /opt/switchmap && . .venv/bin/activate && switchmap scan-switch'

# Build HTML nightly
0 2 * * * /usr/bin/env bash -lc 'cd /opt/switchmap && . .venv/bin/activate && switchmap build-html'
```
