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

# Commands

- Japanese translation: [commands.ja.md](commands.ja.md)

## Common Options

Operational commands support:

- `--config <path>`
- `--debug | --info | --warn`
- `--logfile <path>`
- `--log-format text|json`

## `demo`

- Purpose: generate a full sample report without `site.yml` or network devices.
- Options:
  - `--output <path>` (default: `demo-output`)
  - `--host` (default: `127.0.0.1`)
  - `--port` (default: `8000`)
  - `--no-serve`: generate static output only
  - `--date <ISO datetime>` for deterministic output
- Behavior:
  - writes report output plus demo state under `<output>/.demo-state`,
  - includes a dedicated Transceivers page with sample optic diagnostics,
  - starts a local server by default,
  - use `--no-serve` if search extras are not installed.

## `scan-switch`

- Purpose: update idle-since data per switch.
- Options:
  - `--switch <name>`: target one switch
  - `--prune-missing`: remove ports missing from latest scan
- Behavior: fails fast on switch collection errors.

## `get-arp`

- Purpose: update MAC list data.
- Options:
  - `--source csv|snmp` (default: `csv`)
  - `--csv <path>` required when `--source csv`
  - `--resolve-hostnames`: add reverse-DNS hostnames where resolution succeeds
- Behavior:
  - `snmp` source requires `routers` config.

## `import-hostnames`

- Purpose: merge IPAM, DHCP lease, or inventory hostnames into the MAC list.
- Options:
  - `--csv <path>` accepts `mac,ip,hostname` or `ip,hostname` rows
  - `--overwrite | --no-overwrite` controls replacement of existing hostnames
- Behavior:
  - matches by MAC first, then by IP address.

## `build-html`

- Purpose: collect switch state and generate static HTML output.
- Options:
  - `--date <ISO datetime>`
- Behavior:
  - continues when a switch SNMP/SSH collection fails,
  - records failed switch reasons in output index.
  - writes a JSON history snapshot to `history_directory`.
  - generates `/debug/index.html` with collection and correlation diagnostics.
  - generates `/transceivers/index.html` with collected optic diagnostics.
  - generates `/history/index.html` with previous-snapshot differences.
  - stores collector artifacts under `collection_artifacts_directory`.

## `serve-search`

- Purpose: host search UI from built output.
- Options:
  - `--host` (default: `127.0.0.1`)
  - `--port` (default: `8000`)
- Requirement:
  - install search extras: `pip install -e .[search]`
