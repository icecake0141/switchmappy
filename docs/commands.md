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

All commands support:

- `--config <path>`
- `--debug | --info | --warn`
- `--logfile <path>`
- `--log-format text|json`

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
- Behavior:
  - `snmp` source requires `routers` config.

## `build-html`

- Purpose: collect switch state and generate static HTML output.
- Options:
  - `--date <ISO datetime>`
- Behavior:
  - continues when a switch SNMP/SSH collection fails,
  - records failed switch reasons in output index.

## `serve-search`

- Purpose: host search UI from built output.
- Options:
  - `--host` (default: `127.0.0.1`)
  - `--port` (default: `8000`)
- Requirement:
  - install search extras: `pip install -e .[search]`
