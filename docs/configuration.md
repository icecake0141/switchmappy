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

# Configuration

- Japanese translation: [configuration.ja.md](configuration.ja.md)

## Config File

- Default path: `site.yml`
- Override path: `--config`
- Top-level YAML must be a mapping.
- Missing file or invalid YAML causes command failure.

## Top-level Keys

- `destination_directory` (default: `output`)
- `idlesince_directory` (default: `idlesince`)
- `maclist_file` (default: `maclist.json`)
- `unused_after_days` (default: `30`)
- `snmp_timeout` (default: `2`)
- `snmp_retries` (default: `1`)
- `switches` (list)
- `routers` (list)

## `switches[]`

Required keys:

- `name`
- `management_ip`

SNMP mode (`collection_method: snmp`, default):

- `snmp_version`: `1` | `2c` | `3`
- For `1`/`2c`: `community` required
- For `3`: `username` required
- v3 security fields: `security_level`, `auth_protocol`, `auth_password`, `priv_protocol`, `priv_password`

SSH mode (`collection_method: ssh`):

- `ssh_username` required
- `ssh_password` or `ssh_private_key` required
- `ssh_port` default: `22`

Optional keys:

- `vendor` (default: `generic`)
- `trunk_ports` (list of port names)

## `routers[]`

Required keys:

- `name`
- `management_ip`

SNMP requirements are the same as switch SNMP settings.

## Validation Rules

- Duplicate switch names are rejected.
- Duplicate router names are rejected.
