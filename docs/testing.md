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

# Testing

- Japanese translation: [testing.ja.md](testing.ja.md)

## Standard Local Validation

```bash
python -m ruff check .
python -m pytest -q
python -m pre_commit run --all-files
```

## Test Coverage Map

- CLI behavior and logging: `tests/test_cli_*.py`, `tests/test_logging_schema.py`
- Collection dispatch and SNMP/SSH handling: `tests/test_collection_dispatch.py`, `tests/test_collectors*.py`, `tests/test_ssh_collectors.py`, `tests/test_snmp_session.py`
- Rendering and build integration: `tests/test_build_*.py`, `tests/test_vlan_page.py`, `tests/test_mac_correlation_render.py`
- Search server: `tests/test_search_server*.py`
- Config and storage: `tests/test_config.py`, `tests/test_idlesince_store.py`, `tests/test_maclist_store.py`
- ARP import: `tests/test_arp_csv_importer.py`, `tests/test_arp_snmp_importer.py`

## Regression Notes

- XSS regression scenarios are documented in `tests/XSS_REGRESSION_TESTS.md`.
