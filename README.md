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

# switchmappy

`switchmappy` builds static switch-port inventory reports from SNMP or SSH
collection data. It helps network operators find endpoints, inspect port
status, correlate ARP/MAC data, review VLANs, and serve a local search UI.

English documentation is primary. Japanese onboarding content is available from
the static documentation UI.

## Quick Start

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e .[snmp,search]
cp site.yml.example site.yml
switchmap get-arp --source csv --csv arp.csv
switchmap build-html
switchmap serve-search --host 127.0.0.1 --port 8000
```

Open `http://127.0.0.1:8000/search/` after the server starts.

## Installation

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e .
```

Optional features:

```bash
pip install -e .[snmp,search]
```

Development dependencies:

```bash
pip install -e .[dev]
```

## Documentation

- [Onboarding Documentation UI](docs/index.html)
- [Quick Start and User Tour](docs/onboarding.md)
- [Configuration Reference](docs/configuration.md)
- [Command Reference](docs/commands.md)
- [Testing](docs/testing.md)

### English

- [Documentation Index](docs/README.md)
- [Specification](docs/specification.md)
- [Configuration](docs/configuration.md)
- [Commands](docs/commands.md)
- [Testing](docs/testing.md)
- [Migration Notes](docs/migration_notes.md)

### 日本語

- [ドキュメント一覧](docs/README.ja.md)
- [仕様](docs/specification.ja.md)
- [設定](docs/configuration.ja.md)
- [コマンド](docs/commands.ja.md)
- [テスト](docs/testing.ja.md)
- [移行メモ](docs/migration_notes.ja.md)
