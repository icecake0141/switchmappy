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

## Acknowledgement

switchmappy is based on Pete Siemsen's original
[Switchmap](https://switchmap.sourceforge.net/). Although the original UI is
classical and the project is no longer actively updated, it remains a precise,
thoughtfully built, and fully functional tool. Many engineers have tried to
bring similar switch-port mapping workflows forward in Ruby, Python, and other
modern stacks. This project is one such attempt to revive that great original
for contemporary environments.

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

Try the built-in demo without a `site.yml` or network devices:

```bash
switchmap demo
```

For static output only:

```bash
switchmap demo --no-serve
```

Development dependencies:

```bash
pip install -e .[dev]
```

## Documentation

- [Onboarding Documentation UI](https://icecake0141.github.io/switchmappy/) (GitHub Pages)
- [Quick Start and User Tour](docs/onboarding.md)
- [Configuration Reference](docs/configuration.md)
- [Command Reference](docs/commands.md)
- [Testing](docs/testing.md)
- [GitHub Pages publishing notes](docs/pages.md)

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
