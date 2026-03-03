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

# Perl から Python への対応表

- English version: [migration_notes.md](migration_notes.md)

| Perl コンポーネント | Python モジュール / コマンド | 補足 |
| --- | --- | --- |
| `ScanSwitch.pl` | `switchmap scan-switch` (`switchmap_py.cli`) | `IdleSinceStore` で idle-since 状態を更新。 |
| `SwitchMap.pl` | `switchmap build-html` (`switchmap_py.render.build`) | Jinja2 テンプレートで静的 HTML を生成。 |
| `GetArp.pl` | `switchmap get-arp` (`switchmap_py.cli`) | CSV 取り込みと SNMP ルータからの ARP 収集をサポート。 |
| `FindOffice.pl` + `SearchPortlists.html` | `switchmap serve-search` + `render/templates/search.html.j2` | `search/index.json` を使うローカル検索 UI を提供。 |
| `ThisSite.pm` | `switchmap_py.config.SiteConfig` | YAML ベースの設定管理。 |
| `*.pm` モジュール | `switchmap_py.snmp.*`, `switchmap_py.model.*` | SNMP セッション・収集・ドメインモデルへ分割。 |

## 補足

- SNMP v1/v2c/v3 をサポート。
- スイッチ収集は `collection_method: snmp|ssh` をサポート。
