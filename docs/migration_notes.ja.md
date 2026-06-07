<!--
Copyright 2026 SwitchMappy
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
- Cisco 系 SSH collection では `show interfaces switchport` の情報を取り込み、
  operational mode、access VLAN、voice VLAN、native VLAN、allowed VLANs を表示。
- 装置インベントリは取得可能な範囲で表示。SSH は Cisco 系の `show version`、
  SNMP は `sysDescr` と `sysUpTime` を使用。
- LLDP/CDP neighbor capability は取得できる場合に保持。SNMP LLDP capability
  bitmap は読みやすいラベルに変換。

## Perl SwitchMap との差分として残るもの

詳細な一覧は [SwitchMap 差分分析](switchmap_gap_analysis.ja.md) を参照してください。

- 従来HTMLレイアウトの完全一致は保証しません。
- 長年運用された Perl 版に比べ、機種別OID対応の幅はまだ狭い可能性があります。
- `ThisSite.pm` の公開・定期実行などのサイト固有処理は、Perl互換ランタイムではなく
  YAML設定とローカルコマンドとして表現します。
- `FindOffice.pl` の場所・オフィス単位ワークフローは、検索/Debugページで代替しており、
  UIを1対1には複製していません。
