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

# SwitchMap 差分分析

- English version: [switchmap_gap_analysis.md](switchmap_gap_analysis.md)

このページは、Perl 版 SwitchMap ツール群である `SwitchMap.pl`、`ScanSwitch.pl`、
`GetArp.pl`、`FindOffice.pl`、`SearchPortlists.html`、およびサイト固有の
`ThisSite.pm` ロジックと switchmappy を比較します。

## ステータス

- `Implemented`: switchmappy で対応済み。
- `Partial`: 対応済みだが既知の制限あり。
- `Not yet`: 未実装。
- `Intentionally different`: 意図的に異なる設計。

## 機能差分表

| 領域 | ステータス | switchmappy の対応 | 残作業 |
| --- | --- | --- | --- |
| 静的 switch map 生成 | Implemented | `switchmap build-html` が index、switch、ports、VLAN、endpoint、search、history、debug を生成。 | 従来HTMLレイアウト完全一致は明示要求がない限り目標にしない。 |
| idle-since tracking | Implemented | `scan-switch` がスイッチ単位の idle state を更新。 | vendor追加時にfixtureを拡張。 |
| ARP import | Implemented | CSV と SNMP router ARP import をサポート。 | 必要に応じてrouter-family fixtureを追加。 |
| MAC/IP/hostname 相関 | Implemented | MAC list、ARP data、hostname import、reverse DNS、OUI表示に対応。 | SSH endpoint 相関は再現可能な fixture と integration test で維持する。 |
| Search UI | Implemented | `search/index.json` ベースの静的検索ページと FastAPI serve command。 | office/location workflow は専用viewが必要。 |
| SSH switch collection | Implemented | Cisco系、Juniper、FortiSwitch、Arista向け command profile。 | platform variant のfixture拡張。 |
| SNMP switch collection | Partial | IF-MIB、BRIDGE-MIB fallback、VLAN名、LLDP、sysDescr、sysUpTime。 | device-family OID と VLAN-aware FDB 検証を拡張。 |
| VLAN-aware SNMP FDB | Partial | デバイスが公開する場合は Q-BRIDGE FDB をparse。SNMP communityとして設定すれば VLAN-indexed community 収集も動作。 | VLAN-aware FDB を公開する device family の再現可能な fixture を追加する。 |
| LLDP/CDP neighbors | Implemented | SSH LLDP/CDP と SNMP LLDP neighbor を表示。 | vendor固有出力のcapability fixtureを追加。 |
| Neighbor capabilities | Partial | CDP capability と SNMP LLDP capability bitmap を保持。 | capability field を省略または変化させる device fixture を追加する。 |
| Trunk/uplink 表示 | Intentionally different | role は明示 `trunk_ports` または LLDP/CDP neighbor 根拠で決定。 | MAC数やendpoint数をrole根拠に使わない。 |
| Operational switchport evidence | Implemented | Cisco系SSHで mode、access VLAN、voice VLAN、native VLAN、allowed VLANs を取得。 | 非Cisco系の同等情報を追加。 |
| Switch inventory | Partial | SSH `show version` と SNMP `sysDescr`/`sysUpTime` を表示。 | platform別のmodel/serial/version OIDを追加。 |
| PoE/error counters | Partial | 対応profileでSSH PoE status/power と input/output errors を表示。 | SNMP PoE/error OID とfixtureを拡張。 |
| History/diffs | Implemented | history snapshot と差分ページを生成。 | 出力増加時はretention制御を検討。 |
| Debug diagnostics | Implemented | correlation trace、unmatched data、anomaly、artifact、port evidence を表示。 | Q-BRIDGE unavailable などSNMP FDB診断ラベルを追加。 |
| Site configuration | Intentionally different | `ThisSite.pm` は YAML 設定に置き換え。 | 公開・定期実行は外部automationで扱う。 |
| Office/location workflows | Not yet | 現在のsearchは host/IP/MAC/switch/port を対象。 | location/office metadata import とviewを追加。 |
| Perl module互換 | Intentionally different | Python modules は collection、rendering、storage、search に分割。 | Perl APIの直接互換は予定しない。 |

## 高優先度の残作業

1. Debug payload/UI に SNMP FDB 診断を追加する。
2. office/location metadata import と location-oriented view を追加する。
3. VLAN-aware SNMP FDB fixture を追加VLANへ拡張する、または Q-BRIDGE 対応ターゲットを追加する。
4. 代表的なCisco platform向けの structured inventory OID を追加する。
5. SSH command parsing 以外の PoE/error counter coverage を拡張する。
