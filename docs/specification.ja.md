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

# 仕様

- English version: [specification.md](specification.md)

## 対応ランタイム

- Python 3.12以上

## 主要機能

- SNMP または SSH によるスイッチのポート情報収集。
- 取得可能な場合、platform、serial number、OS version、uptime などの装置インベントリを収集。
- スイッチごとの JSON ファイルによる idle-since 追跡。
- CSV または SNMP ルータからの ARP 取り込み。
- 静的 HTML (`index` / `switches` / `ports` / `vlans` / `search`) の生成。
- FastAPI/Uvicorn オプション依存での検索 UI 提供。

## 出力データ

- `destination_directory`: 生成される HTML と検索インデックス。
- `idlesince_directory`: スイッチ・ポート単位の idle-since 履歴。
- `maclist_file`: ARP 相関表示に使う MAC/IP/ホスト名対応データ。

## ポート role 表示

- `configured_trunk`: `trunk_ports` に明示されたポート。
- `network_neighbor`: LLDP/CDP neighbor があり、ネットワーク機器隣接として表示されるポート。
- `unknown`: 明示 trunk 設定や neighbor 根拠がないポート。
- MAC 数、endpoint 数、複数 VLAN 観測は role 判定に使いません。

## Switchport Evidence

Cisco 系 SSH collection では、利用可能な場合に `show interfaces switchport`
を使い、operational mode、access VLAN、voice VLAN、native VLAN、allowed VLANs
を表示します。collector が公開する場合は SFP/QSFP optic label などの
speed/media type も switch、ports、search、debug view に表示します。
Cisco 系 SSH では利用可能な場合に `show interfaces transceiver` も取得し、
optic model、Tx/Rx optical power (dBm)、bias current (mA) を記録します。
Juniper SSH では利用可能な場合に `show interfaces diagnostics optics` を取得し、
Tx/Rx optical power と laser bias current を記録します。FortiSwitch SSH では
利用可能な場合に module summary/status 出力も取得し、module part number と
DMI optical level を記録します。詳細な transceiver diagnostics は Transceivers
page と Debug payload に表示し、search index では検索対象として保持します。
multi-lane module の単一表示では、平均ではなく Tx/Rx dBm は最弱 lane、
bias current は最大 lane を使い、劣化 lane が隠れないようにします。
これらはレポートと検索データで確認するための根拠情報であり、明示的な
`trunk_ports` role assignment を上書きしません。

## Neighbor Capabilities

collector が取得できる場合、LLDP/CDP neighbor capability を保持します。SNMP
LLDP capability bitmap は `bridge` や `router` などの読みやすいラベルに変換します。

## エラーハンドリング方針

- `scan-switch` は対象スイッチで失敗すると即時終了。
- `build-html` はスイッチ単位の SNMP/SSH 失敗を記録して継続。
- `get-arp --source snmp` は `site.yml` の `routers` 定義が必須。
