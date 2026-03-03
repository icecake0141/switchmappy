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
- スイッチごとの JSON ファイルによる idle-since 追跡。
- CSV または SNMP ルータからの ARP 取り込み。
- 静的 HTML (`index` / `switches` / `ports` / `vlans` / `search`) の生成。
- FastAPI/Uvicorn オプション依存での検索 UI 提供。

## 出力データ

- `destination_directory`: 生成される HTML と検索インデックス。
- `idlesince_directory`: スイッチ・ポート単位の idle-since 履歴。
- `maclist_file`: ARP 相関表示に使う MAC/IP/ホスト名対応データ。

## エラーハンドリング方針

- `scan-switch` は対象スイッチで失敗すると即時終了。
- `build-html` はスイッチ単位の SNMP/SSH 失敗を記録して継続。
- `get-arp --source snmp` は `site.yml` の `routers` 定義が必須。
