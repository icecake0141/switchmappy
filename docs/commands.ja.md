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

# コマンド

- English version: [commands.md](commands.md)

## 共通オプション

全コマンドで利用可能:

- `--config <path>`
- `--debug | --info | --warn`
- `--logfile <path>`
- `--log-format text|json`

## `scan-switch`

- 目的: スイッチごとの idle-since データ更新。
- オプション:
  - `--switch <name>`: 対象スイッチ限定
  - `--prune-missing`: 最新スキャンに存在しないポートを削除
- 挙動: 収集エラー発生時は即時終了。

## `get-arp`

- 目的: MAC リスト更新。
- オプション:
  - `--source csv|snmp` (既定: `csv`)
  - `--csv <path>` (`--source csv` 時に必須)
- 挙動:
  - `snmp` 利用時は `routers` 設定が必須。

## `build-html`

- 目的: スイッチ状態を収集して静的 HTML を生成。
- オプション:
  - `--date <ISO datetime>`
- 挙動:
  - スイッチ単位の SNMP/SSH 失敗時は継続し、
  - 失敗理由を出力インデックスに記録。

## `serve-search`

- 目的: 生成済み出力から検索 UI を配信。
- オプション:
  - `--host` (既定: `127.0.0.1`)
  - `--port` (既定: `8000`)
- 前提:
  - 検索用依存を導入: `pip install -e .[search]`
