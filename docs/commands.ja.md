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

# コマンド

- English version: [commands.md](commands.md)

## 共通オプション

運用系コマンドで利用可能:

- `--config <path>`
- `--debug | --info | --warn`
- `--logfile <path>`
- `--log-format text|json`

## `demo`

- 目的: `site.yml` やネットワーク機器なしでサンプルレポートを生成。
- オプション:
  - `--output <path>` (既定: `demo-output`)
  - `--host` (既定: `127.0.0.1`)
  - `--port` (既定: `8000`)
  - `--no-serve`: 静的出力のみ生成
  - `--date <ISO datetime>`: 決定的な出力用
- 挙動:
  - `<output>/.demo-state` に demo 用状態を保存、
  - サンプル optic diagnostics を含む Transceivers ページを生成、
  - 既定ではローカルサーバを起動、
  - 検索用依存が未導入の場合は `--no-serve` を使う。

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
  - `--resolve-hostnames`: 逆引き DNS に成功したホスト名を追加
- 挙動:
  - `snmp` 利用時は `routers` 設定が必須。

## `import-hostnames`

- 目的: IPAM、DHCP lease、またはインベントリのホスト名を MAC リストへ統合。
- オプション:
  - `--csv <path>` は `mac,ip,hostname` または `ip,hostname` の行を受け付ける
  - `--overwrite | --no-overwrite` で既存ホスト名の置き換えを制御
- 挙動:
  - MAC アドレスを優先し、次に IP アドレスで照合。

## `build-html`

- 目的: スイッチ状態を収集して静的 HTML を生成。
- オプション:
  - `--date <ISO datetime>`
- 挙動:
  - スイッチ単位の SNMP/SSH 失敗時は継続し、
  - 失敗理由を出力インデックスに記録。
  - `history_directory` に JSON 履歴スナップショットを保存。
  - 収集と相関の診断用に `/debug/index.html` を生成。
  - 取得済み optic diagnostics 用に `/transceivers/index.html` を生成。
  - 前回 snapshot との差分用に `/history/index.html` を生成。
  - collector artifact を `collection_artifacts_directory` に保存。

## `serve-search`

- 目的: 生成済み出力から検索 UI を配信。
- オプション:
  - `--host` (既定: `127.0.0.1`)
  - `--port` (既定: `8000`)
- 前提:
  - 検索用依存を導入: `pip install -e .[search]`
