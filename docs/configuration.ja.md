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

# 設定

- English version: [configuration.md](configuration.md)

## 設定ファイル

- 既定パス: `site.yml`
- 変更: `--config`
- YAML のトップレベルはマッピング必須。
- ファイル未存在や不正 YAML はコマンド失敗。

## トップレベルキー

- `destination_directory` (既定: `output`)
- `idlesince_directory` (既定: `idlesince`)
- `maclist_file` (既定: `maclist.json`)
- `unused_after_days` (既定: `30`)
- `snmp_timeout` (既定: `2`)
- `snmp_retries` (既定: `1`)
- `switches` (配列)
- `routers` (配列)

## `switches[]`

必須キー:

- `name`
- `management_ip`

SNMP モード (`collection_method: snmp` が既定):

- `snmp_version`: `1` | `2c` | `3`
- `1`/`2c`: `community` 必須
- `3`: `username` 必須
- v3 セキュリティ項目: `security_level`, `auth_protocol`, `auth_password`, `priv_protocol`, `priv_password`

SSH モード (`collection_method: ssh`):

- `ssh_username` 必須
- `ssh_password` または `ssh_private_key` が必須
- `ssh_port` 既定: `22`

任意キー:

- `vendor` (既定: `generic`)
- `trunk_ports` (ポート名配列)

## `routers[]`

必須キー:

- `name`
- `management_ip`

SNMP の要件はスイッチの SNMP 設定と同じです。

## 検証ルール

- スイッチ名の重複は禁止。
- ルータ名の重複は禁止。
