<!--
Copyright 2025 OpenAI
SPDX-License-Identifier: Apache-2.0

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

This file was created or modified with the assistance of an AI (Large Language Model).
Review required for correctness, security, and licensing.
-->

# switchmappy

Python 3.12+ reimplementation of the Perl-based `switchmap` tooling. The CLI provides
SNMP collection, idle port tracking, static HTML generation, and a lightweight search UI.

## Features

- Collect port status and MAC information via SNMP for configured switches.
- Track idle ports over time and persist history.
- Build static HTML reports for operators.
- Optional FastAPI-based search UI over the generated data.

## Requirements

- Python 3.12+
- SNMP v1/v2c/v3 access to network devices (for `scan-switch` / `build-html`)
- Optional dependencies for SNMP and search features

## Installation

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e .
```

Optional dependencies:

```bash
pip install -e .[snmp,search]
```

For development checks:

```bash
pip install -e .[dev]
```

## Configuration

Create `site.yml` in the repository root (or pass `--config` on the CLI).
If the file is missing or invalid, the CLI reports a configuration error; an empty file
is treated as an empty configuration that uses defaults.
A minimal example:

```yaml
destination_directory: output
idlesince_directory: idlesince
maclist_file: maclist.json
unused_after_days: 30
snmp_timeout: 2
snmp_retries: 1
switches:
  - name: core-sw1
    management_ip: 192.0.2.10
    collection_method: snmp  # snmp | ssh
    vendor: cisco
    snmp_version: 2c  # 1 | 2c | 3
    community: public
    trunk_ports: ["Gi1/0/48"]
routers:
  - name: edge-router
    management_ip: 192.0.2.1
    snmp_version: 2c  # 1 | 2c | 3
    community: public
```

SNMPv3 example:

```yaml
switches:
  - name: core-sw1
    management_ip: 192.0.2.10
    snmp_version: 3
    username: snmpv3-user
    security_level: authPriv   # noAuthNoPriv | authNoPriv | authPriv
    auth_protocol: SHA256      # MD5 | SHA | SHA224 | SHA256 | SHA384 | SHA512
    auth_password: your-auth-pass
    priv_protocol: AES256      # DES | 3DES | AES | AES128 | AES192 | AES256
    priv_password: your-priv-pass
```

SSH collection (foundation) example:

```yaml
switches:
  - name: access-sw1
    management_ip: 192.0.2.20
    collection_method: ssh
    ssh_username: ops
    ssh_private_key: /home/ops/.ssh/id_ed25519
    trunk_ports: ["Gi1/0/24"]
```

Current SSH parser coverage is intentionally minimal:
- Cisco-like devices: `show interfaces status`
- Arista EOS: `show interfaces status`
- Juniper devices: `show interfaces terse`
- Fortinet FortiSwitch OS: `get switch interface status`
- Neighbor discovery:
  - Cisco-like / Arista EOS: `show lldp neighbors detail` (fallback: `show cdp neighbors detail`)
  - Juniper devices: `show lldp neighbors`
  - Fortinet FortiSwitch OS: `get switch lldp neighbors-detail`

For more detail, see `docs/usage.md`.

## CLI quick start

```bash
switchmap scan-switch
switchmap get-arp --source csv --csv maclist.csv
switchmap get-arp --source snmp
switchmap build-html
switchmap serve-search --host 0.0.0.0 --port 8000
```

`get-arp --source snmp` requires at least one router in `site.yml` under `routers:`.
All CLI commands support `--log-format text|json` (default: `text`).

## Validation (local, same as CI)

```bash
python -m ruff check .
python -m pytest -q
python -m pre_commit run --all-files
```

By default, `scan-switch` keeps idle-since entries for ports missing from the latest
scan. Use `--prune-missing` to drop entries for ports that no longer appear.

## Output

- `destination_directory`: generated HTML and search index output.
- `idlesince_directory`: per-switch idle port tracking data.
- `maclist_file`: normalized MAC/IP/hostname data used in reports.
- `unused_after_days`: ports idle for this many days or more are marked `Unused` on switch/ports pages.
- Failed switch collections and failure reasons are listed on the generated report index page.
- `destination_directory/vlans/index.html`: VLAN-centric view with VLAN filter and links to switch detail pages.
- `switches/*.html` / `ports/index.html`: ARP correlation (`IP (hostname)`) inferred from MAC matches in `maclist_file`.
- `switches/*.html` / `ports/index.html`: trunk ports listed in `trunk_ports` are marked in report tables.

Example ARP correlation output on a switch port row:

```text
192.0.2.100 (host-a)
192.0.2.101 (host-b)
```

---

# switchmappy（日本語）

Perl版の`switchmap`をPython 3.12+で再実装したツール群です。CLIから
SNMP収集、アイドルポートの追跡、静的HTML生成、軽量な検索UIを提供します。

## 特長

- 設定したスイッチからSNMPでポート状態とMAC情報を収集。
- アイドルポートの履歴を保存して可視化。
- 運用向けの静的HTMLレポートを生成。
- 生成データに対するFastAPIベースの検索UI（オプション）。

## 動作要件

- Python 3.12以上
- ネットワーク機器へのSNMP v1/v2c/v3アクセス（`scan-switch` / `build-html`で使用）
- SNMPや検索機能のためのオプション依存関係

## インストール

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e .
```

オプション依存関係:

```bash
pip install -e .[snmp,search]
```

開発時の検証用依存関係:

```bash
pip install -e .[dev]
```

## 設定

リポジトリ直下に`site.yml`を作成します（または`--config`で指定）。
ファイルが存在しない/不正な場合はCLIがエラーを表示し、空のファイルはデフォルト設定として扱います。
最小構成の例:

```yaml
destination_directory: output
idlesince_directory: idlesince
maclist_file: maclist.json
unused_after_days: 30
snmp_timeout: 2
snmp_retries: 1
switches:
  - name: core-sw1
    management_ip: 192.0.2.10
    collection_method: snmp  # snmp | ssh
    vendor: cisco
    snmp_version: 2c  # 1 | 2c | 3
    community: public
    trunk_ports: ["Gi1/0/48"]
routers:
  - name: edge-router
    management_ip: 192.0.2.1
    snmp_version: 2c  # 1 | 2c | 3
    community: public
```

SNMPv3設定例:

```yaml
switches:
  - name: core-sw1
    management_ip: 192.0.2.10
    snmp_version: 3
    username: snmpv3-user
    security_level: authPriv   # noAuthNoPriv | authNoPriv | authPriv
    auth_protocol: SHA256      # MD5 | SHA | SHA224 | SHA256 | SHA384 | SHA512
    auth_password: your-auth-pass
    priv_protocol: AES256      # DES | 3DES | AES | AES128 | AES192 | AES256
    priv_password: your-priv-pass
```

SSH収集（基盤実装）設定例:

```yaml
switches:
  - name: access-sw1
    management_ip: 192.0.2.20
    collection_method: ssh
    ssh_username: ops
    ssh_private_key: /home/ops/.ssh/id_ed25519
    trunk_ports: ["Gi1/0/24"]
```

詳細は`docs/usage.md`を参照してください。

## CLIクイックスタート

```bash
switchmap scan-switch
switchmap get-arp --source csv --csv maclist.csv
switchmap get-arp --source snmp
switchmap build-html
switchmap serve-search --host 0.0.0.0 --port 8000
```

`get-arp --source snmp` を使う場合は、`site.yml` の `routers:` に最低1台の定義が必要です。
すべてのCLIコマンドは `--log-format text|json`（デフォルト: `text`）をサポートします。

## 検証コマンド（ローカル/CI共通）

```bash
python -m ruff check .
python -m pytest -q
python -m pre_commit run --all-files
```

`scan-switch`は最新のスキャンに存在しないポートの履歴を保持します。
削除したい場合は`--prune-missing`を指定してください。

## 出力先

- `destination_directory`: 生成されたHTMLと検索用インデックス。
- `idlesince_directory`: スイッチ別のアイドルポート追跡データ。
- `maclist_file`: レポートで使用するMAC/IP/ホスト名の正規化データ。
- 収集に失敗したスイッチ名と理由は、レポートのトップページに一覧表示されます。
- `destination_directory/vlans/index.html`: VLAN一覧ページ（VLANフィルタとスイッチ詳細へのリンク付き）。
- `switches/*.html` / `ports/index.html`: MAC一致に基づくARP相関（`IP (hostname)`）を表示。

スイッチポート行でのARP相関表示例:

```text
192.0.2.100 (host-a)
192.0.2.101 (host-b)
```
