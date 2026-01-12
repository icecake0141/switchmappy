# switchmapy

Python 3.12+ reimplementation of the Perl-based `switchmap` tooling. The CLI provides
SNMP collection, idle port tracking, static HTML generation, and a lightweight search UI.

## Features

- Collect port status and MAC information via SNMP for configured switches.
- Track idle ports over time and persist history.
- Build static HTML reports for operators.
- Optional FastAPI-based search UI over the generated data.

## Requirements

- Python 3.12+
- SNMP v2c access to network devices (for `scan-switch` / `build-html`)
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

## Configuration

Create `site.yml` in the repository root (or pass `--config` on the CLI).
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
    vendor: cisco
    snmp_version: 2c  # v2c only
    community: public
    trunk_ports: ["Gi1/0/48"]
routers:
  - name: edge-router
    management_ip: 192.0.2.1
    snmp_version: 2c  # v2c only
    community: public
```

For more detail, see `docs/usage.md`.

## CLI quick start

```bash
switchmap scan-switch
switchmap get-arp --source csv --csv maclist.csv
switchmap build-html
switchmap serve-search --host 0.0.0.0 --port 8000
```

## Output

- `destination_directory`: generated HTML and search index output.
- `idlesince_directory`: per-switch idle port tracking data.
- `maclist_file`: normalized MAC/IP/hostname data used in reports.

---

# switchmapy（日本語）

Perl版の`switchmap`をPython 3.12+で再実装したツール群です。CLIから
SNMP収集、アイドルポートの追跡、静的HTML生成、軽量な検索UIを提供します。

## 特長

- 設定したスイッチからSNMPでポート状態とMAC情報を収集。
- アイドルポートの履歴を保存して可視化。
- 運用向けの静的HTMLレポートを生成。
- 生成データに対するFastAPIベースの検索UI（オプション）。

## 動作要件

- Python 3.12以上
- ネットワーク機器へのSNMP v2cアクセス（`scan-switch` / `build-html`で使用）
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

## 設定

リポジトリ直下に`site.yml`を作成します（または`--config`で指定）。
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
    vendor: cisco
    snmp_version: 2c  # v2cのみ
    community: public
    trunk_ports: ["Gi1/0/48"]
routers:
  - name: edge-router
    management_ip: 192.0.2.1
    snmp_version: 2c  # v2cのみ
    community: public
```

詳細は`docs/usage.md`を参照してください。

## CLIクイックスタート

```bash
switchmap scan-switch
switchmap get-arp --source csv --csv maclist.csv
switchmap build-html
switchmap serve-search --host 0.0.0.0 --port 8000
```

## 出力先

- `destination_directory`: 生成されたHTMLと検索用インデックス。
- `idlesince_directory`: スイッチ別のアイドルポート追跡データ。
- `maclist_file`: レポートで使用するMAC/IP/ホスト名の正規化データ。
