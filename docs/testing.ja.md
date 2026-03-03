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

# テスト

- English version: [testing.md](testing.md)

## ローカル標準検証

```bash
python -m ruff check .
python -m pytest -q
python -m pre_commit run --all-files
```

## テスト対象マップ

- CLI 挙動・ログ: `tests/test_cli_*.py`, `tests/test_logging_schema.py`
- 収集ディスパッチと SNMP/SSH: `tests/test_collection_dispatch.py`, `tests/test_collectors*.py`, `tests/test_ssh_collectors.py`, `tests/test_snmp_session.py`
- レンダリングとビルド統合: `tests/test_build_*.py`, `tests/test_vlan_page.py`, `tests/test_mac_correlation_render.py`
- 検索サーバ: `tests/test_search_server*.py`
- 設定とストレージ: `tests/test_config.py`, `tests/test_idlesince_store.py`, `tests/test_maclist_store.py`
- ARP 取り込み: `tests/test_arp_csv_importer.py`, `tests/test_arp_snmp_importer.py`

## 回帰メモ

- XSS 回帰シナリオは `tests/XSS_REGRESSION_TESTS.md` に記載。
