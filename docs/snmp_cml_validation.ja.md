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

# Cisco CML SNMP 検証

- English version: [snmp_cml_validation.md](snmp_cml_validation.md)

このメモは、Cisco CML を使った SwitchMappy の SNMP switch collection 検証手順を記録します。主な対象は Q-BRIDGE と VLAN-indexed community の FDB 挙動です。

## 範囲

次の SNMP FDB ケースを検証します:

- Q-BRIDGE VLAN FDB が返る場合に、port ごとの MAC と VLAN が取得できること。
- Q-BRIDGE が空または未公開でも、`public@10` のような VLAN-indexed community で legacy BRIDGE-MIB FDB が返ること。
- 診断が `Q-BRIDGE populated`、`Q-BRIDGE empty`、`FDB populated`、`VLAN-indexed community may be required` を区別すること。

## CML トポロジ

記録に残す名前とアドレスは documentation-only の値に置き換えてください:

- Cisco IOSvL2、Catalyst 9000v、または同等の CML switch node
- VLAN 10 と VLAN 20 など、複数の access VLAN
- VLAN ごとに少なくとも 1 つの endpoint
- LLDP や trunk evidence も同時に見る場合は router または 2 台目の switch

private controller URL、実ラボの IP 割当、node inventory、生の production output はコミットしないでください。

## 推奨 device 設定

CML switch には同等の設定を入れます:

```text
snmp-server community public RO
vlan 10
 name USERS
vlan 20
 name SERVERS
interface GigabitEthernet1/0/1
 switchport mode access
 switchport access vlan 10
 no shutdown
interface GigabitEthernet1/0/2
 switchport mode access
 switchport access vlan 20
 no shutdown
```

SNMP 取得前に endpoint から通信を発生させ、FDB entry が学習されている状態にします。

## Walk コマンド

SwitchMappy が使う OID family だけを取得します。helper は git-ignored の `local_cml_snmpwalks/` に出力します:

```bash
python scripts/collect_cml_snmpwalk.py \
  --target TARGET \
  --community public \
  --vlan 10 \
  --vlan 20
```

手動で実行する場合の同等コマンド:

```bash
snmpwalk -v2c -c public TARGET 1.3.6.1.2.1.31.1.1.1.1
snmpwalk -v2c -c public TARGET 1.3.6.1.2.1.31.1.1.1.18
snmpwalk -v2c -c public TARGET 1.3.6.1.2.1.2.2.1
snmpwalk -v2c -c public TARGET 1.3.6.1.2.1.17.1.4.1.2
snmpwalk -v2c -c public TARGET 1.3.6.1.2.1.17.7.1.2.2.1
snmpwalk -v2c -c public TARGET 1.3.6.1.2.1.17.7.1.4.3.1.1
snmpwalk -v2c -c public TARGET 1.3.6.1.2.1.47.1.1.1.1
```

VLAN-indexed community の検証:

```bash
snmpwalk -v2c -c public@10 TARGET 1.3.6.1.2.1.17.4.3.1
snmpwalk -v2c -c public@20 TARGET 1.3.6.1.2.1.17.4.3.1
```

## Fixture 方針

repository には合成 CML-style fixture だけを保存します:

- `tests/fixtures/synthetic/cisco_cml_qbridge_snmpwalk.txt`
- `tests/fixtures/synthetic/cisco_cml_vlan_indexed_community_snmpwalk.txt`

CML 観測結果から fixture を更新する場合は、SNMP output の形だけを残します。hostname、IP address、serial number、MAC address は documentation-only または locally administered な合成値に置き換えてください。

## 観測済み CML 挙動

Catalyst 9000v 系の検証では、Q-BRIDGE table が空または未公開でも、VLAN-indexed legacy BRIDGE-MIB で endpoint MAC が返る場合があります。この場合、SwitchMappy は VLAN-indexed community 設定時に endpoint を相関し、`Q-BRIDGE empty`、`FDB populated`、`VLAN-indexed community may be required` の診断を出す必要があります。

## 検証コマンド

作業中の focused test:

```bash
python -m pytest tests/test_collectors.py -q
```

到達可能な CML lab target に対する local collection:

```bash
python scripts/collect_cml_snmpwalk.py --target TARGET --community public --vlan 10 --vlan 20
```

PR 前の標準検証:

```bash
python -m ruff check .
python -m pytest -q
python -m pre_commit run --all-files
```
