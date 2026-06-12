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

# Cisco CML SNMP Validation

- Japanese translation: [snmp_cml_validation.ja.md](snmp_cml_validation.ja.md)

This note tracks repeatable Cisco CML validation for SNMP switch collection,
especially Q-BRIDGE and VLAN-indexed community behavior.

## Scope

Validate that SwitchMappy handles these SNMP FDB cases:

- Q-BRIDGE VLAN FDB rows are populated and produce per-port MAC and VLAN data.
- Q-BRIDGE rows are absent while legacy BRIDGE-MIB FDB rows are visible through
  a VLAN-indexed community such as `public@10`.
- Diagnostics distinguish `Q-BRIDGE populated`, `Q-BRIDGE empty`, `FDB
  populated`, and `VLAN-indexed community may be required`.

## CML Topology

Use documentation-only names and addresses in recorded notes:

- one Cisco IOSvL2 or comparable CML switch node,
- two access VLANs, for example VLAN 10 and VLAN 20,
- one endpoint on each VLAN so the switch learns at least one MAC per VLAN,
- optional trunk toward a router or second switch if LLDP and trunk evidence are
  part of the same validation run.

Do not commit private controller URLs, real lab addressing, node inventories, or
raw production output.

## Suggested Device Setup

Use an equivalent configuration for the CML switch:

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

Generate traffic from each endpoint before collecting SNMP data so FDB entries
exist.

## Walk Commands

Collect only the OID families needed by SwitchMappy. Replace target and
community values locally; do not commit private values. The helper writes to
`local_cml_snmpwalks/`, which is git-ignored:

```bash
python scripts/collect_cml_snmpwalk.py \
  --target TARGET \
  --community public \
  --vlan 10 \
  --vlan 20
```

Equivalent manual commands:

```bash
snmpwalk -v2c -c public TARGET 1.3.6.1.2.1.31.1.1.1.1
snmpwalk -v2c -c public TARGET 1.3.6.1.2.1.31.1.1.1.18
snmpwalk -v2c -c public TARGET 1.3.6.1.2.1.2.2.1
snmpwalk -v2c -c public TARGET 1.3.6.1.2.1.17.1.4.1.2
snmpwalk -v2c -c public TARGET 1.3.6.1.2.1.17.7.1.2.2.1
snmpwalk -v2c -c public TARGET 1.3.6.1.2.1.17.7.1.4.3.1.1
snmpwalk -v2c -c public TARGET 1.3.6.1.2.1.47.1.1.1.1
```

For VLAN-indexed community validation:

```bash
snmpwalk -v2c -c public@10 TARGET 1.3.6.1.2.1.17.4.3.1
snmpwalk -v2c -c public@20 TARGET 1.3.6.1.2.1.17.4.3.1
```

## Fixture Policy

The repository stores synthetic CML-style fixtures under
`tests/fixtures/synthetic/`:

- `cisco_cml_qbridge_snmpwalk.txt`
- `cisco_cml_vlan_indexed_community_snmpwalk.txt`

When updating these fixtures from CML observations, preserve only the shape of
the SNMP output. Replace hostnames, IP addresses, serial numbers, and MAC
addresses with documentation-only or locally administered synthetic values.

## Observed CML Behavior

Catalyst 9000v-style validation may expose endpoint MACs through VLAN-indexed
legacy BRIDGE-MIB while returning no Q-BRIDGE table rows. In that case,
SwitchMappy should still correlate the endpoint when the configured community is
VLAN-indexed, and it should emit diagnostics for `Q-BRIDGE empty`, `FDB
populated`, and `VLAN-indexed community may be required`.

## Validation Commands

Run focused tests while iterating:

```bash
python -m pytest tests/test_collectors.py -q
```

Run the local CML collection helper against a reachable lab target:

```bash
python scripts/collect_cml_snmpwalk.py --target TARGET --community public --vlan 10 --vlan 20
```

Run standard validation before opening a PR:

```bash
python -m ruff check .
python -m pytest -q
python -m pre_commit run --all-files
```
