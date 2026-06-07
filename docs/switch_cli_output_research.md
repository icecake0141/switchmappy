<!--
Copyright 2026 OpenAI
SPDX-License-Identifier: Apache-2.0

This file was created or modified with the assistance of an AI (Large Language Model).
Review required for correctness, security, and licensing.
-->

# Switch CLI Output Research

This note tracks public command references used to design synthetic parser fixtures.
Raw public command output is not copied into this repository. Fixtures should be
small, synthetic examples that preserve command structure and edge cases without
including real site names, serial numbers, controller URLs, private addressing,
or operational notes from any private lab.

## Anonymization Rules

- Use documentation IP ranges only: `192.0.2.0/24`, `198.51.100.0/24`,
  and `203.0.113.0/24`.
- Use synthetic hostnames such as `core-1`, `access-1`, `leaf-1`, and
  `fortisw-1`.
- Use synthetic or locally administered MAC addresses only.
- Replace serial numbers and part-specific inventory values with generated demo
  values unless the value is a generic public optic model name.
- Do not store raw public command output. Store only purpose-built synthetic
  fixtures and cite the reference used for field shape.

## Coverage Matrix

| Vendor | Command family | Reference | Fields used for synthetic fixtures | Parser status | Raw output copied |
| --- | --- | --- | --- | --- | --- |
| Cisco IOS XE / NX-OS-like | `show interfaces status`, `show interfaces switchport`, `show interfaces transceiver`, `show interfaces counters errors`, `show power inline` | Cisco command references and DevNet NX-API interface examples | status, VLAN, duplex, speed, media/type, access/native/allowed VLAN, transceiver model, Tx/Rx dBm, current, errors, PoE | Implemented with Cisco-like parser tests | no |
| Arista EOS | `show interfaces status`, `show interfaces switchport`, `show interfaces transceiver` | Arista EOS Ethernet Ports documentation | Cisco-like table shape, media/type label, trunk VLAN fields, DOM power/current values | Implemented via Cisco-like parser path with Arista fixture coverage | no |
| Juniper Junos | `show interfaces terse`, `show ethernet-switching interfaces`, `show lldp neighbors`, `show interfaces diagnostics optics` | Juniper Junos CLI reference for interface and optics diagnostics | physical interface status, access/trunk VLAN membership, LLDP neighbor, Tx/Rx dBm, laser bias current | Interface, VLAN, neighbor, and optics parsing implemented | no |
| Fortinet FortiSwitch | `diagnose switch physical-ports summary`, `show switch interface`, `get switch modules summary`, `get switch modules status`, `get switch poe inline-status` | Fortinet FortiSwitchOS CLI reference and Fortinet community troubleshooting notes | status, TPID, VLAN, duplex, speed, flags, media, description/alias, mode, native VLAN, allowed VLANs, FortiLink hint, module part number, Tx/Rx dBm, current, PoE | Implemented with FortiSwitch parser tests | no |

## Fixture Guidance

- Keep each synthetic fixture focused on one parser behavior or command-family
  variation.
- Include whitespace, blank, and unknown-token variation when that variation
  affects parser behavior.
- Prefer model names that are already used in demo data, such as `SFP-10G-SR`,
  `SFP-10GLR-31`, and `QSFP28-LR4`.
- When adding a fixture, include a test assertion for every field the fixture is
  meant to protect.
