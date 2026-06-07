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

# Perl to Python Mapping

- Japanese translation: [migration_notes.ja.md](migration_notes.ja.md)

| Perl Component | Python Module / Command | Notes |
| --- | --- | --- |
| `ScanSwitch.pl` | `switchmap scan-switch` (`switchmap_py.cli`) | Updates idle-since state files via `IdleSinceStore`. |
| `SwitchMap.pl` | `switchmap build-html` (`switchmap_py.render.build`) | Builds static HTML with Jinja2 templates. |
| `GetArp.pl` | `switchmap get-arp` (`switchmap_py.cli`) | Supports CSV import and SNMP ARP collection from configured routers. |
| `FindOffice.pl` + `SearchPortlists.html` | `switchmap serve-search` + `render/templates/search.html.j2` | Serves local search UI backed by `search/index.json`. |
| `ThisSite.pm` | `switchmap_py.config.SiteConfig` | YAML-based site configuration. |
| `*.pm` modules | `switchmap_py.snmp.*`, `switchmap_py.model.*` | Split into SNMP sessions, collectors, and domain models. |

## Notes

- SNMP v1/v2c/v3 are supported.
- Switch collection supports `collection_method: snmp|ssh`.
- Cisco-like SSH collection captures `show interfaces switchport` evidence for
  operational mode, access VLAN, voice VLAN, native VLAN, and allowed VLANs.
- Switch inventory is exposed where available. SSH uses `show version` for
  Cisco-like devices; SNMP exposes `sysDescr` and `sysUpTime`.
- LLDP/CDP neighbor capabilities are retained when available, including SNMP
  LLDP capability bitmap decoding.

## Remaining Differences from Perl SwitchMap

See [SwitchMap Gap Analysis](switchmap_gap_analysis.md) for the full matrix.

- Exact legacy HTML layout parity is not guaranteed.
- Device-family OID coverage may still be narrower than mature Perl deployments.
- Site-specific `ThisSite.pm` behaviors such as publishing and scheduling are
  represented as YAML configuration and local commands, not as a Perl-compatible
  runtime.
- Location or office-specific workflows from `FindOffice.pl` are represented by
  search/debug pages, not by a one-for-one UI clone.
