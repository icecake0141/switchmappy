# Perl to Python Mapping

| Perl Component | Python Module / Command | Notes |
| --- | --- | --- |
| `ScanSwitch.pl` | `switchmap scan-switch` (`switchmap_py.cli`) | Updates idle-since state files via `IdleSinceStore`. |
| `SwitchMap.pl` | `switchmap build-html` (`switchmap_py.render.build`) | Builds static HTML with Jinja2 templates. |
| `GetArp.pl` | `switchmap get-arp` (`switchmap_py.cli`) | Supports CSV import and SNMP ARP collection from configured routers. |
| `FindOffice.pl` + `SearchPortlists.html` | `switchmap serve-search` + `render/templates/search.html.j2` | Serves local search UI backed by `search/index.json`. |
| `ThisSite.pm` | `switchmap_py.config.SiteConfig` | YAML-based site configuration. |
| `*.pm` modules | `switchmap_py.snmp.*`, `switchmap_py.model.*` | Split into SNMP sessions, collectors, and domain models. |

## Notes

- This implementation focuses on parity for file-based storage and static HTML output first.
- SNMP v2c is currently supported; vendor-specific MIB coverage can be extended in `switchmap_py/snmp/mibs.py`.
