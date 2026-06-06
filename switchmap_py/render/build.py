# Copyright 2024
# SPDX-License-Identifier: Apache-2.0
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# This file was created or modified with the assistance of an AI (Large Language Model).
# Review required for correctness, security, and licensing.

from __future__ import annotations

import json
import shutil
from dataclasses import asdict
from datetime import datetime, timedelta, timezone
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from switchmap_py.model.mac import MacEntry
from switchmap_py.model.switch import Switch
from switchmap_py.oui import load_oui_vendors, vendor_for_mac
from switchmap_py.storage.idlesince_store import IdleSinceStore
from switchmap_py.storage.maclist_store import MacListStore


def build_environment(template_dir: Path) -> Environment:
    # Security: Enable autoescape for .html.j2 templates to prevent XSS vulnerabilities.
    # Previously only ["html"] was specified, which did NOT match .html.j2 files.
    # Adding "j2" ensures all Jinja2 templates with .j2 extension are autoescaped,
    # protecting against injection of malicious HTML/JavaScript from SNMP, CSV, or
    # user-controlled data sources (switch names, port descriptions, etc.).
    return Environment(
        loader=FileSystemLoader(str(template_dir)),
        autoescape=select_autoescape(["html", "j2"]),
    )


def _build_mac_lookup(maclist: list[MacEntry]) -> dict[str, list[MacEntry]]:
    grouped: dict[str, dict[str, MacEntry]] = {}
    for entry in maclist:
        if not entry.mac:
            continue
        mac_key = entry.mac.lower()
        ip_key = entry.ip or ""
        per_ip = grouped.setdefault(mac_key, {})
        existing = per_ip.get(ip_key)
        if existing is None:
            per_ip[ip_key] = MacEntry(
                mac=entry.mac,
                ip=entry.ip,
                hostname=entry.hostname,
                switch=entry.switch,
                port=entry.port,
            )
            continue
        if not existing.hostname and entry.hostname:
            per_ip[ip_key] = MacEntry(
                mac=entry.mac,
                ip=entry.ip,
                hostname=entry.hostname,
                switch=entry.switch,
                port=entry.port,
            )
    lookup: dict[str, list[MacEntry]] = {}
    for mac_key, per_ip in grouped.items():
        values = list(per_ip.values())
        values.sort(key=lambda value: (value.ip or "", value.hostname or ""))
        lookup[mac_key] = values
    return lookup


def _mac_vendor_lookup(macs: list[str], oui_vendors: dict[str, str]) -> dict[str, str]:
    return {mac.lower(): vendor_for_mac(mac, oui_vendors) for mac in macs}


def _build_endpoint_correlations(
    switches: list[Switch],
    mac_entries_by_mac: dict[str, list[MacEntry]],
) -> list[MacEntry]:
    correlations_by_key: dict[tuple[str, str, str, str], MacEntry] = {}
    for switch in switches:
        for port in switch.ports:
            for mac in port.macs:
                mac_key = mac.lower()
                entries = mac_entries_by_mac.get(mac_key, [])
                if not entries:
                    continue
                for entry in entries:
                    key = (switch.name, port.name, mac_key, entry.ip or "")
                    existing = correlations_by_key.get(key)
                    if existing is None or (not existing.hostname and entry.hostname):
                        correlations_by_key[key] = MacEntry(
                            mac=mac,
                            ip=entry.ip,
                            hostname=entry.hostname,
                            switch=switch.name,
                            port=port.name,
                        )
    correlations = list(correlations_by_key.values())
    correlations.sort(
        key=lambda value: (
            value.switch or "",
            value.port or "",
            value.ip or "",
            value.mac.lower(),
        )
    )
    return correlations


def _build_endpoint_warnings(endpoint_correlations: list[MacEntry]) -> dict[tuple[str, str], str]:
    locations_by_mac: dict[str, set[tuple[str, str]]] = {}
    for entry in endpoint_correlations:
        if not entry.switch or not entry.port:
            continue
        locations_by_mac.setdefault(entry.mac.lower(), set()).add((entry.switch, entry.port))

    warnings: dict[tuple[str, str], str] = {}
    for entry in endpoint_correlations:
        locations = locations_by_mac.get(entry.mac.lower(), set())
        if len(locations) > 1:
            warnings[(entry.mac.lower(), entry.ip or "")] = "duplicate MAC"
    return warnings


def _build_report_summary(
    *,
    switches: list[Switch],
    endpoint_correlations: list[MacEntry],
    unused_ports_by_switch: dict[str, set[str]],
    failed_switches: list[str],
) -> dict[str, int]:
    ports = [port for switch in switches for port in switch.ports]
    return {
        "switches": len(switches),
        "failed": len(failed_switches),
        "ports": len(ports),
        "active_ports": sum(1 for port in ports if port.is_link_up),
        "unused_ports": sum(len(ports) for ports in unused_ports_by_switch.values()),
        "missing_descriptions": sum(1 for port in ports if port.needs_description),
        "endpoints": len(endpoint_correlations),
    }


def _build_vlan_summary(
    *,
    switches: list[Switch],
    mac_entries_by_mac: dict[str, list[MacEntry]],
) -> dict[str, dict[str, dict[str, int]]]:
    summary: dict[str, dict[str, dict[str, int]]] = {}
    for switch in switches:
        ports_by_name = {port.name: port for port in switch.ports}
        per_switch: dict[str, dict[str, int]] = {}
        for vlan in switch.vlans:
            macs: set[str] = set()
            endpoint_count = 0
            for port_name in vlan.ports:
                port = ports_by_name.get(port_name)
                if port is None:
                    continue
                for mac in port.macs:
                    mac_key = mac.lower()
                    macs.add(mac_key)
                    endpoint_count += len(mac_entries_by_mac.get(mac_key, []))
            per_switch[vlan.vlan_id] = {
                "macs": len(macs),
                "endpoints": endpoint_count,
            }
        summary[switch.name] = per_switch
    return summary


def _build_debug_payload(
    *,
    switches: list[Switch],
    maclist: list[MacEntry],
    endpoint_rows: list[dict[str, object]],
    failed_switches: list[str],
    failed_switch_reasons: dict[str, str],
    unused_ports_by_switch: dict[str, set[str]],
    build_date: datetime,
) -> dict[str, object]:
    ports = [port for switch in switches for port in switch.ports]
    switch_macs = {mac.lower() for port in ports for mac in port.macs}
    correlated_keys = {str(row.get("mac", "")).lower() for row in endpoint_rows}
    maclist_keys = {entry.mac.lower() for entry in maclist if entry.mac}
    unmatched_maclist = [
        {
            **asdict(entry),
            "reason": "MAC not present in collected switch tables",
        }
        for entry in maclist
        if entry.mac.lower() not in switch_macs
    ]
    unmatched_switch_macs = [
        {
            "mac": mac,
            "reason": "MAC present on switch but missing from maclist",
        }
        for mac in sorted(switch_macs - maclist_keys)
    ]
    correlation_trace = []
    for row in endpoint_rows:
        correlation_trace.append(
            {
                "hostname": row.get("hostname") or "",
                "ip": row.get("ip") or "",
                "mac": row.get("mac") or "",
                "vendor": row.get("vendor") or "",
                "switch": row.get("switch") or "",
                "port": row.get("port") or "",
                "warning": row.get("warning") or "",
                "source": "maclist + switch mac table",
            }
        )

    port_debug = []
    anomalies = []
    for switch in switches:
        for port in switch.ports:
            mac_count = len(port.macs)
            correlated_count = sum(1 for mac in port.macs if mac.lower() in correlated_keys)
            neighbor_count = len(port.neighbors)
            is_unused = port.name in unused_ports_by_switch.get(switch.name, set())
            row = {
                "switch": switch.name,
                "port": port.name,
                "description": port.descr,
                "admin_status": port.admin_status,
                "oper_status": port.oper_status,
                "vlan": port.vlan or "",
                "duplex": port.duplex or "",
                "speed": port.speed,
                "last_change": port.last_change or "",
                "mac_count": mac_count,
                "correlated_endpoint_count": correlated_count,
                "neighbor_count": neighbor_count,
                "is_trunk": port.is_trunk,
                "is_unused": is_unused,
                "input_errors": port.input_errors,
                "output_errors": port.output_errors,
            }
            port_debug.append(row)
            if port.needs_description:
                anomalies.append({"severity": "warning", "type": "missing description", **row})
            if port.is_trunk and correlated_count:
                anomalies.append({"severity": "info", "type": "endpoint visible on trunk", **row})
            if mac_count and correlated_count == 0:
                anomalies.append({"severity": "info", "type": "uncorrelated switch MACs", **row})

    switch_debug = []
    for switch in switches:
        switch_ports = switch.ports
        switch_debug.append(
            {
                "name": switch.name,
                "management_ip": switch.management_ip,
                "vendor": switch.vendor,
                "ports": len(switch_ports),
                "active_ports": sum(1 for port in switch_ports if port.is_link_up),
                "macs": sum(len(port.macs) for port in switch_ports),
                "vlans": len(switch.vlans),
                "neighbors": sum(len(port.neighbors) for port in switch_ports),
                "endpoints": sum(1 for row in endpoint_rows if row.get("switch") == switch.name),
            }
        )

    return {
        "build": {
            "generated_at": build_date.isoformat(),
            "failed_switches": failed_switches,
            "failed_switch_reasons": failed_switch_reasons,
        },
        "summary": {
            "switches": len(switches),
            "failed_switches": len(failed_switches),
            "ports": len(ports),
            "maclist_entries": len(maclist),
            "switch_macs": len(switch_macs),
            "endpoint_correlations": len(endpoint_rows),
            "unmatched_maclist_entries": len(unmatched_maclist),
            "unmatched_switch_macs": len(unmatched_switch_macs),
            "anomalies": len(anomalies),
        },
        "switches": switch_debug,
        "ports": port_debug,
        "correlation_trace": correlation_trace,
        "unmatched_maclist": unmatched_maclist,
        "unmatched_switch_macs": unmatched_switch_macs,
        "anomalies": anomalies,
    }


def _to_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _build_unused_ports(
    *,
    idle_states_by_switch: dict[str, dict[str, object]],
    build_date: datetime,
    unused_after_days: int,
) -> dict[str, set[str]]:
    cutoff = _to_utc(build_date) - timedelta(days=unused_after_days)
    unused_ports_by_switch: dict[str, set[str]] = {}
    for switch_name, idle_states in idle_states_by_switch.items():
        unused_ports: set[str] = set()
        for port_name, idle_state in idle_states.items():
            idle_since = getattr(idle_state, "idle_since", None)
            if isinstance(idle_since, datetime) and _to_utc(idle_since) <= cutoff:
                unused_ports.add(port_name)
        unused_ports_by_switch[switch_name] = unused_ports
    return unused_ports_by_switch


def build_site(
    *,
    switches: list[Switch],
    failed_switches: list[str],
    failed_switch_reasons: dict[str, str] | None = None,
    output_dir: Path,
    template_dir: Path,
    static_dir: Path,
    idlesince_store: IdleSinceStore,
    maclist_store: MacListStore,
    build_date: datetime,
    unused_after_days: int = 30,
    oui_file: Path | None = None,
    history_dir: Path | None = None,
) -> None:
    failed_switch_reasons = failed_switch_reasons or {}
    output_dir.mkdir(parents=True, exist_ok=True)
    for subdir in ["debug", "endpoints", "ports", "vlans", "switches", "search"]:
        (output_dir / subdir).mkdir(parents=True, exist_ok=True)

    env = build_environment(template_dir)
    index_template = env.get_template("index.html.j2")
    switch_template = env.get_template("switch.html.j2")
    port_template = env.get_template("ports.html.j2")
    vlan_template = env.get_template("vlans.html.j2")
    endpoint_template = env.get_template("endpoints.html.j2")
    debug_template = env.get_template("debug.html.j2")
    search_template = env.get_template("search.html.j2")

    maclist = maclist_store.load()
    oui_vendors = load_oui_vendors(oui_file)
    mac_entries_by_mac = _build_mac_lookup(maclist)
    endpoint_correlations = _build_endpoint_correlations(switches, mac_entries_by_mac)
    endpoint_warnings = _build_endpoint_warnings(endpoint_correlations)
    idle_states_by_switch = {switch.name: idlesince_store.load(switch.name) for switch in switches}
    unused_ports_by_switch = _build_unused_ports(
        idle_states_by_switch=idle_states_by_switch,
        build_date=build_date,
        unused_after_days=unused_after_days,
    )
    report_summary = _build_report_summary(
        switches=switches,
        endpoint_correlations=endpoint_correlations,
        unused_ports_by_switch=unused_ports_by_switch,
        failed_switches=failed_switches,
    )
    vlan_summary = _build_vlan_summary(switches=switches, mac_entries_by_mac=mac_entries_by_mac)

    index_html = index_template.render(
        switches=switches,
        failed_switches=failed_switches,
        failed_switch_reasons=failed_switch_reasons,
        report_summary=report_summary,
        build_date=build_date,
    )
    (output_dir / "index.html").write_text(index_html, encoding="utf-8")

    for switch in switches:
        idle_states = idle_states_by_switch.get(switch.name, {})
        switch_html = switch_template.render(
            switch=switch,
            idle_states=idle_states,
            unused_ports=unused_ports_by_switch.get(switch.name, set()),
            unused_after_days=unused_after_days,
            mac_entries_by_mac=mac_entries_by_mac,
            mac_vendor_lookup=_mac_vendor_lookup(
                [mac for port in switch.ports for mac in port.macs],
                oui_vendors,
            ),
            build_date=build_date,
        )
        (output_dir / "switches" / f"{switch.name}.html").write_text(switch_html, encoding="utf-8")

    port_html = port_template.render(
        switches=switches,
        idle_states_by_switch=idle_states_by_switch,
        unused_ports_by_switch=unused_ports_by_switch,
        unused_after_days=unused_after_days,
        mac_entries_by_mac=mac_entries_by_mac,
        mac_vendor_lookup=_mac_vendor_lookup(
            [mac for switch in switches for port in switch.ports for mac in port.macs],
            oui_vendors,
        ),
        build_date=build_date,
    )
    (output_dir / "ports" / "index.html").write_text(port_html, encoding="utf-8")

    vlan_html = vlan_template.render(switches=switches, vlan_summary=vlan_summary, build_date=build_date)
    (output_dir / "vlans" / "index.html").write_text(vlan_html, encoding="utf-8")

    endpoint_rows = [
        {
            **asdict(entry),
            "vendor": vendor_for_mac(entry.mac, oui_vendors),
            "warning": endpoint_warnings.get((entry.mac.lower(), entry.ip or ""), ""),
        }
        for entry in endpoint_correlations
    ]
    endpoint_html = endpoint_template.render(endpoints=endpoint_rows, switches=switches, build_date=build_date)
    (output_dir / "endpoints" / "index.html").write_text(endpoint_html, encoding="utf-8")

    debug_payload = _build_debug_payload(
        switches=switches,
        maclist=maclist,
        endpoint_rows=endpoint_rows,
        failed_switches=failed_switches,
        failed_switch_reasons=failed_switch_reasons,
        unused_ports_by_switch=unused_ports_by_switch,
        build_date=build_date,
    )
    debug_html_payload = {
        **debug_payload,
        "build": {
            **debug_payload["build"],
            "output_directory": str(output_dir),
            "history_directory": str(history_dir) if history_dir is not None else "",
        },
    }
    debug_html = debug_template.render(debug=debug_html_payload, build_date=build_date)
    (output_dir / "debug" / "index.html").write_text(debug_html, encoding="utf-8")

    search_html = search_template.render(build_date=build_date)
    (output_dir / "search" / "index.html").write_text(search_html, encoding="utf-8")

    for asset in static_dir.iterdir():
        destination = output_dir / asset.name
        if asset.is_dir():
            shutil.copytree(asset, destination, dirs_exist_ok=True)
        elif asset.is_file():
            shutil.copyfile(asset, destination)

    # JSON serialization: Using asdict() for all dataclasses to ensure consistent
    # schema representation. MacEntry is a dataclass, so we use asdict() instead
    # of __dict__ to maintain consistency with the Switch serialization approach.
    # The sort_keys=True ensures deterministic, reproducible JSON output.
    # The ensure_ascii=False preserves UTF-8 characters in output (instead of \uXXXX escapes).
    search_payload = {
        "generated_at": build_date.isoformat(),
        "switches": [asdict(switch) for switch in switches],
        "maclist": [asdict(entry) for entry in maclist],
        "endpoint_correlations": endpoint_rows,
        "failed_switches": failed_switches,
        "debug": debug_payload,
    }
    (output_dir / "search" / "index.json").write_text(
        json.dumps(search_payload, indent=2, sort_keys=True, ensure_ascii=False),
        encoding="utf-8",
    )
    if history_dir is not None:
        history_dir.mkdir(parents=True, exist_ok=True)
        stamp = _to_utc(build_date).strftime("%Y%m%dT%H%M%SZ")
        (history_dir / f"{stamp}.json").write_text(
            json.dumps(search_payload, indent=2, sort_keys=True, ensure_ascii=False),
            encoding="utf-8",
        )
