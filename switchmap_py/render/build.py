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
from datetime import datetime
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from switchmap_py.model.switch import Switch
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


def build_site(
    *,
    switches: list[Switch],
    failed_switches: list[str],
    output_dir: Path,
    template_dir: Path,
    static_dir: Path,
    idlesince_store: IdleSinceStore,
    maclist_store: MacListStore,
    build_date: datetime,
) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    for subdir in ["ports", "vlans", "switches", "search"]:
        (output_dir / subdir).mkdir(parents=True, exist_ok=True)

    env = build_environment(template_dir)
    index_template = env.get_template("index.html.j2")
    switch_template = env.get_template("switch.html.j2")
    port_template = env.get_template("ports.html.j2")
    vlan_template = env.get_template("vlans.html.j2")
    search_template = env.get_template("search.html.j2")

    maclist = maclist_store.load()

    index_html = index_template.render(
        switches=switches,
        failed_switches=failed_switches,
        build_date=build_date,
    )
    (output_dir / "index.html").write_text(index_html, encoding="utf-8")

    for switch in switches:
        idle_states = idlesince_store.load(switch.name)
        switch_html = switch_template.render(
            switch=switch, idle_states=idle_states, build_date=build_date
        )
        (output_dir / "switches" / f"{switch.name}.html").write_text(switch_html, encoding="utf-8")

    port_html = port_template.render(
        switches=switches, maclist=maclist, build_date=build_date
    )
    (output_dir / "ports" / "index.html").write_text(port_html, encoding="utf-8")

    vlan_html = vlan_template.render(switches=switches, build_date=build_date)
    (output_dir / "vlans" / "index.html").write_text(vlan_html, encoding="utf-8")

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
        "failed_switches": failed_switches,
    }
    (output_dir / "search" / "index.json").write_text(
        json.dumps(search_payload, indent=2, sort_keys=True, ensure_ascii=False),
        encoding="utf-8",
    )
