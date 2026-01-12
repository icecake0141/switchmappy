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

from dataclasses import asdict
from datetime import datetime
import json
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from switchmap_py.model.switch import Switch
from switchmap_py.storage.idlesince_store import IdleSinceStore
from switchmap_py.storage.maclist_store import MacListStore


def build_environment(template_dir: Path) -> Environment:
    return Environment(
        loader=FileSystemLoader(str(template_dir)),
        autoescape=select_autoescape(["html"]),
    )


def build_site(
    *,
    switches: list[Switch],
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
    search_template = env.get_template("search.html.j2")

    maclist = maclist_store.load()

    index_html = index_template.render(switches=switches, build_date=build_date)
    (output_dir / "index.html").write_text(index_html)

    for switch in switches:
        idle_states = idlesince_store.load(switch.name)
        switch_html = switch_template.render(
            switch=switch, idle_states=idle_states, build_date=build_date
        )
        (output_dir / "switches" / f"{switch.name}.html").write_text(switch_html)

    port_html = port_template.render(
        switches=switches, maclist=maclist, build_date=build_date
    )
    (output_dir / "ports" / "index.html").write_text(port_html)

    search_html = search_template.render(build_date=build_date)
    (output_dir / "search" / "index.html").write_text(search_html)

    for asset in static_dir.glob("*"):
        if asset.is_file():
            (output_dir / asset.name).write_text(asset.read_text())

    search_payload = {
        "generated_at": build_date.isoformat(),
        "switches": [asdict(switch) for switch in switches],
        "maclist": [entry.__dict__ for entry in maclist],
    }
    (output_dir / "search" / "index.json").write_text(
        json.dumps(search_payload, indent=2)
    )
