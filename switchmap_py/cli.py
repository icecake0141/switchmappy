# Copyright 2024 switchmapy
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

from datetime import datetime
import logging
from pathlib import Path
from typing import Optional

import typer
import yaml

from switchmap_py.config import SiteConfig, default_config_path
from switchmap_py.model.mac import MacEntry
from switchmap_py.render.build import build_site
from switchmap_py.search.app import SearchServer
from switchmap_py.snmp.collectors import collect_port_snapshots, collect_switch_state
from switchmap_py.storage.idlesince_store import IdleSinceStore
from switchmap_py.storage.maclist_store import MacListStore

app = typer.Typer(help="Switchmap Python CLI")


def _load_config(path: Optional[Path]) -> SiteConfig:
    config_path = path or default_config_path()
    try:
        return SiteConfig.load(config_path)
    except FileNotFoundError as exc:
        raise typer.BadParameter(str(exc)) from exc
    except (ValueError, yaml.YAMLError) as exc:
        raise typer.BadParameter(
            f"Failed to load config '{config_path}': {exc}"
        ) from exc


def _configure_logging(
    *, debug: bool, info: bool, warn: bool, logfile: Optional[Path]
) -> None:
    if debug:
        level = logging.DEBUG
    elif info:
        level = logging.INFO
    elif warn:
        level = logging.WARNING
    else:
        level = logging.INFO
    handlers: list[logging.Handler] = []
    if logfile:
        handlers.append(logging.FileHandler(logfile))
    else:
        handlers.append(logging.StreamHandler())
    logging.basicConfig(level=level, handlers=handlers)


@app.command("scan-switch")
def scan_switch(
    switch: Optional[str] = typer.Option(None, "--switch"),
    config: Optional[Path] = typer.Option(None, "--config"),
    debug: bool = typer.Option(False, "--debug"),
    info: bool = typer.Option(False, "--info"),
    warn: bool = typer.Option(False, "--warn"),
    logfile: Optional[Path] = typer.Option(None, "--logfile"),
) -> None:
    """Scan switches and update idlesince data."""
    _configure_logging(debug=debug, info=info, warn=warn, logfile=logfile)
    site = _load_config(config)
    store = IdleSinceStore(site.idlesince_directory)
    for sw in site.switches:
        if switch and sw.name != switch:
            continue
        snapshots = collect_port_snapshots(sw, site.snmp_timeout, site.snmp_retries)
        current = store.load(sw.name)
        updated = {}
        for snapshot in snapshots:
            state = current.get(snapshot.name)
            updated[snapshot.name] = store.update_port(
                state,
                port=snapshot.name,
                is_active=snapshot.is_active,
            )
        store.save(sw.name, updated)


@app.command("get-arp")
def get_arp(
    source: str = typer.Option("csv", "--source"),
    csv_path: Optional[Path] = typer.Option(None, "--csv"),
    config: Optional[Path] = typer.Option(None, "--config"),
    debug: bool = typer.Option(False, "--debug"),
    info: bool = typer.Option(False, "--info"),
    warn: bool = typer.Option(False, "--warn"),
    logfile: Optional[Path] = typer.Option(None, "--logfile"),
) -> None:
    """Update MAC list from ARP data."""
    _configure_logging(debug=debug, info=info, warn=warn, logfile=logfile)
    site = _load_config(config)
    store = MacListStore(site.maclist_file)
    entries: list[MacEntry] = []
    if source == "csv":
        if not csv_path:
            raise typer.BadParameter("--csv is required when source=csv")
        for line in csv_path.read_text().splitlines():
            if not line.strip() or line.startswith("#"):
                continue
            mac, ip, *rest = [part.strip() for part in line.split(",")]
            hostname = rest[0] if rest else None
            entries.append(
                MacEntry(mac=mac, ip=ip, hostname=hostname, switch=None, port=None)
            )
    else:
        raise typer.BadParameter("Only csv source is supported in this implementation")
    store.save(entries)


@app.command("build-html")
def build_html(
    date: Optional[str] = typer.Option(None, "--date"),
    config: Optional[Path] = typer.Option(None, "--config"),
    debug: bool = typer.Option(False, "--debug"),
    info: bool = typer.Option(False, "--info"),
    warn: bool = typer.Option(False, "--warn"),
    logfile: Optional[Path] = typer.Option(None, "--logfile"),
) -> None:
    """Build static HTML output."""
    _configure_logging(debug=debug, info=info, warn=warn, logfile=logfile)
    logger = logging.getLogger(__name__)
    site = _load_config(config)
    build_date = datetime.fromisoformat(date) if date else datetime.now()
    switches = []
    failed_switches = []
    for sw in site.switches:
        try:
            switches.append(
                collect_switch_state(sw, site.snmp_timeout, site.snmp_retries)
            )
        except Exception:
            logger.exception("Failed to collect switch state for %s", sw.name)
            failed_switches.append(sw.name)
    build_site(
        switches=switches,
        failed_switches=failed_switches,
        output_dir=site.destination_directory,
        template_dir=Path(__file__).parent / "render" / "templates",
        static_dir=Path(__file__).parent / "render" / "static",
        idlesince_store=IdleSinceStore(site.idlesince_directory),
        maclist_store=MacListStore(site.maclist_file),
        build_date=build_date,
    )


@app.command("serve-search")
def serve_search(
    host: str = typer.Option("127.0.0.1", "--host"),
    port: int = typer.Option(8000, "--port"),
    config: Optional[Path] = typer.Option(None, "--config"),
    debug: bool = typer.Option(False, "--debug"),
    info: bool = typer.Option(False, "--info"),
    warn: bool = typer.Option(False, "--warn"),
    logfile: Optional[Path] = typer.Option(None, "--logfile"),
) -> None:
    """Serve search UI from built HTML output."""
    _configure_logging(debug=debug, info=info, warn=warn, logfile=logfile)
    site = _load_config(config)
    server = SearchServer(site.destination_directory, host, port)
    server.serve()


if __name__ == "__main__":
    app()
