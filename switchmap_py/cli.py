# Copyright 2024 switchmappy
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
import logging
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import typer
import yaml

from switchmap_py.config import SiteConfig, default_config_path
from switchmap_py.importers.arp_csv import load_arp_csv
from switchmap_py.importers.arp_snmp import load_arp_snmp
from switchmap_py.render.build import build_site
from switchmap_py.search.app import SearchServer
from switchmap_py.snmp.collectors import collect_port_snapshots, collect_switch_state
from switchmap_py.snmp.session import SnmpError
from switchmap_py.storage.idlesince_store import IdleSinceStore
from switchmap_py.storage.maclist_store import MacListStore

app = typer.Typer(help="Switchmap Python CLI")

_SWITCHMAP_HANDLER_ATTR = "_switchmap_handler"


class CliUsageError(ValueError):
    pass


def _is_bool(value: object) -> bool:
    return isinstance(value, bool)


def _is_str(value: object) -> bool:
    return isinstance(value, str)


class JsonLogFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "event": getattr(record, "event", "log"),
            "command": getattr(record, "command", ""),
            "target": getattr(record, "target", ""),
            "status": getattr(record, "status", ""),
            "elapsed_ms": getattr(record, "elapsed_ms", None),
            "error_code": getattr(record, "error_code", None),
        }
        for key in ("switch", "router", "oid", "error_type", "entries_count"):
            value = getattr(record, key, None)
            if value is not None:
                payload[key] = value
        return json.dumps(payload, ensure_ascii=False)


def _classify_error(exc: BaseException) -> str:
    message = str(exc).lower()
    if isinstance(exc, SnmpError):
        if "timeout" in message:
            return "SNMP_TIMEOUT"
        if "community" in message or "authorization" in message or "auth" in message:
            return "SNMP_AUTH"
        if "oid" in message or "no such" in message:
            return "SNMP_OID"
        return "SNMP_ERROR"
    if isinstance(exc, (ValueError, yaml.YAMLError)):
        return "CONFIG_ERROR"
    return "UNEXPECTED_ERROR"


def _event_extra(
    *,
    event: str,
    command: str,
    status: str,
    target: str = "",
    elapsed_seconds: float | None = None,
    error_code: str | None = None,
) -> dict[str, object]:
    payload: dict[str, object] = {
        "event": event,
        "command": command,
        "status": status,
        "target": target,
        "error_code": error_code,
        "elapsed_ms": int((elapsed_seconds or 0.0) * 1000)
        if elapsed_seconds is not None
        else None,
    }
    if target:
        payload["switch"] = target
    return payload


def _load_config(path: Optional[Path]) -> SiteConfig:
    config_path = path or default_config_path()
    try:
        return SiteConfig.load(config_path)
    except FileNotFoundError as exc:
        raise CliUsageError(str(exc)) from exc
    except (ValueError, yaml.YAMLError) as exc:
        raise CliUsageError(
            f"Failed to load config '{config_path}': {exc}"
        ) from exc


def _configure_logging(
    *,
    debug: bool,
    info: bool,
    warn: bool,
    logfile: Optional[Path],
    log_format: str,
) -> None:
    if debug:
        level = logging.DEBUG
    elif info:
        level = logging.INFO
    elif warn:
        level = logging.WARNING
    else:
        level = logging.INFO
    handler: logging.Handler
    if logfile:
        handler = logging.FileHandler(logfile)
    else:
        handler = logging.StreamHandler()
    if log_format == "json":
        handler.setFormatter(JsonLogFormatter())
    else:
        handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
    setattr(handler, _SWITCHMAP_HANDLER_ATTR, True)

    root = logging.getLogger()
    root.handlers = [
        existing
        for existing in root.handlers
        if not getattr(existing, _SWITCHMAP_HANDLER_ATTR, False)
    ]
    root.setLevel(level)
    root.addHandler(handler)


@app.command("scan-switch")
def scan_switch(
    switch: Optional[str] = typer.Option(None, "--switch"),
    config: Optional[Path] = typer.Option(None, "--config"),
    debug: bool = typer.Option(False, "--debug"),
    info: bool = typer.Option(False, "--info"),
    warn: bool = typer.Option(False, "--warn"),
    logfile: Optional[Path] = typer.Option(None, "--logfile"),
    log_format: str = typer.Option("text", "--log-format"),
    prune_missing: bool = typer.Option(
        False,
        "--prune-missing",
        help="Remove ports that are missing from the latest scan.",
    ),
) -> None:
    """Scan switches and update idlesince data.

    This command fails fast on any error (including SNMP errors) to ensure
    scan failures are immediately visible to the operator.
    """
    switch = switch if _is_str(switch) else None
    config = config if isinstance(config, Path) else None
    logfile = logfile if isinstance(logfile, Path) else None
    log_format = log_format if _is_str(log_format) else "text"
    debug = debug if _is_bool(debug) else False
    info = info if _is_bool(info) else False
    warn = warn if _is_bool(warn) else False
    prune_missing = prune_missing if _is_bool(prune_missing) else False

    _configure_logging(
        debug=debug, info=info, warn=warn, logfile=logfile, log_format=log_format
    )
    logger = logging.getLogger(__name__)
    site = _load_config(config)
    store = IdleSinceStore(site.idlesince_directory)
    for sw in site.switches:
        if switch and sw.name != switch:
            continue
        started = time.monotonic()
        try:
            snapshots = collect_port_snapshots(sw, site.snmp_timeout, site.snmp_retries)
        except SnmpError as exc:
            logger.exception(
                "Failed to scan switch %s",
                sw.name,
                extra={
                    **_event_extra(
                        event="scan_switch",
                        command="scan-switch",
                        status="error",
                        target=sw.name,
                        elapsed_seconds=time.monotonic() - started,
                        error_code=_classify_error(exc),
                    ),
                    "error_type": type(exc).__name__,
                },
            )
            raise
        current = store.load(sw.name)
        updated = {} if prune_missing else dict(current)
        for snapshot in snapshots:
            state = current.get(snapshot.name)
            updated[snapshot.name] = store.update_port(
                state,
                port=snapshot.name,
                is_active=snapshot.is_active,
            )
        store.save(sw.name, updated)
        logger.info(
            "Updated idle-since state for switch",
            extra=_event_extra(
                event="scan_switch",
                command="scan-switch",
                status="success",
                target=sw.name,
                elapsed_seconds=time.monotonic() - started,
            ),
        )


@app.command("get-arp")
def get_arp(
    source: str = typer.Option("csv", "--source"),
    csv_path: Optional[Path] = typer.Option(None, "--csv"),
    config: Optional[Path] = typer.Option(None, "--config"),
    debug: bool = typer.Option(False, "--debug"),
    info: bool = typer.Option(False, "--info"),
    warn: bool = typer.Option(False, "--warn"),
    logfile: Optional[Path] = typer.Option(None, "--logfile"),
    log_format: str = typer.Option("text", "--log-format"),
) -> None:
    """Update MAC list from ARP data."""
    _configure_logging(
        debug=debug, info=info, warn=warn, logfile=logfile, log_format=log_format
    )
    logger = logging.getLogger(__name__)
    site = _load_config(config)
    store = MacListStore(site.maclist_file)
    if source == "csv":
        if not csv_path:
            raise CliUsageError("--csv is required when source=csv")
        started = time.monotonic()
        entries = load_arp_csv(csv_path)
        logger.info(
            "Loaded ARP entries from CSV",
            extra=_event_extra(
                event="get_arp",
                command="get-arp",
                status="success",
                elapsed_seconds=time.monotonic() - started,
            ),
        )
    elif source == "snmp":
        if not site.routers:
            raise CliUsageError(
                "No routers configured in site.yml; add routers or use --source csv"
            )
        started = time.monotonic()
        entries = load_arp_snmp(site.routers, site.snmp_timeout, site.snmp_retries)
        logger.info(
            "Collected ARP entries via SNMP",
            extra=_event_extra(
                event="get_arp",
                command="get-arp",
                status="success",
                elapsed_seconds=time.monotonic() - started,
            ),
        )
    else:
        raise CliUsageError("source must be one of: csv, snmp")
    store.save(entries)


@app.command("build-html")
def build_html(
    date: Optional[str] = typer.Option(None, "--date"),
    config: Optional[Path] = typer.Option(None, "--config"),
    debug: bool = typer.Option(False, "--debug"),
    info: bool = typer.Option(False, "--info"),
    warn: bool = typer.Option(False, "--warn"),
    logfile: Optional[Path] = typer.Option(None, "--logfile"),
    log_format: str = typer.Option("text", "--log-format"),
) -> None:
    """Build static HTML output.

    Collects state from all configured switches and generates static HTML reports.
    SNMP errors for individual switches are logged and those switches are marked as
    failed, allowing the build to continue with remaining switches. Any other
    exception type will cause the command to fail fast.
    """
    _configure_logging(
        debug=debug, info=info, warn=warn, logfile=logfile, log_format=log_format
    )
    logger = logging.getLogger(__name__)
    site = _load_config(config)
    build_date = datetime.fromisoformat(date) if date else datetime.now()
    switches = []
    failed_switches = []
    failed_switch_reasons: dict[str, str] = {}
    for sw in site.switches:
        started = time.monotonic()
        try:
            switches.append(
                collect_switch_state(sw, site.snmp_timeout, site.snmp_retries)
            )
            logger.info(
                "Collected switch state",
                extra=_event_extra(
                    event="build_html_collect",
                    command="build-html",
                    status="success",
                    target=sw.name,
                    elapsed_seconds=time.monotonic() - started,
                ),
            )
        except SnmpError as exc:
            # Only catch expected SNMP operational errors. Log and continue
            # with other switches. Programming errors will propagate.
            code = _classify_error(exc)
            logger.exception(
                "Failed to collect switch state for %s",
                sw.name,
                extra={
                    **_event_extra(
                        event="build_html_collect",
                        command="build-html",
                        status="error",
                        target=sw.name,
                        elapsed_seconds=time.monotonic() - started,
                        error_code=code,
                    ),
                    "error_type": type(exc).__name__,
                },
            )
            failed_switches.append(sw.name)
            failed_switch_reasons[sw.name] = f"[{code}] {exc}"
    build_site(
        switches=switches,
        failed_switches=failed_switches,
        failed_switch_reasons=failed_switch_reasons,
        output_dir=site.destination_directory,
        template_dir=Path(__file__).parent / "render" / "templates",
        static_dir=Path(__file__).parent / "render" / "static",
        idlesince_store=IdleSinceStore(site.idlesince_directory),
        maclist_store=MacListStore(site.maclist_file),
        build_date=build_date,
        unused_after_days=site.unused_after_days,
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
    log_format: str = typer.Option("text", "--log-format"),
) -> None:
    """Serve search UI from built HTML output."""
    _configure_logging(
        debug=debug, info=info, warn=warn, logfile=logfile, log_format=log_format
    )
    site = _load_config(config)
    server = SearchServer(site.destination_directory, host, port)
    server.serve()


if __name__ == "__main__":
    app()
