# Copyright 2026 SwitchMappy
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

import argparse
import subprocess
from datetime import UTC, datetime
from pathlib import Path

OID_GROUPS = {
    "if_name": "1.3.6.1.2.1.31.1.1.1.1",
    "if_alias": "1.3.6.1.2.1.31.1.1.1.18",
    "if_table": "1.3.6.1.2.1.2.2.1",
    "bridge_port_ifindex": "1.3.6.1.2.1.17.1.4.1.2",
    "qbridge_vlan_fdb": "1.3.6.1.2.1.17.7.1.2.2.1",
    "qbridge_vlan_names": "1.3.6.1.2.1.17.7.1.4.3.1.1",
    "entity_inventory": "1.3.6.1.2.1.47.1.1.1.1",
}
VLAN_INDEXED_OIDS = {
    "legacy_fdb": "1.3.6.1.2.1.17.4.3.1",
}


def _run_snmpwalk(
    target: str,
    community: str,
    oid: str,
    timeout: int,
    retries: int,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            "snmpwalk",
            "-v2c",
            "-c",
            community,
            "-t",
            str(timeout),
            "-r",
            str(retries),
            target,
            oid,
        ],
        check=False,
        text=True,
        capture_output=True,
    )


def _write_result(path: Path, result: subprocess.CompletedProcess[str]) -> None:
    body = result.stdout
    if result.stderr:
        body += "\n# stderr\n" + result.stderr
    path.write_text(body, encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description="Collect Cisco CML SNMP walk excerpts for local validation.")
    parser.add_argument("--target", required=True, help="CML switch management address or hostname.")
    parser.add_argument("--community", required=True, help="SNMP v2c community for normal Q-BRIDGE collection.")
    parser.add_argument(
        "--vlan",
        action="append",
        default=[],
        help="VLAN ID to collect with a VLAN-indexed community, for example --vlan 10.",
    )
    parser.add_argument("--timeout", type=int, default=2)
    parser.add_argument("--retries", type=int, default=1)
    parser.add_argument("--output-dir", type=Path, default=Path("local_cml_snmpwalks"))
    args = parser.parse_args()

    timestamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    run_dir = args.output_dir / timestamp
    run_dir.mkdir(parents=True, exist_ok=True)

    failures: list[str] = []
    for name, oid in OID_GROUPS.items():
        result = _run_snmpwalk(args.target, args.community, oid, args.timeout, args.retries)
        _write_result(run_dir / f"{name}.walk", result)
        if result.returncode != 0:
            failures.append(f"{name}: snmpwalk exited {result.returncode}")

    for vlan in args.vlan:
        community = f"{args.community}@{vlan}"
        for name, oid in VLAN_INDEXED_OIDS.items():
            result = _run_snmpwalk(args.target, community, oid, args.timeout, args.retries)
            _write_result(run_dir / f"vlan_{vlan}_{name}.walk", result)
            if result.returncode != 0:
                failures.append(f"vlan {vlan} {name}: snmpwalk exited {result.returncode}")

    (run_dir / "README.txt").write_text(
        "\n".join(
            [
                "Local Cisco CML SNMP validation output.",
                "Do not commit this directory.",
                f"Target: {args.target}",
                f"Normal community: {args.community}",
                f"VLAN-indexed communities: {', '.join(args.vlan) if args.vlan else '(none)'}",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    print(f"Wrote SNMP walk output to {run_dir}")
    if failures:
        print("\n".join(failures))
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
