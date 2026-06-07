# Copyright 2026 OpenAI
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

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SYNTHETIC_FIXTURE_DIR = REPO_ROOT / "tests" / "fixtures" / "synthetic"
SYNTHETIC_FIXTURE_FILES = [
    REPO_ROOT / "docs" / "switch_cli_output_research.md",
    REPO_ROOT / "tests" / "test_ssh_collectors.py",
    REPO_ROOT / "tests" / "test_collectors.py",
    REPO_ROOT / "tests" / "test_maclist_store.py",
]
PRIVATE_DATA_PATTERNS = {
    "private IPv4 address": re.compile(
        r"(?<![\d.])(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})(?![\d.])"
    ),
    "local workspace path": re.compile(r"/Users/|/Volumes/|/home/[^/\s]+/"),
    "controller URL": re.compile(r"https?://(?:[^/\s.]+\.)?(?:controller|fortigate|fortimanager|panorama)[^\s]*", re.I),
    "non-demo FortiSwitch serial": re.compile(r"\bS\d{3}[A-Z0-9]{8,}\b"),
    "non-demo Cisco serial": re.compile(r"\bFOC[A-Z0-9]{5,}\b"),
}


def test_synthetic_fixture_policy_files_do_not_include_private_data():
    paths = SYNTHETIC_FIXTURE_FILES + sorted(SYNTHETIC_FIXTURE_DIR.glob("*.txt"))
    assert paths
    for path in paths:
        text = path.read_text(encoding="utf-8")
        for label, pattern in PRIVATE_DATA_PATTERNS.items():
            assert not pattern.search(text), f"{path.relative_to(REPO_ROOT)} contains {label}"


def test_research_note_marks_public_raw_output_as_not_copied():
    text = (REPO_ROOT / "docs" / "switch_cli_output_research.md").read_text(encoding="utf-8")
    table_rows = [line for line in text.splitlines() if line.startswith("|") and "`" in line]

    assert table_rows
    assert all(row.rstrip().endswith("| no |") for row in table_rows)
