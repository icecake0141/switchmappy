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
from pathlib import Path


def load_index(output_dir: Path) -> dict:
    index_path = output_dir / "search" / "index.json"
    if not index_path.exists():
        return {}
    return json.loads(index_path.read_text())
