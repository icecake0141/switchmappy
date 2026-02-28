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

import json

import pytest

from switchmap_py.search.app import SearchServer


def test_search_server_serves_search_assets_via_fastapi(tmp_path):
    fastapi = pytest.importorskip("fastapi")
    testclient_mod = pytest.importorskip("fastapi.testclient")
    assert fastapi is not None

    (tmp_path / "search").mkdir()
    (tmp_path / "search" / "index.html").write_text("<h1>Search</h1>", encoding="utf-8")
    (tmp_path / "search" / "index.json").write_text(
        json.dumps({"maclist": [], "switches": []}),
        encoding="utf-8",
    )
    app = SearchServer(output_dir=tmp_path, host="127.0.0.1", port=8000).build_app()
    client = testclient_mod.TestClient(app)

    root_response = client.get("/", follow_redirects=False)
    assert root_response.status_code in {302, 307}
    assert root_response.headers["location"] == "/search/"

    html_response = client.get("/search/index.html")
    assert html_response.status_code == 200
    assert "Search" in html_response.text

    json_response = client.get("/search/index.json")
    assert json_response.status_code == 200
    assert json_response.json() == {"maclist": [], "switches": []}
