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

import builtins
import sys
from pathlib import Path
from types import ModuleType

import pytest

from switchmap_py.search.app import SearchServer


def test_search_server_requires_optional_dependencies(monkeypatch):
    real_import = builtins.__import__

    def fake_import(name, globals=None, locals=None, fromlist=(), level=0):
        if name == "fastapi" or name.startswith("fastapi.") or name == "uvicorn":
            raise ModuleNotFoundError(name)
        return real_import(name, globals, locals, fromlist, level)

    monkeypatch.setattr(builtins, "__import__", fake_import)

    server = SearchServer(output_dir=Path("."), host="127.0.0.1", port=8000)
    with pytest.raises(RuntimeError, match="Install with: pip install -e .\\[search\\]"):
        server.serve()


def test_search_server_runs_uvicorn_with_configured_host_port(monkeypatch, tmp_path):
    captured: dict[str, object] = {}

    fastapi_module = ModuleType("fastapi")
    responses_module = ModuleType("fastapi.responses")
    staticfiles_module = ModuleType("fastapi.staticfiles")
    uvicorn_module = ModuleType("uvicorn")

    class FakeFastAPI:
        def __init__(self, **_kwargs):
            self.routes: list[tuple[str, object]] = []
            self.mounts: list[tuple[str, object, str | None]] = []

        def get(self, path: str, include_in_schema: bool = True):
            def decorator(func):
                self.routes.append((path, func))
                return func

            return decorator

        def mount(self, path: str, app: object, name: str | None = None):
            self.mounts.append((path, app, name))

    class FakeRedirectResponse:
        def __init__(self, url: str) -> None:
            self.url = url

    class FakeStaticFiles:
        def __init__(self, directory: str, html: bool) -> None:
            self.directory = directory
            self.html = html

    def fake_run(app, host: str, port: int):
        captured["app"] = app
        captured["host"] = host
        captured["port"] = port

    fastapi_module.FastAPI = FakeFastAPI
    responses_module.RedirectResponse = FakeRedirectResponse
    staticfiles_module.StaticFiles = FakeStaticFiles
    uvicorn_module.run = fake_run

    monkeypatch.setitem(sys.modules, "fastapi", fastapi_module)
    monkeypatch.setitem(sys.modules, "fastapi.responses", responses_module)
    monkeypatch.setitem(sys.modules, "fastapi.staticfiles", staticfiles_module)
    monkeypatch.setitem(sys.modules, "uvicorn", uvicorn_module)

    server = SearchServer(output_dir=tmp_path, host="0.0.0.0", port=18000)
    server.serve()

    assert captured["host"] == "0.0.0.0"
    assert captured["port"] == 18000
    app = captured["app"]
    assert isinstance(app, FakeFastAPI)
    assert len(app.mounts) == 1
    mount_path, mounted_app, mount_name = app.mounts[0]
    assert mount_path == "/"
    assert isinstance(mounted_app, FakeStaticFiles)
    assert mounted_app.directory == str(tmp_path)
    assert mounted_app.html is True
    assert mount_name == "switchmap-static-site"
