# Copyright 2025 Switchmapy Authors
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

import logging
from pathlib import Path

logger = logging.getLogger(__name__)


class SearchServer:
    def __init__(self, output_dir: Path, host: str, port: int) -> None:
        self.output_dir = output_dir
        self.host = host
        self.port = port

    def build_app(self):
        try:
            from fastapi import FastAPI  # type: ignore[import-not-found]
            from fastapi.responses import RedirectResponse  # type: ignore[import-not-found]
            from fastapi.staticfiles import StaticFiles  # type: ignore[import-not-found]
        except ModuleNotFoundError as exc:
            raise RuntimeError(
                "Search server requires optional dependencies. Install with: pip install -e .[search]"
            ) from exc

        app = FastAPI(title="switchmappy-search", docs_url=None, redoc_url=None)

        @app.get("/", include_in_schema=False)
        def redirect_to_search() -> RedirectResponse:
            return RedirectResponse(url="/search/")

        app.mount(
            "/",
            StaticFiles(directory=str(self.output_dir), html=True),
            name="switchmap-static-site",
        )
        return app

    def serve(self) -> None:
        try:
            import uvicorn  # type: ignore[import-not-found]
        except ModuleNotFoundError as exc:
            raise RuntimeError(
                "Search server requires optional dependencies. Install with: pip install -e .[search]"
            ) from exc
        app = self.build_app()
        logger.info("Serving search UI at http://%s:%s/search/", self.host, self.port)
        uvicorn.run(app, host=self.host, port=self.port)
