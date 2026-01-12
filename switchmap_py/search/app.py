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

import http.server
import socketserver
from functools import partial
from pathlib import Path


class SearchServer:
    def __init__(self, output_dir: Path, host: str, port: int) -> None:
        self.output_dir = output_dir
        self.host = host
        self.port = port

    def serve(self) -> None:
        handler = partial(
            http.server.SimpleHTTPRequestHandler, directory=str(self.output_dir)
        )
        with socketserver.TCPServer((self.host, self.port), handler) as httpd:
            print(f"Serving search UI at http://{self.host}:{self.port}/search/")
            httpd.serve_forever()
