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
