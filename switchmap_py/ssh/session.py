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

import subprocess
from dataclasses import dataclass


class SshError(RuntimeError):
    pass


@dataclass
class SshConfig:
    hostname: str
    port: int
    username: str
    password: str | None
    private_key: str | None
    connect_timeout: int


class SshSession:
    def __init__(self, config: SshConfig) -> None:
        self.config = config

    def run(self, command: str, timeout: int) -> str:
        argv = [
            "ssh",
            "-o",
            "BatchMode=yes",
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            f"ConnectTimeout={self.config.connect_timeout}",
            "-p",
            str(self.config.port),
        ]
        if self.config.private_key:
            argv.extend(["-i", self.config.private_key])
        argv.append(f"{self.config.username}@{self.config.hostname}")
        argv.append(command)
        try:
            result = subprocess.run(
                argv,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise SshError(str(exc)) from exc
        if result.returncode != 0:
            error = result.stderr.strip() or result.stdout.strip() or "ssh command failed"
            raise SshError(error)
        return result.stdout
