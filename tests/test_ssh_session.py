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

import sys
from types import ModuleType
from typing import Any

import pytest

from switchmap_py.ssh.session import SshConfig, SshError, SshSession


class _FakeStream:
    def __init__(self, data: str, exit_status: int = 0) -> None:
        self.data = data
        self.channel = self
        self.exit_status = exit_status

    def read(self) -> bytes:
        return self.data.encode()

    def recv_exit_status(self) -> int:
        return self.exit_status


def test_password_ssh_uses_paramiko(monkeypatch):
    record: dict[str, object] = {}
    paramiko: Any = ModuleType("paramiko")

    class AutoAddPolicy:
        pass

    class SSHClient:
        def set_missing_host_key_policy(self, policy) -> None:
            record["policy"] = policy

        def connect(self, **kwargs) -> None:
            record["connect"] = kwargs

        def exec_command(self, command: str, timeout: int):
            record["command"] = command
            record["timeout"] = timeout
            return None, _FakeStream("ok"), _FakeStream("")

        def close(self) -> None:
            record["closed"] = True

    paramiko.AutoAddPolicy = AutoAddPolicy
    paramiko.SSHClient = SSHClient
    monkeypatch.setitem(sys.modules, "paramiko", paramiko)

    session = SshSession(
        SshConfig(
            hostname="192.0.2.10",
            port=22,
            username="ops",
            password="secret",
            private_key=None,
            connect_timeout=3,
        )
    )

    assert session.run("show version", timeout=5) == "ok"
    assert record["connect"] == {
        "hostname": "192.0.2.10",
        "port": 22,
        "username": "ops",
        "password": "secret",
        "look_for_keys": False,
        "allow_agent": False,
        "timeout": 3,
        "auth_timeout": 5,
        "banner_timeout": 5,
    }
    assert record["command"] == "show version"
    assert record["closed"] is True


def test_password_ssh_raises_on_nonzero_exit(monkeypatch):
    paramiko: Any = ModuleType("paramiko")

    class AutoAddPolicy:
        pass

    class SSHClient:
        def set_missing_host_key_policy(self, _policy) -> None:
            pass

        def connect(self, **_kwargs) -> None:
            pass

        def exec_command(self, _command: str, timeout: int):
            return None, _FakeStream("", exit_status=1), _FakeStream("denied")

        def close(self) -> None:
            pass

    paramiko.AutoAddPolicy = AutoAddPolicy
    paramiko.SSHClient = SSHClient
    monkeypatch.setitem(sys.modules, "paramiko", paramiko)

    session = SshSession(
        SshConfig(
            hostname="192.0.2.10",
            port=22,
            username="ops",
            password="secret",
            private_key=None,
            connect_timeout=3,
        )
    )

    with pytest.raises(SshError, match="denied"):
        session.run("show version", timeout=5)
