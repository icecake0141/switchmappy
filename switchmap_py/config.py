# Copyright 2025 Switchmapy
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

from pathlib import Path
from typing import Literal, Optional

import yaml
from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class SwitchConfig(BaseModel):
    name: str
    management_ip: str
    vendor: str = "generic"
    snmp_version: Literal["2c"] = "2c"
    community: Optional[str] = None
    trunk_ports: list[str] = Field(default_factory=list)


class RouterConfig(BaseModel):
    name: str
    management_ip: str
    snmp_version: Literal["2c"] = "2c"
    community: Optional[str] = None


class SiteConfig(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="SWITCHMAP_")

    destination_directory: Path = Path("output")
    idlesince_directory: Path = Path("idlesince")
    maclist_file: Path = Path("maclist.json")
    unused_after_days: int = 30
    switches: list[SwitchConfig] = Field(default_factory=list)
    routers: list[RouterConfig] = Field(default_factory=list)
    snmp_timeout: int = 2
    snmp_retries: int = 1

    @classmethod
    def load(cls, path: Path) -> "SiteConfig":
        raw = yaml.safe_load(path.read_text())
        return cls(**raw)


def default_config_path() -> Path:
    return Path("site.yml")
