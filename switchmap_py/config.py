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
from typing import Literal, Optional, Union

import yaml
from pydantic import BaseModel, Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class SwitchConfig(BaseModel):
    name: str
    management_ip: str
    vendor: str = "generic"
    snmp_version: Union[str, int] = "2c"
    community: Optional[str] = None
    trunk_ports: list[str] = Field(default_factory=list)
    username: Optional[str] = None
    security_level: Literal["noAuthNoPriv", "authNoPriv", "authPriv"] = "noAuthNoPriv"
    auth_protocol: Optional[Literal["MD5", "SHA", "SHA224", "SHA256", "SHA384", "SHA512"]] = None
    auth_password: Optional[str] = None
    priv_protocol: Optional[Literal["DES", "3DES", "AES", "AES128", "AES192", "AES256"]] = None
    priv_password: Optional[str] = None

    @model_validator(mode="after")
    def validate_snmp_credentials(self) -> "SwitchConfig":
        self.snmp_version = str(self.snmp_version)
        if self.snmp_version not in {"1", "2c", "3"}:
            raise ValueError(
                f"Switch '{self.name}' has unsupported snmp_version '{self.snmp_version}'; expected one of: 1, 2c, 3"
            )
        if self.snmp_version in {"1", "2c"}:
            if not self.community:
                raise ValueError(f"Switch '{self.name}' requires 'community' when snmp_version is {self.snmp_version}")
            if self.username:
                raise ValueError(
                    f"Switch '{self.name}' must not set 'username' when snmp_version is {self.snmp_version}"
                )
            return self
        if not self.username:
            raise ValueError(f"Switch '{self.name}' requires 'username' when snmp_version is 3")
        if self.security_level == "noAuthNoPriv":
            if self.auth_password or self.priv_password:
                raise ValueError(
                    f"Switch '{self.name}' must not set auth/priv passwords when security_level is noAuthNoPriv"
                )
        elif self.security_level == "authNoPriv":
            if not self.auth_password:
                raise ValueError(f"Switch '{self.name}' requires 'auth_password' when security_level is authNoPriv")
            if self.priv_password:
                raise ValueError(f"Switch '{self.name}' must not set 'priv_password' when security_level is authNoPriv")
        elif self.security_level == "authPriv":
            if not self.auth_password:
                raise ValueError(f"Switch '{self.name}' requires 'auth_password' when security_level is authPriv")
            if not self.priv_password:
                raise ValueError(f"Switch '{self.name}' requires 'priv_password' when security_level is authPriv")
        return self


class RouterConfig(BaseModel):
    name: str
    management_ip: str
    snmp_version: Union[str, int] = "2c"
    community: Optional[str] = None
    username: Optional[str] = None
    security_level: Literal["noAuthNoPriv", "authNoPriv", "authPriv"] = "noAuthNoPriv"
    auth_protocol: Optional[Literal["MD5", "SHA", "SHA224", "SHA256", "SHA384", "SHA512"]] = None
    auth_password: Optional[str] = None
    priv_protocol: Optional[Literal["DES", "3DES", "AES", "AES128", "AES192", "AES256"]] = None
    priv_password: Optional[str] = None

    @model_validator(mode="after")
    def validate_snmp_credentials(self) -> "RouterConfig":
        self.snmp_version = str(self.snmp_version)
        if self.snmp_version not in {"1", "2c", "3"}:
            raise ValueError(
                f"Router '{self.name}' has unsupported snmp_version '{self.snmp_version}'; expected one of: 1, 2c, 3"
            )
        if self.snmp_version in {"1", "2c"}:
            if not self.community:
                raise ValueError(f"Router '{self.name}' requires 'community' when snmp_version is {self.snmp_version}")
            if self.username:
                raise ValueError(
                    f"Router '{self.name}' must not set 'username' when snmp_version is {self.snmp_version}"
                )
            return self
        if not self.username:
            raise ValueError(f"Router '{self.name}' requires 'username' when snmp_version is 3")
        if self.security_level == "noAuthNoPriv":
            if self.auth_password or self.priv_password:
                raise ValueError(
                    f"Router '{self.name}' must not set auth/priv passwords when security_level is noAuthNoPriv"
                )
        elif self.security_level == "authNoPriv":
            if not self.auth_password:
                raise ValueError(f"Router '{self.name}' requires 'auth_password' when security_level is authNoPriv")
            if self.priv_password:
                raise ValueError(f"Router '{self.name}' must not set 'priv_password' when security_level is authNoPriv")
        elif self.security_level == "authPriv":
            if not self.auth_password:
                raise ValueError(f"Router '{self.name}' requires 'auth_password' when security_level is authPriv")
            if not self.priv_password:
                raise ValueError(f"Router '{self.name}' requires 'priv_password' when security_level is authPriv")
        return self


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

    @model_validator(mode="after")
    def validate_unique_names(self) -> "SiteConfig":
        switch_names = [switch.name for switch in self.switches]
        router_names = [router.name for router in self.routers]
        duplicate_switches = sorted({name for name in switch_names if switch_names.count(name) > 1})
        duplicate_routers = sorted({name for name in router_names if router_names.count(name) > 1})
        errors: list[str] = []
        if duplicate_switches:
            errors.append(f"duplicate switch names: {', '.join(duplicate_switches)}")
        if duplicate_routers:
            errors.append(f"duplicate router names: {', '.join(duplicate_routers)}")
        if errors:
            raise ValueError("; ".join(errors))
        return self

    @classmethod
    def load(cls, path: Path) -> "SiteConfig":
        if not path.exists():
            raise FileNotFoundError(f"Config file not found: {path}")
        raw = yaml.safe_load(path.read_text())
        if raw is None:
            raw = {}
        if not isinstance(raw, dict):
            raise ValueError("Config file must contain a YAML mapping at the top level.")
        return cls(**raw)


def default_config_path() -> Path:
    return Path("site.yml")
