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
    snmp_version: Literal["2c", "3"] = "2c"
    community: Optional[str] = None
    username: Optional[str] = None
    auth_key: Optional[str] = None
    priv_key: Optional[str] = None
    trunk_ports: list[str] = Field(default_factory=list)


class RouterConfig(BaseModel):
    name: str
    management_ip: str
    snmp_version: Literal["2c", "3"] = "2c"
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
