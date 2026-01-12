from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Mapping


class SnmpError(RuntimeError):
    pass


@dataclass
class SnmpConfig:
    hostname: str
    version: str
    community: str | None
    timeout: int
    retries: int


class SnmpSession:
    def __init__(self, config: SnmpConfig) -> None:
        self.config = config

    def get_table(self, oid: str) -> Mapping[str, str]:
        try:
            from pysnmp.hlapi import (  # type: ignore[import-not-found]
                CommunityData,
                ContextData,
                ObjectIdentity,
                ObjectType,
                SnmpEngine,
                UdpTransportTarget,
                nextCmd,
            )
        except ModuleNotFoundError as exc:
            raise SnmpError("pysnmp is required for SNMP operations") from exc

        if self.config.version != "2c":
            raise SnmpError("Only SNMP v2c is currently supported")
        if not self.config.community:
            raise SnmpError("SNMP community not configured")

        results: dict[str, str] = {}
        for (error_indication, error_status, error_index, var_binds) in nextCmd(
            SnmpEngine(),
            CommunityData(self.config.community),
            UdpTransportTarget(
                (self.config.hostname, 161),
                timeout=self.config.timeout,
                retries=self.config.retries,
            ),
            ContextData(),
            ObjectType(ObjectIdentity(oid)),
            lexicographicMode=False,
        ):
            if error_indication:
                raise SnmpError(str(error_indication))
            if error_status:
                raise SnmpError(
                    f"SNMP error {error_status.prettyPrint()} at {error_index}"
                )
            for name, val in var_binds:
                results[str(name)] = str(val)
        return results

    def get_bulk(self, oids: Iterable[str]) -> Mapping[str, str]:
        data: dict[str, str] = {}
        for oid in oids:
            data.update(self.get_table(oid))
        return data
