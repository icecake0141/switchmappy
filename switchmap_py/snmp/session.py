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
    username: str | None = None
    security_level: str = "noAuthNoPriv"
    auth_protocol: str | None = None
    auth_password: str | None = None
    priv_protocol: str | None = None
    priv_password: str | None = None


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
                UsmUserData,
                nextCmd,
                usm3DESEDEPrivProtocol,
                usmAesCfb128Protocol,
                usmAesCfb192Protocol,
                usmAesCfb256Protocol,
                usmDESPrivProtocol,
                usmHMAC128SHA224AuthProtocol,
                usmHMAC192SHA256AuthProtocol,
                usmHMAC256SHA384AuthProtocol,
                usmHMAC384SHA512AuthProtocol,
                usmHMACMD5AuthProtocol,
                usmHMACSHAAuthProtocol,
            )
        except ModuleNotFoundError as exc:
            raise SnmpError("pysnmp is required for SNMP operations") from exc

        auth_protocols = {
            "MD5": usmHMACMD5AuthProtocol,
            "SHA": usmHMACSHAAuthProtocol,
            "SHA224": usmHMAC128SHA224AuthProtocol,
            "SHA256": usmHMAC192SHA256AuthProtocol,
            "SHA384": usmHMAC256SHA384AuthProtocol,
            "SHA512": usmHMAC384SHA512AuthProtocol,
        }
        priv_protocols = {
            "DES": usmDESPrivProtocol,
            "3DES": usm3DESEDEPrivProtocol,
            "AES": usmAesCfb128Protocol,
            "AES128": usmAesCfb128Protocol,
            "AES192": usmAesCfb192Protocol,
            "AES256": usmAesCfb256Protocol,
        }

        auth_data: object
        version = self.config.version
        if version in {"1", "2c"}:
            if not self.config.community:
                raise SnmpError("SNMP community not configured")
            auth_data = CommunityData(
                self.config.community,
                mpModel=0 if version == "1" else 1,
            )
        elif version == "3":
            if not self.config.username:
                raise SnmpError("SNMPv3 username not configured")
            level = self.config.security_level
            if level == "noAuthNoPriv":
                auth_data = UsmUserData(self.config.username)
            elif level == "authNoPriv":
                if not self.config.auth_password:
                    raise SnmpError("SNMPv3 auth_password not configured")
                auth_name = self.config.auth_protocol or "SHA"
                auth_data = UsmUserData(
                    self.config.username,
                    authKey=self.config.auth_password,
                    authProtocol=auth_protocols.get(auth_name, usmHMACSHAAuthProtocol),
                )
            elif level == "authPriv":
                if not self.config.auth_password:
                    raise SnmpError("SNMPv3 auth_password not configured")
                if not self.config.priv_password:
                    raise SnmpError("SNMPv3 priv_password not configured")
                auth_name = self.config.auth_protocol or "SHA"
                priv_name = self.config.priv_protocol or "AES"
                auth_data = UsmUserData(
                    self.config.username,
                    authKey=self.config.auth_password,
                    privKey=self.config.priv_password,
                    authProtocol=auth_protocols.get(auth_name, usmHMACSHAAuthProtocol),
                    privProtocol=priv_protocols.get(priv_name, usmAesCfb128Protocol),
                )
            else:
                raise SnmpError(f"Unsupported SNMPv3 security level: {level}")
        else:
            raise SnmpError(f"Unsupported SNMP version: {version}")

        results: dict[str, str] = {}
        for error_indication, error_status, error_index, var_binds in nextCmd(
            SnmpEngine(),
            auth_data,
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
                raise SnmpError(f"SNMP error {error_status.prettyPrint()} at {error_index}")
            for name, val in var_binds:
                results[str(name)] = str(val)
        return results

    def get_bulk(self, oids: Iterable[str]) -> Mapping[str, str]:
        data: dict[str, str] = {}
        for oid in oids:
            data.update(self.get_table(oid))
        return data
