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

import pytest

from switchmap_py.snmp.session import SnmpConfig, SnmpError, SnmpSession


def _install_fake_hlapi(monkeypatch):
    record: dict[str, object] = {}
    hlapi = ModuleType("pysnmp.hlapi")

    class CommunityData:
        def __init__(self, community, mpModel=1):
            self.community = community
            self.mpModel = mpModel
            record["community"] = (community, mpModel)

    class UsmUserData:
        def __init__(self, userName, authKey=None, privKey=None, authProtocol=None, privProtocol=None):
            self.userName = userName
            self.authKey = authKey
            self.privKey = privKey
            self.authProtocol = authProtocol
            self.privProtocol = privProtocol
            record["usm"] = {
                "userName": userName,
                "authKey": authKey,
                "privKey": privKey,
                "authProtocol": authProtocol,
                "privProtocol": privProtocol,
            }

    class ContextData:
        pass

    class ObjectIdentity:
        def __init__(self, oid):
            self.oid = oid

        def __str__(self):
            return self.oid

    class ObjectType:
        def __init__(self, identity):
            self.identity = identity

    class SnmpEngine:
        pass

    class UdpTransportTarget:
        def __init__(self, target, timeout, retries):
            self.target = target
            self.timeout = timeout
            self.retries = retries

    def nextCmd(*_args, **_kwargs):
        yield (None, None, 0, [("1.3.6.1.2.1.1.1.0", "ok")])

    hlapi.CommunityData = CommunityData
    hlapi.UsmUserData = UsmUserData
    hlapi.ContextData = ContextData
    hlapi.ObjectIdentity = ObjectIdentity
    hlapi.ObjectType = ObjectType
    hlapi.SnmpEngine = SnmpEngine
    hlapi.UdpTransportTarget = UdpTransportTarget
    hlapi.nextCmd = nextCmd
    hlapi.usmHMACMD5AuthProtocol = "AUTH_MD5"
    hlapi.usmHMACSHAAuthProtocol = "AUTH_SHA"
    hlapi.usmHMAC128SHA224AuthProtocol = "AUTH_SHA224"
    hlapi.usmHMAC192SHA256AuthProtocol = "AUTH_SHA256"
    hlapi.usmHMAC256SHA384AuthProtocol = "AUTH_SHA384"
    hlapi.usmHMAC384SHA512AuthProtocol = "AUTH_SHA512"
    hlapi.usmDESPrivProtocol = "PRIV_DES"
    hlapi.usm3DESEDEPrivProtocol = "PRIV_3DES"
    hlapi.usmAesCfb128Protocol = "PRIV_AES128"
    hlapi.usmAesCfb192Protocol = "PRIV_AES192"
    hlapi.usmAesCfb256Protocol = "PRIV_AES256"

    pysnmp_pkg = ModuleType("pysnmp")
    pysnmp_pkg.hlapi = hlapi
    monkeypatch.setitem(sys.modules, "pysnmp", pysnmp_pkg)
    monkeypatch.setitem(sys.modules, "pysnmp.hlapi", hlapi)
    return record


def test_snmp_session_uses_v1_community_model(monkeypatch):
    record = _install_fake_hlapi(monkeypatch)
    session = SnmpSession(
        SnmpConfig(
            hostname="192.0.2.1",
            version="1",
            community="public",
            timeout=2,
            retries=1,
        )
    )
    result = session.get_table("1.3.6.1.2.1.1")
    assert result["1.3.6.1.2.1.1.1.0"] == "ok"
    assert record["community"] == ("public", 0)


def test_snmp_session_uses_v2c_community_model(monkeypatch):
    record = _install_fake_hlapi(monkeypatch)
    session = SnmpSession(
        SnmpConfig(
            hostname="192.0.2.1",
            version="2c",
            community="public",
            timeout=2,
            retries=1,
        )
    )
    session.get_table("1.3.6.1.2.1.1")
    assert record["community"] == ("public", 1)


def test_snmp_session_uses_v3_authpriv(monkeypatch):
    record = _install_fake_hlapi(monkeypatch)
    session = SnmpSession(
        SnmpConfig(
            hostname="192.0.2.1",
            version="3",
            community=None,
            username="snmpv3-user",
            security_level="authPriv",
            auth_protocol="SHA256",
            auth_password="auth-pass",
            priv_protocol="AES256",
            priv_password="priv-pass",
            timeout=2,
            retries=1,
        )
    )
    session.get_table("1.3.6.1.2.1.1")
    assert record["usm"]["userName"] == "snmpv3-user"
    assert record["usm"]["authKey"] == "auth-pass"
    assert record["usm"]["privKey"] == "priv-pass"
    assert record["usm"]["authProtocol"] == "AUTH_SHA256"
    assert record["usm"]["privProtocol"] == "PRIV_AES256"


def test_snmp_session_rejects_unknown_version(monkeypatch):
    _install_fake_hlapi(monkeypatch)
    session = SnmpSession(
        SnmpConfig(
            hostname="192.0.2.1",
            version="2x",
            community="public",
            timeout=2,
            retries=1,
        )
    )
    with pytest.raises(SnmpError, match="Unsupported SNMP version"):
        session.get_table("1.3.6.1.2.1.1")
