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

import pytest

pytest.importorskip("yaml")

from switchmap_py.config import SiteConfig, default_config_path


def test_default_config_path():
    assert default_config_path().name == "site.yml"


def test_site_config_load(tmp_path):
    config_path = tmp_path / "site.yml"
    config_path.write_text(
        """
        destination_directory: output
        idlesince_directory: idlesince
        maclist_file: maclist.json
        unused_after_days: 15
        snmp_timeout: 3
        snmp_retries: 2
        switches:
          - name: core-1
            management_ip: 10.0.0.1
            community: public
        routers:
          - name: edge-1
            management_ip: 10.0.0.254
            community: public
        """
    )

    config = SiteConfig.load(config_path)

    assert config.destination_directory.name == "output"
    assert config.idlesince_directory.name == "idlesince"
    assert config.maclist_file.name == "maclist.json"
    assert config.unused_after_days == 15
    assert config.snmp_timeout == 3
    assert config.snmp_retries == 2
    assert len(config.switches) == 1
    assert config.switches[0].name == "core-1"
    assert config.switches[0].management_ip == "10.0.0.1"
    assert config.switches[0].community == "public"
    assert len(config.routers) == 1
    assert config.routers[0].name == "edge-1"
    assert config.routers[0].management_ip == "10.0.0.254"
    assert config.routers[0].community == "public"


def test_site_config_rejects_missing_community_for_v2c_switch(tmp_path):
    config_path = tmp_path / "site.yml"
    config_path.write_text(
        """
        switches:
          - name: core-1
            management_ip: 10.0.0.1
        """
    )

    with pytest.raises(ValueError, match="requires 'community'"):
        SiteConfig.load(config_path)


def test_site_config_rejects_missing_community_for_v2c_router(tmp_path):
    config_path = tmp_path / "site.yml"
    config_path.write_text(
        """
        routers:
          - name: edge-1
            management_ip: 10.0.0.254
        """
    )

    with pytest.raises(ValueError, match="requires 'community'"):
        SiteConfig.load(config_path)


def test_site_config_rejects_missing_community_for_v1_switch(tmp_path):
    config_path = tmp_path / "site.yml"
    config_path.write_text(
        """
        switches:
          - name: core-1
            management_ip: 10.0.0.1
            snmp_version: 1
        """
    )

    with pytest.raises(ValueError, match="requires 'community'"):
        SiteConfig.load(config_path)


def test_site_config_accepts_snmpv3_authpriv(tmp_path):
    config_path = tmp_path / "site.yml"
    config_path.write_text(
        """
        switches:
          - name: core-v3
            management_ip: 10.0.0.10
            snmp_version: 3
            username: snmpv3-user
            security_level: authPriv
            auth_protocol: SHA256
            auth_password: auth-pass
            priv_protocol: AES256
            priv_password: priv-pass
        routers:
          - name: edge-v3
            management_ip: 10.0.0.254
            snmp_version: 3
            username: router-user
            security_level: noAuthNoPriv
        """
    )

    config = SiteConfig.load(config_path)
    assert config.switches[0].snmp_version == "3"
    assert config.switches[0].username == "snmpv3-user"
    assert config.switches[0].security_level == "authPriv"
    assert config.routers[0].snmp_version == "3"
    assert config.routers[0].security_level == "noAuthNoPriv"


def test_site_config_rejects_snmpv3_missing_username(tmp_path):
    config_path = tmp_path / "site.yml"
    config_path.write_text(
        """
        switches:
          - name: core-v3
            management_ip: 10.0.0.10
            snmp_version: 3
            security_level: noAuthNoPriv
        """
    )

    with pytest.raises(ValueError, match="requires 'username'"):
        SiteConfig.load(config_path)


def test_site_config_rejects_snmpv3_authpriv_missing_priv_password(tmp_path):
    config_path = tmp_path / "site.yml"
    config_path.write_text(
        """
        routers:
          - name: edge-v3
            management_ip: 10.0.0.254
            snmp_version: 3
            username: edge-user
            security_level: authPriv
            auth_password: auth-pass
        """
    )

    with pytest.raises(ValueError, match="requires 'priv_password'"):
        SiteConfig.load(config_path)


def test_site_config_accepts_ssh_collection_method(tmp_path):
    config_path = tmp_path / "site.yml"
    config_path.write_text(
        """
        switches:
          - name: access-ssh
            management_ip: 10.0.0.20
            collection_method: ssh
            ssh_username: ops
            ssh_password: secret
            trunk_ports: ["Gi1/0/48"]
        """
    )

    config = SiteConfig.load(config_path)
    assert config.switches[0].collection_method == "ssh"
    assert config.switches[0].ssh_username == "ops"
    assert config.switches[0].ssh_port == 22


def test_site_config_rejects_ssh_without_username(tmp_path):
    config_path = tmp_path / "site.yml"
    config_path.write_text(
        """
        switches:
          - name: access-ssh
            management_ip: 10.0.0.20
            collection_method: ssh
            ssh_password: secret
        """
    )

    with pytest.raises(ValueError, match="requires 'ssh_username'"):
        SiteConfig.load(config_path)


def test_site_config_rejects_ssh_without_credentials(tmp_path):
    config_path = tmp_path / "site.yml"
    config_path.write_text(
        """
        switches:
          - name: access-ssh
            management_ip: 10.0.0.20
            collection_method: ssh
            ssh_username: ops
        """
    )

    with pytest.raises(ValueError, match="requires either 'ssh_password' or 'ssh_private_key'"):
        SiteConfig.load(config_path)


def test_site_config_rejects_duplicate_switch_names(tmp_path):
    config_path = tmp_path / "site.yml"
    config_path.write_text(
        """
        switches:
          - name: core-1
            management_ip: 10.0.0.1
            community: public
          - name: core-1
            management_ip: 10.0.0.2
            community: public
        """
    )

    with pytest.raises(ValueError, match="duplicate switch names"):
        SiteConfig.load(config_path)


def test_site_config_rejects_duplicate_router_names(tmp_path):
    config_path = tmp_path / "site.yml"
    config_path.write_text(
        """
        routers:
          - name: edge-1
            management_ip: 10.0.0.254
            community: public
          - name: edge-1
            management_ip: 10.0.0.253
            community: public
        """
    )

    with pytest.raises(ValueError, match="duplicate router names"):
        SiteConfig.load(config_path)
