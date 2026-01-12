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
