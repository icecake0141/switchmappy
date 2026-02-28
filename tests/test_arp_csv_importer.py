# Copyright 2024 switchmappy
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

"""Unit tests for the ARP CSV importer module."""

import io
import logging

import pytest

from switchmap_py.importers.arp_csv import (
    is_valid_ip,
    is_valid_mac,
    load_arp_csv,
    parse_arp_csv,
)


class TestMacValidation:
    """Tests for MAC address validation."""

    def test_valid_mac_colon_separator(self):
        assert is_valid_mac("aa:bb:cc:dd:ee:ff") is True
        assert is_valid_mac("AA:BB:CC:DD:EE:FF") is True
        assert is_valid_mac("00:11:22:33:44:55") is True

    def test_valid_mac_hyphen_separator(self):
        assert is_valid_mac("aa-bb-cc-dd-ee-ff") is True
        assert is_valid_mac("AA-BB-CC-DD-EE-FF") is True
        assert is_valid_mac("00-11-22-33-44-55") is True

    def test_invalid_mac_wrong_format(self):
        assert is_valid_mac("not-a-mac") is False
        assert is_valid_mac("aa:bb:cc:dd:ee") is False  # too short
        assert is_valid_mac("aa:bb:cc:dd:ee:ff:gg") is False  # too long
        assert is_valid_mac("aabbccddeeff") is False  # no separators
        assert is_valid_mac("aa.bb.cc.dd.ee.ff") is False  # wrong separator
        assert is_valid_mac("") is False
        assert is_valid_mac("zz:zz:zz:zz:zz:zz") is False  # invalid hex

    def test_mac_allows_consistent_separators_per_pair(self):
        # The regex allows each pair to have its own separator choice
        # This is acceptable for parsing flexibility
        assert is_valid_mac("aa:bb:cc:dd:ee:ff") is True
        assert is_valid_mac("aa-bb-cc-dd-ee-ff") is True


class TestIpValidation:
    """Tests for IP address validation."""

    def test_valid_ipv4(self):
        assert is_valid_ip("192.0.2.10") is True
        assert is_valid_ip("10.0.0.1") is True
        assert is_valid_ip("255.255.255.255") is True
        assert is_valid_ip("0.0.0.0") is True

    def test_valid_ipv6(self):
        assert is_valid_ip("2001:db8::1") is True
        assert is_valid_ip("::1") is True
        assert is_valid_ip("fe80::1") is True
        assert is_valid_ip("2001:0db8:85a3:0000:0000:8a2e:0370:7334") is True

    def test_invalid_ip(self):
        assert is_valid_ip("999.999.999.999") is False
        assert is_valid_ip("192.0.2") is False  # incomplete
        assert is_valid_ip("not-an-ip") is False
        assert is_valid_ip("") is False
        assert is_valid_ip("192.0.2.1.1") is False  # too many octets


class TestParseArpCsv:
    """Tests for CSV parsing functionality."""

    def test_parse_valid_csv_with_hostname(self):
        csv_data = "aa:bb:cc:dd:ee:ff,192.0.2.10,example-host\n"
        entries = list(parse_arp_csv(io.StringIO(csv_data)))

        assert len(entries) == 1
        assert entries[0].mac == "aa:bb:cc:dd:ee:ff"
        assert entries[0].ip == "192.0.2.10"
        assert entries[0].hostname == "example-host"
        assert entries[0].switch is None
        assert entries[0].port is None

    def test_parse_valid_csv_without_hostname(self):
        csv_data = "11:22:33:44:55:66,192.0.2.20\n"
        entries = list(parse_arp_csv(io.StringIO(csv_data)))

        assert len(entries) == 1
        assert entries[0].mac == "11:22:33:44:55:66"
        assert entries[0].ip == "192.0.2.20"
        assert entries[0].hostname is None

    def test_parse_multiple_valid_entries(self):
        csv_data = (
            "aa:bb:cc:dd:ee:ff,192.0.2.10,host1\n11:22:33:44:55:66,192.0.2.20,host2\n22:33:44:55:66:77,10.0.0.1\n"
        )
        entries = list(parse_arp_csv(io.StringIO(csv_data)))

        assert len(entries) == 3
        assert entries[0].hostname == "host1"
        assert entries[1].hostname == "host2"
        assert entries[2].hostname is None

    def test_parse_skip_comment_lines(self):
        csv_data = (
            "# This is a comment\n"
            "aa:bb:cc:dd:ee:ff,192.0.2.10,host1\n"
            "# Another comment\n"
            "11:22:33:44:55:66,192.0.2.20,host2\n"
        )
        entries = list(parse_arp_csv(io.StringIO(csv_data)))

        assert len(entries) == 2
        assert entries[0].mac == "aa:bb:cc:dd:ee:ff"
        assert entries[1].mac == "11:22:33:44:55:66"

    def test_parse_skip_blank_lines(self):
        csv_data = "aa:bb:cc:dd:ee:ff,192.0.2.10,host1\n\n11:22:33:44:55:66,192.0.2.20,host2\n\n\n"
        entries = list(parse_arp_csv(io.StringIO(csv_data)))

        assert len(entries) == 2

    def test_parse_trim_whitespace(self):
        csv_data = "  aa:bb:cc:dd:ee:ff  ,  192.0.2.10  ,  host1  \n"
        entries = list(parse_arp_csv(io.StringIO(csv_data)))

        assert len(entries) == 1
        assert entries[0].mac == "aa:bb:cc:dd:ee:ff"
        assert entries[0].ip == "192.0.2.10"
        assert entries[0].hostname == "host1"

    def test_parse_skip_invalid_mac(self, caplog):
        caplog.set_level(logging.WARNING)
        csv_data = (
            "aa:bb:cc:dd:ee:ff,192.0.2.10,host1\nnot-a-mac,192.0.2.20,host2\n11:22:33:44:55:66,192.0.2.30,host3\n"
        )
        entries = list(parse_arp_csv(io.StringIO(csv_data)))

        assert len(entries) == 2
        assert entries[0].mac == "aa:bb:cc:dd:ee:ff"
        assert entries[1].mac == "11:22:33:44:55:66"
        assert any("invalid MAC address" in record.message for record in caplog.records)

    def test_parse_skip_invalid_ip(self, caplog):
        caplog.set_level(logging.WARNING)
        csv_data = (
            "aa:bb:cc:dd:ee:ff,192.0.2.10,host1\n"
            "11:22:33:44:55:66,999.999.999.999,host2\n"
            "22:33:44:55:66:77,192.0.2.30,host3\n"
        )
        entries = list(parse_arp_csv(io.StringIO(csv_data)))

        assert len(entries) == 2
        assert entries[0].ip == "192.0.2.10"
        assert entries[1].ip == "192.0.2.30"
        assert any("invalid IP address" in record.message for record in caplog.records)

    def test_parse_skip_missing_columns(self, caplog):
        caplog.set_level(logging.WARNING)
        csv_data = "aa:bb:cc:dd:ee:ff,192.0.2.10,host1\nmissing-ip-column\n11:22:33:44:55:66,192.0.2.20,host2\n"
        entries = list(parse_arp_csv(io.StringIO(csv_data)))

        assert len(entries) == 2
        assert any("missing MAC/IP columns" in record.message for record in caplog.records)

    def test_parse_skip_empty_mac(self, caplog):
        caplog.set_level(logging.WARNING)
        csv_data = "aa:bb:cc:dd:ee:ff,192.0.2.10,host1\n,192.0.2.20,host2\n11:22:33:44:55:66,192.0.2.30,host3\n"
        entries = list(parse_arp_csv(io.StringIO(csv_data)))

        assert len(entries) == 2
        assert any("missing MAC/IP columns" in record.message for record in caplog.records)

    def test_parse_skip_empty_ip(self, caplog):
        caplog.set_level(logging.WARNING)
        csv_data = "aa:bb:cc:dd:ee:ff,192.0.2.10,host1\n11:22:33:44:55:66,,host2\n22:33:44:55:66:77,192.0.2.30,host3\n"
        entries = list(parse_arp_csv(io.StringIO(csv_data)))

        assert len(entries) == 2
        assert any("missing MAC/IP columns" in record.message for record in caplog.records)

    def test_parse_empty_hostname_treated_as_none(self):
        csv_data = "aa:bb:cc:dd:ee:ff,192.0.2.10,\n"
        entries = list(parse_arp_csv(io.StringIO(csv_data)))

        assert len(entries) == 1
        assert entries[0].hostname is None

    def test_parse_whitespace_only_hostname_treated_as_none(self):
        csv_data = "aa:bb:cc:dd:ee:ff,192.0.2.10,   \n"
        entries = list(parse_arp_csv(io.StringIO(csv_data)))

        assert len(entries) == 1
        assert entries[0].hostname is None

    def test_parse_ipv6_addresses(self):
        csv_data = "aa:bb:cc:dd:ee:ff,2001:db8::1,host1\n11:22:33:44:55:66,::1,host2\n"
        entries = list(parse_arp_csv(io.StringIO(csv_data)))

        assert len(entries) == 2
        assert entries[0].ip == "2001:db8::1"
        assert entries[1].ip == "::1"

    def test_parse_hyphen_mac_addresses(self):
        csv_data = "aa-bb-cc-dd-ee-ff,192.0.2.10,host1\n"
        entries = list(parse_arp_csv(io.StringIO(csv_data)))

        assert len(entries) == 1
        assert entries[0].mac == "aa-bb-cc-dd-ee-ff"

    def test_parse_mixed_valid_invalid_rows(self, caplog):
        caplog.set_level(logging.WARNING)
        csv_data = (
            "# comment row\n"
            "aa:bb:cc:dd:ee:ff,192.0.2.10,example-host\n"
            "11:22:33:44:55:66,\n"
            "not-a-mac,192.0.2.11\n"
            "22:33:44:55:66:77,999.999.999.999\n"
            "missing-columns\n"
            "\n"
            "33:44:55:66:77:88,192.0.2.12,valid-host\n"
        )
        entries = list(parse_arp_csv(io.StringIO(csv_data)))

        # Only 2 valid entries
        assert len(entries) == 2
        assert entries[0].mac == "aa:bb:cc:dd:ee:ff"
        assert entries[1].mac == "33:44:55:66:77:88"

        # Should have warning logs for invalid rows
        warning_messages = [record.message for record in caplog.records]
        assert any("missing MAC/IP columns" in msg for msg in warning_messages)
        assert any("invalid MAC address" in msg for msg in warning_messages)
        assert any("invalid IP address" in msg for msg in warning_messages)

    def test_parse_empty_file(self):
        csv_data = ""
        entries = list(parse_arp_csv(io.StringIO(csv_data)))
        assert len(entries) == 0

    def test_parse_only_comments_and_blanks(self):
        csv_data = "# comment 1\n\n# comment 2\n\n"
        entries = list(parse_arp_csv(io.StringIO(csv_data)))
        assert len(entries) == 0


class TestLoadArpCsv:
    """Tests for loading ARP CSV from file."""

    def test_load_valid_file(self, tmp_path):
        csv_path = tmp_path / "test.csv"
        csv_path.write_text("aa:bb:cc:dd:ee:ff,192.0.2.10,host1\n11:22:33:44:55:66,192.0.2.20,host2\n")

        entries = load_arp_csv(csv_path)

        assert len(entries) == 2
        assert entries[0].mac == "aa:bb:cc:dd:ee:ff"
        assert entries[1].mac == "11:22:33:44:55:66"

    def test_load_file_not_found(self, tmp_path):
        csv_path = tmp_path / "nonexistent.csv"

        with pytest.raises(FileNotFoundError):
            load_arp_csv(csv_path)

    def test_load_with_mixed_content(self, tmp_path, caplog):
        caplog.set_level(logging.WARNING)
        csv_path = tmp_path / "test.csv"
        csv_path.write_text(
            "# comment\n"
            "aa:bb:cc:dd:ee:ff,192.0.2.10,host1\n"
            "\n"
            "invalid-mac,192.0.2.20\n"
            "11:22:33:44:55:66,192.0.2.30,host2\n"
        )

        entries = load_arp_csv(csv_path)

        assert len(entries) == 2
        assert entries[0].mac == "aa:bb:cc:dd:ee:ff"
        assert entries[1].mac == "11:22:33:44:55:66"
