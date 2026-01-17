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

"""ARP CSV importer module.

This module provides functionality to parse and validate ARP data from CSV files.
It handles comment lines, blank lines, and validates MAC addresses and IP addresses.

Contract:
- CSV rows must contain at least 2 columns: MAC address and IP address
- Optional third column for hostname
- Comment lines starting with '#' are ignored
- Blank lines are ignored
- Invalid rows are skipped with logging warnings
- MAC addresses must match pattern: XX:XX:XX:XX:XX:XX or XX-XX-XX-XX-XX-XX
- IP addresses must be valid IPv4 or IPv6 addresses
"""

from __future__ import annotations

import csv
import ipaddress
import logging
from pathlib import Path
import re
from typing import Iterator, TextIO

from switchmap_py.model.mac import MacEntry

_MAC_ADDRESS_PATTERN = re.compile(r"^(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}$")


def is_valid_mac(address: str) -> bool:
    """Check if a MAC address is valid.
    
    Args:
        address: MAC address string to validate
        
    Returns:
        True if the address matches the expected MAC address format, False otherwise
    """
    return bool(_MAC_ADDRESS_PATTERN.fullmatch(address))


def is_valid_ip(address: str) -> bool:
    """Check if an IP address is valid.
    
    Args:
        address: IP address string to validate
        
    Returns:
        True if the address is a valid IPv4 or IPv6 address, False otherwise
    """
    try:
        ipaddress.ip_address(address)
    except ValueError:
        return False
    return True


def parse_arp_csv(file_handle: TextIO) -> Iterator[MacEntry]:
    """Parse ARP data from a CSV file handle.
    
    Yields MacEntry objects for each valid row in the CSV. Invalid rows are
    skipped with warning logs. The CSV format is:
    - Column 1: MAC address (required)
    - Column 2: IP address (required)
    - Column 3: hostname (optional)
    
    Comment lines (starting with '#') and blank lines are ignored.
    
    Args:
        file_handle: Open text file handle for reading CSV data
        
    Yields:
        MacEntry objects for each valid CSV row
    """
    logger = logging.getLogger(__name__)
    reader = csv.reader(file_handle)
    
    for row_number, row in enumerate(reader, start=1):
        # Skip blank lines
        if not row:
            continue
            
        # Skip comment lines
        if row[0].strip().startswith("#"):
            continue
            
        # Trim whitespace from all columns
        trimmed = [part.strip() for part in row]
        
        # Validate required columns exist and are not empty
        if len(trimmed) < 2 or not trimmed[0] or not trimmed[1]:
            logger.warning(
                "Skipping CSV row %s: missing MAC/IP columns: %s",
                row_number,
                row,
            )
            continue
            
        mac, ip = trimmed[0], trimmed[1]
        
        # Validate MAC address format
        if not is_valid_mac(mac):
            logger.warning(
                "Skipping CSV row %s: invalid MAC address: %s",
                row_number,
                mac,
            )
            continue
            
        # Validate IP address format
        if not is_valid_ip(ip):
            logger.warning(
                "Skipping CSV row %s: invalid IP address: %s",
                row_number,
                ip,
            )
            continue
            
        # Extract optional hostname
        hostname = trimmed[2] if len(trimmed) > 2 and trimmed[2] else None
        
        yield MacEntry(mac=mac, ip=ip, hostname=hostname, switch=None, port=None)


def load_arp_csv(csv_path: Path) -> list[MacEntry]:
    """Load ARP entries from a CSV file.
    
    Opens the CSV file and parses all valid entries into a list of MacEntry objects.
    
    Args:
        csv_path: Path to the CSV file to load
        
    Returns:
        List of MacEntry objects parsed from the CSV file
        
    Raises:
        FileNotFoundError: If the CSV file does not exist
        PermissionError: If the CSV file cannot be read
    """
    with csv_path.open(newline="") as handle:
        return list(parse_arp_csv(handle))
