"""Canonical archive/RPA scanner public surface."""

from __future__ import annotations

from Virus_Scan.scanners.archives.common import extract_methods, rarity_multiplier_for_probability
from Virus_Scan.scanners.archives.scanner import scan_archive_file, scan_extracted_archive_member
from Virus_Scan.scanners.archives.rpa import scan_rpa_file

__all__ = (
    "extract_methods",
    "rarity_multiplier_for_probability",
    "scan_archive_file",
    "scan_extracted_archive_member",
    "scan_rpa_file",
)
