"""Canonical scanner configuration validation API.

Implementation lives in bounded validation modules so each policy owner remains small
and inspectable while callers keep one public validation import surface.
"""
from __future__ import annotations

from Virus_Scan.scanners.config.validation_archive import validate_archive_policy
from Virus_Scan.scanners.config.validation_binary import validate_binary_policy
from Virus_Scan.scanners.config.validation_limits import validate_scanner_limits_policy
from Virus_Scan.scanners.config.validation_policy_core import (
    validate_engine_policy,
    validate_filetype_policy,
    validate_payload_policy,
    validate_pickle_policy,
    validate_raw_chunk_policy,
    validate_text_policy,
)

__all__ = (
    "validate_archive_policy",
    "validate_binary_policy",
    "validate_engine_policy",
    "validate_filetype_policy",
    "validate_payload_policy",
    "validate_pickle_policy",
    "validate_raw_chunk_policy",
    "validate_scanner_limits_policy",
    "validate_text_policy",
)
