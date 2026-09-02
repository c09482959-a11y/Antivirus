"""Immutable scanner configuration contracts.

This public contract module re-exports bounded scanner-owned configuration
contracts from domain modules while preserving the canonical import surface used
by scanner config loaders and validation code.
"""
from __future__ import annotations

from Virus_Scan.scanners.config.archive_limits_contracts import ArchivePolicySnapshot, ScannerLimitsPolicySnapshot
from Virus_Scan.scanners.config.binary_contracts import BinaryPolicySnapshot
from Virus_Scan.scanners.config.core_contracts import (
    PayloadPolicySnapshot,
    PicklePolicySnapshot,
    RawChunkPolicySnapshot,
    TextPolicySnapshot,
)
from Virus_Scan.scanners.config.error_contracts import ScannerConfigError, ScannerConfigFailure
from Virus_Scan.scanners.config.filetype_engine_contracts import FiletypePolicySnapshot, EnginePolicySnapshot


__all__ = (
    "ArchivePolicySnapshot",
    "BinaryPolicySnapshot",
    "EnginePolicySnapshot",
    "FiletypePolicySnapshot",
    "PayloadPolicySnapshot",
    "PicklePolicySnapshot",
    "RawChunkPolicySnapshot",
    "ScannerConfigError",
    "ScannerConfigFailure",
    "ScannerLimitsPolicySnapshot",
    "TextPolicySnapshot",
)
