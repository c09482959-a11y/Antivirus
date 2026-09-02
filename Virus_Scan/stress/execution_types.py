"""Immutable contracts for executable stress-run evidence."""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class ProfileFileSnapshot:
    relative_path: str
    size_bytes: int
    sha256: str
    json_valid: bool
    semantic_digest: str | None


@dataclass(frozen=True, slots=True)
class ProfileSnapshot:
    root: str
    files: tuple[ProfileFileSnapshot, ...]
    violations: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class StressRunVerification:
    passed: bool
    intended_count: int
    manifest_count: int
    materialized_count: int
    final_count: int
    checkpoint_count: int
    scanlog_count: int
    oracle_pass_count: int
    missing_count: int
    duplicate_count: int
    mismatch_count: int
    profile_violation_count: int
    live_partial_count: int
    scanner_exit_code: int
    errors: tuple[str, ...]
    manifest_sha256: str
    final_json_sha256: str
    checkpoint_sha256: str
    scanlog_ledger_sha256: str
    profile_snapshot_sha256: str


__all__ = (
    "ProfileFileSnapshot",
    "ProfileSnapshot",
    "StressRunVerification",
)
