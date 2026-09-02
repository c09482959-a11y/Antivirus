"""Binary strict-fast failure evidence helpers."""

from __future__ import annotations



def _mark_strict_fast_failure(metadata: dict[str, object], stage: str) -> dict[str, object]:
    metadata["binary_strict_fast_failure"] = stage
    metadata["scanner_failure"] = True
    metadata["scanner_degraded"] = True
    metadata["scan_incomplete"] = True
    metadata["scanner_failure_evidence_recorded"] = True
    metadata["scanner_failure_evidence"] = "binary:strict_fast_file_read"
    metadata["binary_final_json_must_record"] = True
    return metadata


def append_strict_fast_failure_evidence(
    metadata: dict[str, object], stage: str, exc: BaseException
) -> dict[str, object]:
    """Attach immutable binary strict-fast failure evidence to metadata."""
    _mark_strict_fast_failure(metadata, stage)
    metadata["binary_strict_fast_exception_type"] = type(exc).__name__
    return metadata


def append_strict_fast_rejection_evidence(
    metadata: dict[str, object], stage: str, reason: str
) -> dict[str, object]:
    """Attach deterministic strict-fast rejection evidence without hooks."""
    _mark_strict_fast_failure(metadata, stage)
    metadata["binary_strict_fast_rejection_reason"] = reason
    return metadata


__all__ = ("append_strict_fast_failure_evidence", "append_strict_fast_rejection_evidence")
