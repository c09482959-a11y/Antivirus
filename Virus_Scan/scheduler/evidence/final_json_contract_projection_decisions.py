"""Replayable scheduler contract final JSON projection decisions."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping

from Virus_Scan.scheduler.evidence.final_json_exact_fields import exact_flag, exact_has_content, exact_mapping_value
from Virus_Scan.scheduler.evidence.final_json_contract_support import mapping_from_scheduler_value

_MISSING = object()


@dataclass(frozen=True, slots=True)
class ScanIntegrityFailureDecision:
    """Decision for whether worker scan-integrity data proves scheduler failure."""

    failed: bool
    reason: str
    matched_keys: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class WorkerStatusFailureDecision:
    """Decision for whether worker status data proves scheduler failure."""

    failed: bool
    reason: str
    scan_integrity_present: bool
    matched_keys: tuple[str, ...]


def scan_integrity_failure_decision(scan_integrity: Mapping[str, object]) -> ScanIntegrityFailureDecision:
    if not exact_has_content(scan_integrity):
        return ScanIntegrityFailureDecision(
            failed=False,
            reason="scan_integrity_empty",
            matched_keys=(),
        )
    failure_keys = (
        "worker_result_schema_invalid",
        "worker_output_publication_failed",
        "queue_failure",
        "timeout_failure",
        "retry_failure",
        "retry_exhaustion_result_failed",
        "scheduler_failure",
    )
    matched = tuple(key for key in failure_keys if exact_flag(scan_integrity, key))
    return ScanIntegrityFailureDecision(
        failed=bool(matched),
        reason="scan_integrity_failure_keys_present" if matched else "scan_integrity_without_failure_keys",
        matched_keys=matched,
    )


def worker_status_failure_decision(status: Mapping[str, object]) -> WorkerStatusFailureDecision:
    if exact_mapping_value(status, "success") is False or exact_flag(status, "worker_failure", "worker_dead"):
        return WorkerStatusFailureDecision(
            failed=True,
            reason="worker_status_explicit_failure",
            scan_integrity_present=False,
            matched_keys=(),
        )
    raw_result = exact_mapping_value(status, "result", default=_MISSING)
    if raw_result is _MISSING:
        return WorkerStatusFailureDecision(
            failed=False,
            reason="worker_result_missing",
            scan_integrity_present=False,
            matched_keys=(),
        )
    result = mapping_from_scheduler_value(raw_result)
    raw_scan_integrity = exact_mapping_value(result, "scan_integrity", default=_MISSING)
    if raw_scan_integrity is _MISSING:
        return WorkerStatusFailureDecision(
            failed=False,
            reason="scan_integrity_missing",
            scan_integrity_present=False,
            matched_keys=(),
        )
    scan_integrity = mapping_from_scheduler_value(raw_scan_integrity)
    integrity_decision = scan_integrity_failure_decision(scan_integrity)
    return WorkerStatusFailureDecision(
        failed=integrity_decision.failed,
        reason=integrity_decision.reason,
        scan_integrity_present=True,
        matched_keys=integrity_decision.matched_keys,
    )


__all__ = (
    "ScanIntegrityFailureDecision",
    "WorkerStatusFailureDecision",
    "scan_integrity_failure_decision",
    "worker_status_failure_decision",
)
