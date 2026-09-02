"""Canonical raw-queue degradation telemetry ownership.

This module owns attributable raw-queue infrastructure degradation records.  It
keeps failure provenance explicit while callers provide concrete persistence and
telemetry dependencies instead of relying on scheduler-root mutable state.
"""
from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Callable, Mapping

from Virus_Scan.contracts.no_hook_materialization import no_hook_mapping_items, no_hook_text, no_hook_type_name
from Virus_Scan.scheduler.internal.immutable_outputs import materialize_scheduler_mapping
from Virus_Scan.scheduler.internal.immutable_output_support import unsupported_scheduler_value_evidence



@dataclass(frozen=True, slots=True)
class RawQueueIntegrityMappingDecision:
    mapping: dict[str, object]
    reason: str
    accepted: bool

def _raw_queue_integrity_mapping_decision(integrity: Mapping[str, object] | None) -> RawQueueIntegrityMappingDecision:
    if integrity is None:
        return RawQueueIntegrityMappingDecision(mapping={}, reason="raw_queue_integrity_absent", accepted=True)
    failure = {
        "raw_queue_integrity_unavailable": True,
        "raw_queue_integrity_failure": unsupported_scheduler_value_evidence(
            integrity,
            field_name="raw_queue_integrity",
        ),
    }
    if no_hook_mapping_items(integrity) is None:
        return RawQueueIntegrityMappingDecision(mapping=failure, reason="raw_queue_integrity_unsupported", accepted=False)
    materialized = materialize_scheduler_mapping(integrity)
    if type(materialized) is dict:
        return RawQueueIntegrityMappingDecision(mapping=materialized, reason="raw_queue_integrity_materialized", accepted=True)
    return RawQueueIntegrityMappingDecision(mapping=failure, reason="raw_queue_integrity_non_materializable", accepted=False)


def _raw_queue_integrity_mapping(integrity: Mapping[str, object] | None) -> dict[str, object]:
    return _raw_queue_integrity_mapping_decision(integrity).mapping


def record_raw_queue_issue(where: object, exc: BaseException, *, report: Callable[[str, BaseException], object]) -> None:
    """Record a raw-queue issue with stable stage121 attribution."""
    marker_text, marker_reason = no_hook_text(
        where,
        missing_reason="raw_queue_stage_missing",
        unsupported_reason="raw_queue_stage_unsafe",
    )
    marker = "raw_queue_issue" if marker_reason or marker_text == "" else marker_text
    report("stage121." + marker, exc)


def record_raw_queue_degradation(
    path: object,
    exc: BaseException,
    *,
    where: object,
    integrity: Mapping[str, object] | None = None,
    set_scan_integrity: Callable[[object, Mapping[str, object]], object],
    report_issue: Callable[[object, BaseException], object],
    recoverable_exceptions: tuple[type[BaseException], ...],
) -> dict[str, object]:
    """Return and persist explicit degraded raw-queue scan integrity."""
    marker_text, marker_reason = no_hook_text(
        where,
        missing_reason="raw_queue_stage_missing",
        unsupported_reason="raw_queue_stage_unsafe",
    )
    marker = "global_raw_queue" if marker_reason or marker_text == "" else marker_text
    info = _raw_queue_integrity_mapping(integrity)
    error_text, error_reason = no_hook_text(
        exc,
        missing_reason="raw_queue_error_missing",
        unsupported_reason="raw_queue_error_unsafe",
    )
    if error_reason or error_text == "":
        error_text = "raw queue exception message unavailable without caller hooks"
    else:
        error_text = error_text[:1000]
    info.update(
        {
            "raw_queue_degraded": True,
            "had_degraded_stage": True,
            "partial_retry": True,
            "scan_incomplete": True,
            "allow_learning": False,
            "stage121_marker": marker,
            "error": error_text,
            "failure_info": {
                "stage": marker,
                "exception_type": no_hook_type_name(exc),
                "error": error_text,
                "exception_text_unavailable": error_text == "raw queue exception message unavailable without caller hooks",
                "time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            },
        }
    )
    try:
        set_scan_integrity(path, info)
    except recoverable_exceptions as set_exc:
        report_issue(marker + ".scan_integrity_update_failed", set_exc)
    report_issue(marker, exc)
    return info
