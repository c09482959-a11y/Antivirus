"""Evidence-owned failure projection helpers for final JSON records."""
from __future__ import annotations

from typing import Mapping, cast

from Virus_Scan.scheduler.contracts.evidence_record import SchedulerEvidenceRecord
from Virus_Scan.scheduler.evidence.final_json_exact_fields import (
    exact_flag,
    exact_mapping_items,
    exact_mapping_value,
    first_exact_text,
    is_exact_mapping,
)
from Virus_Scan.scheduler.internal.immutable_outputs import materialize_scheduler_mapping


def failure_record_from_scheduler_result(record: Mapping[str, object]) -> SchedulerEvidenceRecord | None:
    scan_integrity_value = exact_mapping_value(record, "scan_integrity")
    scan_integrity = cast("Mapping[str, object]", scan_integrity_value) if is_exact_mapping(scan_integrity_value) else {}
    reason = first_exact_text(
        record,
        "scheduler_failure_reason",
        "queue_failure_reason",
        "worker_failure_reason",
        "timeout_failure_reason",
    ) or first_exact_text(
        scan_integrity,
        "scheduler_failure_reason",
        "worker_result_schema_reason",
        "worker_output_publication_stage",
    )
    visible_failure = _visible_scheduler_failure(record, scan_integrity)
    if not (visible_failure or reason):
        return None
    category = reason or "scheduler_failure"
    return SchedulerEvidenceRecord(
        stage=first_exact_text(record, "scheduler_failure_stage") or first_exact_text(scan_integrity, "worker_output_publication_stage") or ("worker" if "worker" in category else "timeout" if "timeout" in category else "retry" if "retry" in category else "queue" if "queue" in category else "scheduler_result"),
        state="failure" if visible_failure else "degraded",
        error_category=category,
        error_source=first_exact_text(record, "scheduler_failure_source", default_text="scheduler.final_json_projection"),
        message=first_exact_text(record, "scheduler_failure_message", default_text=category),
        context={
            "scan_integrity": materialize_scheduler_mapping(scan_integrity),
            "result_keys": _scheduler_result_keys(record),
        },
        queue_id=first_exact_text(record, "queue_id", "queue_claim_id", "claim_id"),
        job_id=first_exact_text(record, "job_id") or first_exact_text(scan_integrity, "job_id"),
        worker_id=first_exact_text(record, "worker_id") or first_exact_text(scan_integrity, "worker_id"),
        path=first_exact_text(record, "input_file_path", "path", "file"),
        retry_state_affected="retry" in category or exact_flag(record, "retry_failure", "retry_exhaustion_result_failed") or exact_flag(scan_integrity, "retry_failure", "retry_exhaustion_result_failed"),
        timeout_state_affected="timeout" in category or exact_flag(record, "timeout_failure") or exact_flag(scan_integrity, "timeout_failure"),
        final_json_must_record=True,
        checkpoint_must_record=True,
        replay_must_record=True,
        fatal=exact_flag(record, "scheduler_fatal", "fatal_scheduler_failure") or exact_flag(scan_integrity, "fatal_scheduler_failure"),
    )


def _visible_scheduler_failure(record: Mapping[str, object], scan_integrity: Mapping[str, object]) -> bool:
    result_keys = ("queue_failure", "timeout_failure", "retry_failure", "worker_output_publication_failed", "retry_exhaustion_result_failed", "scheduler_failure")
    integrity_keys = ("queue_failure", "timeout_failure", "retry_failure", "worker_result_schema_invalid", "worker_output_publication_failed", "retry_exhaustion_result_failed")
    return any(exact_flag(record, key) for key in result_keys) or any(exact_flag(scan_integrity, key) for key in integrity_keys)


def _scheduler_result_keys(record: Mapping[str, object]) -> tuple[str, ...]:
    items = exact_mapping_items(record)
    if items is None:





















        return ()
    return tuple(sorted(
        key for key, _value in items
        if type(key) is str and key.startswith(("scheduler_", "queue_", "worker_", "timeout_", "retry_"))
    ))


__all__ = ("failure_record_from_scheduler_result",)
