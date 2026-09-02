"""Evidence-owned queue-status projection for final JSON records."""
from __future__ import annotations

from typing import Mapping

from Virus_Scan.scheduler.contracts.evidence_record import SchedulerEvidenceRecord
from Virus_Scan.scheduler.evidence.final_json_contract_support import (
    dedupe_scheduler_evidence_records,
    mapping_from_scheduler_value,
    scheduler_status_sources,
)
from Virus_Scan.scheduler.evidence.final_json_exact_fields import (
    collect_exact_scheduler_evidence,
    exact_flag,
    exact_has_content,
    exact_int_with_rejection,
    exact_mapping_value,
    first_exact_text,
    is_empty_placeholder,
)
from Virus_Scan.scheduler.internal.immutable_outputs import materialize_scheduler_mapping


_QUEUE_STATUS_FIELDS: tuple[tuple[str, str, str], ...] = (
    ("queue_integrity_result", "queue_integrity", "queue_integrity_failure"),
    ("queue_recovery_result", "queue_recovery", "queue_recovery_failure"),
    ("orphan_recovery_result", "orphan_recovery", "orphan_recovery_failure"),
    ("queue_merge_result", "queue_result_merge", "queue_result_merge_failure"),
)
_MISSING = object()


def failure_records_from_queue_status(
    record: Mapping[str, object],
    existing: Mapping[str, object] | None = None,
) -> tuple[SchedulerEvidenceRecord, ...]:
    """Return explicit evidence for passive queue status contracts.

    Queue integrity, recovery, orphan-recovery, and merge contracts may reach the
    final-JSON boundary as ``*_result`` mappings or immutable contract objects.
    Phase 11 requires those failures to appear in the canonical scheduler section
    even when the producer did not also attach a separate ``*_evidence`` field.
    """
    records: list[SchedulerEvidenceRecord] = []
    for source in scheduler_status_sources(record, existing):
        for field, stage, category in _QUEUE_STATUS_FIELDS:
            raw_status = exact_mapping_value(source, field, default=_MISSING)
            if raw_status is _MISSING:
                continue
            if is_empty_placeholder(raw_status):
                continue
            status = mapping_from_scheduler_value(raw_status)
            if not status:
                continue

            for key in ("evidence", "failures", "missing_results"):
                records.extend(collect_exact_scheduler_evidence(exact_mapping_value(status, key, default=())))
            raw_snapshot = exact_mapping_value(status, "snapshot", default=_MISSING)
            if raw_snapshot is not _MISSING and not is_empty_placeholder(raw_snapshot):
                snapshot = mapping_from_scheduler_value(raw_snapshot)
                records.extend(collect_exact_scheduler_evidence(exact_mapping_value(snapshot, "evidence", default=())))

            status_text = first_exact_text(status, "status", "state").lower()
            reason_text = first_exact_text(status, "reason", "error", "error_category")
            status_failed = bool(
                exact_flag(status, "fatal", "failed", "queue_failure", "queue_recovery_failure")
                or exact_mapping_value(status, "ok") is False
                or exact_mapping_value(status, "success") is False
                or status_text in {"failed", "failure", "error", "corrupt", "missing", "invalid"}
                or "failed" in status_text
                or "error" in status_text
                or "corrupt" in status_text
                or exact_has_content(exact_mapping_value(status, "failures"))
                or exact_has_content(exact_mapping_value(status, "missing_results"))
            )
            if not status_failed and field in {"queue_recovery_result", "orphan_recovery_result"}:
                orphaned, orphaned_rejected = exact_int_with_rejection(status, "orphaned")
                status_failed = bool(orphaned_rejected or orphaned > 0)
            if not status_failed and reason_text:
                status_failed = any(marker in reason_text.lower() for marker in ("failed", "error", "corrupt", "missing", "orphan"))
            if status_failed:
                materialized = materialize_scheduler_mapping(status)
                status_stage = stage if exact_flag(status, "unsupported_scheduler_value") else first_exact_text(status, "stage", default_text=stage)
                records.append(
                    SchedulerEvidenceRecord(
                        stage=status_stage,
                        state="failure" if exact_flag(status, "fatal", "failed") or exact_mapping_value(status, "ok") is False else "degraded",
                        error_category=first_exact_text(status, "error_category", "reason", default_text=category),
                        error_source=first_exact_text(status, "error_source", default_text=_queue_error_source(field)),
                        message=first_exact_text(status, "message", "error", "reason", default_text=category),
                        context={field: materialized},
                        queue_id=first_exact_text(status, "queue_id", "queue_claim_id", "claim_id")
                        or first_exact_text(record, "queue_id", "queue_claim_id", "claim_id"),
                        job_id=first_exact_text(status, "job_id") or first_exact_text(record, "job_id"),
                        worker_id=first_exact_text(status, "worker_id") or first_exact_text(record, "worker_id"),
                        path=first_exact_text(status, "path", "input_file_path", "file")
                        or first_exact_text(record, "input_file_path", "path", "file"),
                        retry_state_affected=exact_flag(status, "retry_state_affected", "retry_failure") or "retry" in category,
                        timeout_state_affected=exact_flag(status, "timeout_state_affected", "timeout_failure") or "timeout" in category,
                        final_json_must_record=True,
                        checkpoint_must_record=True,
                        replay_must_record=True,
                        fatal=exact_flag(status, "fatal"),
                    )
                )
    return dedupe_scheduler_evidence_records(records)


def _queue_error_source(field: str) -> str:
    return str.__add__("scheduler.evidence.", field)


__all__ = ("failure_records_from_queue_status",)
