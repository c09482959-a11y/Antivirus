"""Evidence-owned trace-status projection for scheduler final JSON records."""
from __future__ import annotations

from typing import Mapping

from Virus_Scan.scheduler.contracts.evidence_record import SchedulerEvidenceRecord
from Virus_Scan.scheduler.evidence.final_json_contract_support import mapping_from_scheduler_value, scheduler_status_sources, dedupe_scheduler_evidence_records
from Virus_Scan.scheduler.evidence.final_json_exact_fields import (
    collect_exact_scheduler_evidence,
    exact_flag,
    exact_mapping_value,
    first_exact_text,
)
from Virus_Scan.scheduler.internal.immutable_outputs import materialize_scheduler_mapping


_TRACE_STATUS_FIELDS: tuple[str, ...] = (
    "trace",
    "trace_status",
    "scheduler_trace",
    "scheduler_trace_status",
    "trace_write_result",
    "scheduler_trace_write_result",
)
_MISSING = object()


def failure_records_from_trace_status(
    record: Mapping[str, object],
    existing: Mapping[str, object] | None = None,
) -> tuple[SchedulerEvidenceRecord, ...]:
    """Return explicit scheduler evidence for passive trace writer status.

    The trace writer can return an immutable result/status mapping containing a
    failure and evidence.  Phase 11 requires that failure to travel through the
    scheduler-owned final-JSON evidence path instead of remaining passive trace
    metadata.
    """
    records: list[SchedulerEvidenceRecord] = []
    for source in scheduler_status_sources(record, existing):
        for field in _TRACE_STATUS_FIELDS:
            raw_status = exact_mapping_value(source, field, default=_MISSING)
            if raw_status is _MISSING:
                continue
            status = mapping_from_scheduler_value(raw_status)
            if not status:
                continue
            records.extend(collect_exact_scheduler_evidence(exact_mapping_value(status, "evidence", default=())))
            records.extend(collect_exact_scheduler_evidence(exact_mapping_value(status, "failures", default=())))
            status_text = first_exact_text(status, "status", "state").lower()
            reason_text = first_exact_text(status, "reason", "error", "error_category").lower()
            trace_status_failed = (
                exact_flag(status, "fatal", "failed", "trace_failure")
                or exact_mapping_value(status, "ok") is False
                or exact_mapping_value(status, "success") is False
                or status_text in {"failed", "failure", "error", "unwritten", "missing", "invalid"}
                or any(
                    marker in _trace_status_reason_text(status_text, reason_text)
                    for marker in ("failed", "failure", "error", "unwritten", "missing", "invalid")
                )
            )
            if trace_status_failed:
                records.append(_synthetic_trace_status_record(record, status, field=field))
    return dedupe_scheduler_evidence_records(records)


def _trace_status_reason_text(status_text: str, reason_text: str) -> str:
    return str.__add__(str.__add__(status_text, " "), reason_text)


def _trace_error_source(field: str) -> str:
    return str.__add__("scheduler.evidence.", field)


def _synthetic_trace_status_record(
    record: Mapping[str, object],
    status: Mapping[str, object],
    *,
    field: str,
) -> SchedulerEvidenceRecord:
    category = first_exact_text(status, "error_category", "reason", default_text="trace_write_failed")
    return SchedulerEvidenceRecord(
        stage=first_exact_text(status, "stage", default_text="trace_writer"),
        state="failure" if exact_flag(status, "fatal", "failed") or exact_mapping_value(status, "ok") is False else "degraded",
        error_category=category,
        error_source=first_exact_text(status, "error_source") or _trace_error_source(field),
        message=first_exact_text(status, "message", "error", default_text=category),
        context={field: materialize_scheduler_mapping(status)},
        queue_id=first_exact_text(status, "queue_id", "queue_claim_id", "claim_id") or first_exact_text(record, "queue_id", "queue_claim_id", "claim_id"),
        job_id=first_exact_text(status, "job_id") or first_exact_text(record, "job_id"),
        worker_id=first_exact_text(status, "worker_id") or first_exact_text(record, "worker_id"),
        path=first_exact_text(status, "path", "input_file_path", "file") or first_exact_text(record, "input_file_path", "path", "file"),
        final_json_must_record=True,
        checkpoint_must_record=True,
        replay_must_record=True,
        fatal=exact_flag(status, "fatal"),
    )


__all__ = ("failure_records_from_trace_status",)
