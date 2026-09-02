"""Evidence-owned projection for passive scheduler result/status carriers."""
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
    exact_contains_fragment,
    exact_flag,
    exact_mapping_value,
    first_exact_text,
)
from Virus_Scan.scheduler.internal.immutable_outputs import materialize_scheduler_mapping
from Virus_Scan.scheduler.evidence.final_json_scheduler_result_decisions import root_scheduler_status_decision

_SCHEDULER_RESULT_FIELDS: tuple[str, ...] = (
    "scheduler_result",
    "final_scheduler_result",
)
_NON_OK_STATUSES = (
    "degraded",
    "failed",
    "failure",
    "fatal",
    "error",
    "timeout",
    "timed_out",
    "exhausted",
    "dead",
    "invalid",
)
_OK_STATUSES = ("", "ok", "clean", "success", "passed")
_MISSING = object()
_ROOT_STATUS_RECORD_UNAVAILABLE: SchedulerEvidenceRecord | None = None


def failure_records_from_scheduler_result_status(
    record: Mapping[str, object],
    existing: Mapping[str, object] | None = None,
) -> tuple[SchedulerEvidenceRecord, ...]:
    """Return evidence for passive root/scheduler-result degraded states.

    Phase 11 requires scheduler failures to appear through canonical scheduler
    evidence, not merely as root-level ``scheduler_status`` mirrors or as a
    passive ``scheduler_result`` contract.  This projection handles both without
    mutating queue, worker, timeout, retry, replay, checkpoint, or JSON domains.
    """
    records: list[SchedulerEvidenceRecord] = []
    for source in scheduler_status_sources(record, existing):
        for field in _SCHEDULER_RESULT_FIELDS:
            raw_result = exact_mapping_value(source, field, default=_MISSING)
            if raw_result is _MISSING:
                continue
            result = mapping_from_scheduler_value(raw_result)
            if not result:
                continue
            for key in ("evidence", "scheduler_evidence", "scheduler_failure_evidence", "failures"):
                records.extend(collect_exact_scheduler_evidence(exact_mapping_value(result, key, default=())))
            status_text = first_exact_text(result, "scheduler_status", "status", "state").lower()
            reason_text = first_exact_text(result, "reason", "error", "error_category").lower()
            scheduler_result_failed = (
                exact_flag(result, "fatal", "failed", "failure", "degraded")
                or exact_mapping_value(result, "ok") is False
                or exact_mapping_value(result, "success") is False
                or status_text in _NON_OK_STATUSES
                or any(marker in reason_text for marker in ("failed", "failure", "error", "timeout", "exhaust", "dead", "invalid"))
            )
            if scheduler_result_failed:
                records.append(_synthetic_scheduler_result_record(record, result, field=field))
    root_record = _synthetic_root_status_record(record)
    if root_record is not None:
        records.append(root_record)
    return dedupe_scheduler_evidence_records(records)


def _synthetic_root_status_record(record: Mapping[str, object]) -> SchedulerEvidenceRecord | None:
    decision = root_scheduler_status_decision(record)
    if not decision.should_record:
        return _ROOT_STATUS_RECORD_UNAVAILABLE
    status_text = decision.status_text
    fatal = decision.fatal
    category = first_exact_text(
        record,
        "error_category",
        "reason",
        "scheduler_failure_reason",
        default_text=_root_status_category(status_text),
    )
    return SchedulerEvidenceRecord(
        stage=first_exact_text(record, "stage", default_text="scheduler_final_json_root_status"),
        state="failure" if fatal or status_text in ("fatal", "failed", "failure", "error") else "degraded",
        error_category=category,
        error_source=first_exact_text(record, "error_source", default_text="scheduler.evidence.final_json_projection"),
        message=first_exact_text(record, "message", "scheduler_failure_message", default_text=category),
        context={"scheduler_root_status": materialize_scheduler_mapping(record)},
        queue_id=first_exact_text(record, "queue_id", "queue_claim_id", "claim_id"),
        job_id=first_exact_text(record, "job_id", "file_job_id"),
        worker_id=first_exact_text(record, "worker_id"),
        path=first_exact_text(record, "input_file_path", "path", "file", "node"),
        retry_state_affected=exact_contains_fragment(record, "retry"),
        timeout_state_affected=exact_contains_fragment(record, "timeout"),
        final_json_must_record=True,
        checkpoint_must_record=True,
        replay_must_record=True,
        fatal=fatal,
    )


def _synthetic_scheduler_result_record(
    record: Mapping[str, object],
    result: Mapping[str, object],
    *,
    field: str,
) -> SchedulerEvidenceRecord:
    status_text = first_exact_text(result, "scheduler_status", "status", "state", default_text="degraded").lower()
    fatal = exact_flag(result, "fatal") or status_text in ("fatal", "failed", "failure", "error")
    category = first_exact_text(result, "error_category", "reason", "error", default_text=_result_status_category(field, status_text))
    return SchedulerEvidenceRecord(
        stage=first_exact_text(result, "stage", default_text="scheduler_result"),
        state="failure" if fatal else "degraded",
        error_category=category,
        error_source=first_exact_text(result, "error_source", default_text="scheduler.contracts.scheduler_result"),
        message=first_exact_text(result, "message", default_text=category),
        context={field: materialize_scheduler_mapping(result)},
        queue_id=first_exact_text(result, "queue_id") or first_exact_text(record, "queue_id", "queue_claim_id", "claim_id"),
        job_id=first_exact_text(result, "job_id") or first_exact_text(record, "job_id", "file_job_id"),
        worker_id=first_exact_text(result, "worker_id") or first_exact_text(record, "worker_id"),
        path=first_exact_text(result, "path", "input_file_path", "file") or first_exact_text(record, "input_file_path", "path", "file"),
        retry_state_affected=exact_contains_fragment(result, "retry"),
        timeout_state_affected=exact_contains_fragment(result, "timeout"),
        final_json_must_record=True,
        checkpoint_must_record=True,
        replay_must_record=True,
        fatal=fatal,
    )



def _root_status_category(status_text: str) -> str:
    return str.__add__("scheduler_root_status_", status_text or "degraded")


def _result_status_category(field: str, status_text: str) -> str:
    return str.__add__(str.__add__(field, "_"), status_text or "degraded")


__all__ = ("failure_records_from_scheduler_result_status",)
