"""Bounded passive scheduler-status inventory projection."""
from __future__ import annotations

from typing import TYPE_CHECKING

from Virus_Scan.scheduler.contracts.evidence_record import SchedulerEvidenceRecord
from Virus_Scan.scheduler.evidence.final_json_contract_support import mapping_from_scheduler_value, scheduler_status_sources, dedupe_scheduler_evidence_records
from Virus_Scan.scheduler.evidence.final_json_exact_fields import (
    collect_exact_scheduler_evidence,
    exact_flag,
    exact_mapping_items,
    exact_mapping_value,
    first_exact_text,
    is_exact_mapping,
)
from Virus_Scan.scheduler.evidence.final_json_passive_decisions import scheduler_status_key_decision
from Virus_Scan.scheduler.evidence.final_json_passive_scalar import scalar_failure_category
from Virus_Scan.scheduler.internal.immutable_outputs import (
    is_trusted_scheduler_materialization_value,
    materialize_scheduler_mapping,
)

if TYPE_CHECKING:
    from collections.abc import Mapping

_DOMAIN_FRAGMENTS = (
    "scheduler", "queue", "worker", "timeout", "retry", "replay", "checkpoint", "trace", "orphan",
)
_STATUS_FRAGMENTS = (
    "status", "state", "result", "failure", "failed", "fatal", "degraded", "suppressed_failures",
)
_FAILURE_MARKERS = (
    "failed", "failure", "error", "fatal", "degraded", "timeout", "timed_out", "exhaust", "dead",
    "invalid", "corrupt", "missing", "orphan", "unwritten", "suppressed",
)
_OK_STATUSES = ("", "ok", "clean", "success", "passed", "complete", "completed")
_SPECIFIC_PROJECTION_FIELDS = (
    "checkpoint", "checkpoint_status", "scheduler_checkpoint",
    "replay_comparison_result", "replay_result", "replay_status", "scheduler_replay",
    "queue_integrity_result", "queue_recovery_result", "orphan_recovery_result", "queue_merge_result",
    "timeout_result", "timeout_decision", "retry_decision", "retry_result", "retry_exhaustion_result",
    "worker_result", "worker_lifecycle_result", "worker_snapshot",
    "trace", "trace_status", "scheduler_trace", "scheduler_trace_status",
    "trace_write_result", "scheduler_trace_write_result",
)


def failure_records_from_passive_scheduler_statuses(
    record: Mapping[str, object],
    existing: Mapping[str, object] | None = None,
) -> tuple[SchedulerEvidenceRecord, ...]:
    """Return evidence for passive failed/degraded scheduler-domain carriers.

    This is the Phase 11 inventory backstop.  Specific queue/worker/timeout/
    retry/replay/checkpoint/trace projections own their domain semantics; this
    module prevents newly surfaced passive scheduler-domain status/result/failure
    fields from remaining clean metadata when they already declare failure.
    """
    records: list[SchedulerEvidenceRecord] = []
    for source in scheduler_status_sources(record, existing):
        items = exact_mapping_items(source)
        if items is None:
            continue
        for key, value in items:
            if type(key) is not str:
                continue
            key_text = str.__str__(key)
            if not _is_scheduler_status_key(key_text):
                continue
            if is_exact_mapping(value) or is_trusted_scheduler_materialization_value(value):
                status = mapping_from_scheduler_value(value)
                if not status:
                    continue
                for evidence_key in (
                    "evidence",
                    "scheduler_evidence",
                    "scheduler_failure_evidence",
                    "failures",
                    "failure_evidence",
                ):
                    records.extend(
                        collect_exact_scheduler_evidence(
                            exact_mapping_value(status, evidence_key, default=())
                        )
                    )
                status_text = first_exact_text(status, "scheduler_status", "status", "state").lower()
                reason_text = first_exact_text(status, "reason", "error", "error_category", "message").lower()
                mapping_failed = (
                    exact_flag(status, "fatal", "failed", "failure", "degraded")
                    or exact_mapping_value(status, "ok") is False
                    or exact_mapping_value(status, "success") is False
                    or (status_text and status_text not in _OK_STATUSES and any(marker in status_text for marker in _FAILURE_MARKERS))
                    or any(marker in reason_text for marker in _FAILURE_MARKERS)
                )
                if mapping_failed:
                    category = first_exact_text(
                        status,
                        "error_category",
                        "reason",
                        "error",
                        default_text=str.__add__(key_text, "_failure"),
                    )
                    fatal = exact_flag(status, "fatal") or status_text in ("fatal", "failed", "failure", "error")
                    records.append(_base_record(
                        record,
                        key_text,
                        category,
                        {key_text: materialize_scheduler_mapping(status)},
                        fatal=fatal,
                    ))
                continue
            category = scalar_failure_category(key_text, value)
            if category:
                records.append(
                    _base_record(
                        record,
                        key_text,
                        category,
                        {key_text: materialize_scheduler_mapping(value)},
                        fatal=category.endswith("_unsupported") or "fatal" in key_text.lower(),
                    )
                )
    return dedupe_scheduler_evidence_records(records)


def _is_scheduler_status_key(key: str) -> bool:
    return scheduler_status_key_decision(
        key,
        domain_fragments=_DOMAIN_FRAGMENTS,
        status_fragments=_STATUS_FRAGMENTS,
        specific_projection_fields=_SPECIFIC_PROJECTION_FIELDS,
    ).accepted


def _base_record(
    record: Mapping[str, object],
    field: str,
    category: str,
    context: Mapping[str, object],
    *,
    fatal: bool,
) -> SchedulerEvidenceRecord:
    text = str.lower(field)
    stage = "scheduler_passive_status"
    for domain in _DOMAIN_FRAGMENTS:
        if domain in text:
            stage = domain
            break
    return SchedulerEvidenceRecord(
        stage=stage,
        state="failure" if fatal or text.endswith(("_failed", "_failure")) else "degraded",
        error_category=category,
        error_source=str.__add__("scheduler.evidence.", field),
        message=category,
        context=context,
        queue_id=first_exact_text(record, "queue_id", "queue_claim_id", "claim_id"),
        job_id=first_exact_text(record, "job_id", "file_job_id"),
        worker_id=first_exact_text(record, "worker_id"),
        path=first_exact_text(record, "input_file_path", "path", "file", "node"),
        retry_state_affected="retry" in text,
        timeout_state_affected="timeout" in text,
        final_json_must_record=True,
        checkpoint_must_record=True,
        replay_must_record=True,
        fatal=fatal,
    )


__all__ = ("failure_records_from_passive_scheduler_statuses",)
