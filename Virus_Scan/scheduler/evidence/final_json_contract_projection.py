from __future__ import annotations

from typing import Mapping

from Virus_Scan.scheduler.contracts.evidence_record import SchedulerEvidenceRecord
from Virus_Scan.scheduler.evidence.final_json_contract_error_sources import contract_error_source
from Virus_Scan.scheduler.evidence.final_json_contract_support import dedupe_contract_records, mapping_from_scheduler_value, scheduler_status_sources
from Virus_Scan.scheduler.evidence.final_json_contract_projection_decisions import scan_integrity_failure_decision, worker_status_failure_decision
from Virus_Scan.scheduler.evidence.final_json_exact_fields import (
    collect_exact_scheduler_evidence,
    exact_flag,
    exact_has_content,
    exact_int_with_rejection,
    exact_mapping_value,
    first_exact_text,
)
from Virus_Scan.scheduler.internal.immutable_outputs import materialize_scheduler_mapping


_CONTRACT_STATUS_FIELDS: tuple[tuple[str, str, str], ...] = (
    ("timeout_result", "timeout", "timeout_result_failure"),
    ("timeout_decision", "timeout", "timeout_decision_failure"),
    ("retry_decision", "retry", "retry_decision_failure"),
    ("retry_result", "retry", "retry_decision_failure"),
    ("retry_exhaustion_result", "retry_exhaustion", "retry_exhausted"),
    ("worker_result", "worker", "worker_result_failure"),
    ("worker_lifecycle_result", "worker_lifecycle", "worker_lifecycle_failure"),
    ("worker_snapshot", "worker_lifecycle", "worker_lifecycle_failure"),
)

_MISSING = object()


def failure_records_from_scheduler_contract_status(
    record: Mapping[str, object],
    existing: Mapping[str, object] | None = None,
) -> tuple[SchedulerEvidenceRecord, ...]:
    records: list[SchedulerEvidenceRecord] = []
    for source in scheduler_status_sources(record, existing):
        for field, stage, category in _CONTRACT_STATUS_FIELDS:
            raw_status = exact_mapping_value(source, field, default=_MISSING)
            if raw_status is _MISSING:
                continue
            status = mapping_from_scheduler_value(raw_status)
            if not status:
                continue

            for key in ("evidence", "failures", "failure_evidence", "events"):
                records.extend(collect_exact_scheduler_evidence(exact_mapping_value(status, key, default=())))
            raw_result = exact_mapping_value(status, "result", default=_MISSING)
            if raw_result is not _MISSING:
                result = mapping_from_scheduler_value(raw_result)
                records.extend(collect_exact_scheduler_evidence(exact_mapping_value(result, "scheduler_evidence", default=())))
                records.extend(collect_exact_scheduler_evidence(exact_mapping_value(result, "scheduler_failure_evidence", default=())))
                raw_scan_integrity = exact_mapping_value(result, "scan_integrity", default=_MISSING)
                if raw_scan_integrity is not _MISSING:
                    scan_integrity = mapping_from_scheduler_value(raw_scan_integrity)
                    if scan_integrity_failure_decision(scan_integrity).failed:
                        scan_category = (
                            first_exact_text(
                                scan_integrity,
                                "worker_result_schema_reason",
                                "worker_output_publication_stage",
                                "scheduler_failure_reason",
                            )
                            or "worker_result_scan_integrity_failure"
                        )
                        raw_identity = exact_mapping_value(status, "identity", default=_MISSING)
                        identity = {} if raw_identity is _MISSING else mapping_from_scheduler_value(raw_identity)
                        records.append(
                            SchedulerEvidenceRecord(
                                stage="worker_result",
                                state="failure",
                                error_category=scan_category,
                                error_source="scheduler.evidence.worker_result",
                                message=scan_category,
                                context={"scan_integrity": materialize_scheduler_mapping(scan_integrity)},
                                queue_id=first_exact_text(status, "queue_id", "queue_claim_id", "claim_id"),
                                job_id=first_exact_text(status, "job_id"),
                                worker_id=first_exact_text(status, "worker_id") or first_exact_text(identity, "worker_id"),
                                path=first_exact_text(status, "path", "input_file_path", "file"),
                                retry_state_affected=exact_flag(scan_integrity, "retry_failure", "retry_exhaustion_result_failed"),
                                timeout_state_affected=exact_flag(scan_integrity, "timeout_failure"),
                                final_json_must_record=True,
                                checkpoint_must_record=True,
                                replay_must_record=True,
                                fatal=exact_flag(scan_integrity, "fatal_scheduler_failure"),
                            )
                        )

            status_text = first_exact_text(status, "status", "state").lower()
            reason_text = first_exact_text(status, "reason", "error", "error_category").lower()
            status_failed = bool(
                exact_flag(status, "fatal", "failed", "failure")
                or exact_mapping_value(status, "ok") is False
                or exact_mapping_value(status, "success") is False
                or status_text in {"failed", "failure", "error", "timeout", "timed_out", "exhausted", "dead", "invalid"}
                or any(marker in status_text for marker in ("failed", "error", "timeout", "exhaust", "dead", "invalid"))
                or any(marker in reason_text for marker in ("failed", "failure", "error", "timeout", "exhaust", "dead", "invalid"))
                or (field.startswith("timeout") and exact_flag(status, "timed_out", "timeout_failure"))
            )
            if not status_failed and field.startswith("retry"):
                retry_status_failed = exact_flag(status, "retry_failure", "exhausted", "retry_exhausted")
                if not retry_status_failed:
                    attempt, attempt_rejected = exact_int_with_rejection(status, "attempt")
                    max_attempts, max_attempts_rejected = exact_int_with_rejection(status, "max_attempts")
                    retry_status_failed = bool(
                        attempt_rejected
                        or max_attempts_rejected
                        or (exact_mapping_value(status, "retry_allowed") is False and max_attempts > 0 and attempt >= max_attempts)
                    )
                status_failed = retry_status_failed
            if not status_failed and field.startswith("worker") and worker_status_failure_decision(status).failed:
                status_failed = True
            if not status_failed:
                status_failed = exact_has_content(exact_mapping_value(status, "failures"))
            if status_failed:
                materialized = materialize_scheduler_mapping(status)
                raw_identity = exact_mapping_value(status, "identity", default=_MISSING)
                identity = {} if raw_identity is _MISSING else mapping_from_scheduler_value(raw_identity)
                stage_default = "retry_exhaustion" if exact_flag(status, "exhausted") and field.startswith("retry") else stage
                stage_name = first_exact_text(status, "stage") or stage_default
                if field.startswith("timeout") and exact_flag(status, "timed_out"):
                    default_category = "timeout_result_timed_out"
                elif field.startswith("retry") and exact_flag(status, "exhausted"):
                    default_category = "retry_exhausted"
                else:
                    default_category = category
                reason = first_exact_text(status, "error_category", "reason", "error") or default_category
                state = (
                    "failure"
                    if exact_flag(status, "fatal", "failed")
                    or exact_mapping_value(status, "ok") is False
                    or exact_mapping_value(status, "success") is False
                    else "degraded"
                )
                records.append(
                    SchedulerEvidenceRecord(
                        stage=stage_name,
                        state=state,
                        error_category=reason,
                        error_source=first_exact_text(status, "error_source") or contract_error_source(field),
                        message=first_exact_text(status, "message", "error") or reason,
                        context={field: materialized},
                        queue_id=first_exact_text(status, "queue_id", "queue_claim_id", "claim_id")
                        or first_exact_text(record, "queue_id", "queue_claim_id", "claim_id"),
                        job_id=first_exact_text(status, "job_id") or first_exact_text(record, "job_id"),
                        worker_id=first_exact_text(status, "worker_id")
                        or first_exact_text(identity, "worker_id")
                        or first_exact_text(record, "worker_id"),
                        path=first_exact_text(status, "path", "input_file_path", "file")
                        or first_exact_text(record, "input_file_path", "path", "file"),
                        retry_state_affected=field.startswith("retry") or exact_flag(status, "retry_state_affected", "retry_failure"),
                        timeout_state_affected=field.startswith("timeout")
                        or exact_flag(status, "timeout_state_affected", "timeout_failure"),
                        final_json_must_record=True,
                        checkpoint_must_record=True,
                        replay_must_record=True,
                        fatal=exact_flag(status, "fatal"),
                    )
                )
    return dedupe_contract_records(records)


__all__ = ("failure_records_from_scheduler_contract_status",)
