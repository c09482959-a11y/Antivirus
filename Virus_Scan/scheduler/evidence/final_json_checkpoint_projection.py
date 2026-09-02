"""Evidence-owned checkpoint-status projection for final JSON records."""
from __future__ import annotations

from typing import Mapping

from Virus_Scan.scheduler.contracts.evidence_record import SchedulerEvidenceRecord
from Virus_Scan.scheduler.evidence.final_json_exact_fields import (
    exact_flag,
    exact_has_content,
    first_exact_text,
    is_exact_mapping,
)
from Virus_Scan.scheduler.internal.immutable_outputs import materialize_scheduler_mapping


def failure_record_from_checkpoint_status(record: Mapping[str, object], checkpoint_status: Mapping[str, object]) -> SchedulerEvidenceRecord | None:
    """Return explicit evidence when checkpoint publication/restoration failed.

    Phase 11 requires checkpoint failures to remain visible in final JSON and
    replay/checkpoint evidence.  Some checkpoint write results are attached as
    compact status mappings instead of scheduler evidence records; without this
    projection a failed checkpoint can be copied as passive metadata while the
    scheduler section remains ``ok`` or absent.
    """
    if not is_exact_mapping(checkpoint_status) or not exact_has_content(checkpoint_status):
        return None
    status_text = first_exact_text(checkpoint_status, "status", "checkpoint_status").lower()
    error_text = first_exact_text(checkpoint_status, "error", "error_category", "message")
    failed = bool(
        exact_flag(checkpoint_status, "fatal", "failed")
        or status_text in {"failed", "failure", "error", "corrupt", "missing", "unwritten"}
        or "failed" in status_text
        or "error" in status_text
    )
    if not failed:
        return None
    category = first_exact_text(checkpoint_status, "error_category") or "checkpoint_write_failed"
    checkpoint_path = first_exact_text(checkpoint_status, "checkpoint_path", "path") or first_exact_text(
        record,
        "checkpoint_path",
        "checkpoint_reference",
        "replay_checkpoint_reference",
    )
    return SchedulerEvidenceRecord(
        stage=first_exact_text(checkpoint_status, "stage") or "checkpoint_writer",
        state="failure",
        error_category=category,
        error_source=first_exact_text(checkpoint_status, "error_source") or "scheduler.evidence.checkpoint_writer",
        message=first_exact_text(checkpoint_status, "message") or error_text or category,
        context={
            "checkpoint": materialize_scheduler_mapping(checkpoint_status),
            "checkpoint_path": checkpoint_path,
        },
        queue_id=first_exact_text(record, "queue_id", "queue_claim_id", "claim_id"),
        job_id=first_exact_text(record, "job_id") or first_exact_text(checkpoint_status, "job_id"),
        worker_id=first_exact_text(record, "worker_id") or first_exact_text(checkpoint_status, "worker_id"),
        path=first_exact_text(record, "input_file_path", "path", "file"),
        final_json_must_record=True,
        checkpoint_must_record=True,
        replay_must_record=True,
        fatal=exact_flag(checkpoint_status, "fatal", default=True),
    )


__all__ = ("failure_record_from_checkpoint_status",)
