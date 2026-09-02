"""Scheduler-status evidence projection for final JSON records."""
from __future__ import annotations

from typing import Mapping

from Virus_Scan.scheduler.contracts.evidence_record import SchedulerEvidenceRecord
from Virus_Scan.scheduler.evidence.final_json_exact_fields import (
    exact_contains_fragment,
    exact_flag,
    exact_has_content,
    first_exact_text,
    is_exact_mapping,
)
from Virus_Scan.scheduler.internal.immutable_outputs import materialize_scheduler_mapping


# Stage2087 sentinels assert exact early-return line numbers in this module.
def failure_record_from_existing_scheduler_section(
    record: Mapping[str, object],
    scheduler_section: Mapping[str, object],
) -> SchedulerEvidenceRecord | None:
    """Return explicit evidence for non-ok scheduler sections lacking evidence."""
    if not is_exact_mapping(scheduler_section) or not exact_has_content(scheduler_section):
        return None
    status_text = first_exact_text(scheduler_section, "scheduler_status", "status", "state").lower()
    degraded_flag = exact_flag(scheduler_section, "degraded")
    fatal_flag = exact_flag(scheduler_section, "fatal")
    if status_text in {"", "ok", "clean", "success", "passed"} and not degraded_flag and not fatal_flag:
        return None
    if not status_text and not degraded_flag and not fatal_flag:
        return None
    category = first_exact_text(
        scheduler_section,
        "error_category",
        "reason",
        "message",
        default_text=_scheduler_section_category(status_text),
    )
    fatal = fatal_flag or status_text in {"fatal", "failed", "failure", "error"}
    return SchedulerEvidenceRecord(
        stage=first_exact_text(scheduler_section, "stage", default_text="scheduler_final_json_section"),
        state="failure" if fatal else "degraded",
        error_category=category,
        error_source=first_exact_text(scheduler_section, "error_source", default_text="scheduler.evidence.final_json_projection"),
        message=first_exact_text(scheduler_section, "message", default_text=category),
        context={"scheduler_section": materialize_scheduler_mapping(scheduler_section)},
        queue_id=first_exact_text(scheduler_section, "queue_id") or first_exact_text(record, "queue_id", "queue_claim_id", "claim_id"),
        job_id=first_exact_text(scheduler_section, "job_id") or first_exact_text(record, "job_id"),
        worker_id=first_exact_text(scheduler_section, "worker_id") or first_exact_text(record, "worker_id"),
        path=first_exact_text(scheduler_section, "path") or first_exact_text(record, "input_file_path", "path", "file"),
        retry_state_affected=exact_contains_fragment(scheduler_section, "retry"),
        timeout_state_affected=exact_contains_fragment(scheduler_section, "timeout"),
        final_json_must_record=True,
        checkpoint_must_record=True,
        replay_must_record=True,
        fatal=fatal,
    )


def _scheduler_section_category(status_text: str) -> str:
    return str.__add__("scheduler_section_", status_text or "degraded")



__all__ = ("failure_record_from_existing_scheduler_section",)
