"""Replay-status evidence projection for scheduler final JSON records."""
from __future__ import annotations

from typing import Mapping

from Virus_Scan.scheduler.contracts.evidence_record import SchedulerEvidenceRecord
from Virus_Scan.scheduler.evidence.final_json_exact_fields import (
    exact_flag,
    exact_has_content,
    exact_mapping_value,
    first_exact_text,
    is_exact_mapping,
)
from Virus_Scan.scheduler.internal.immutable_outputs import materialize_scheduler_mapping


def failure_record_from_replay_status(record: Mapping[str, object], replay_status: Mapping[str, object]) -> SchedulerEvidenceRecord | None:
    """Return explicit evidence when replay comparison reports a mismatch."""
    if not is_exact_mapping(replay_status) or not exact_has_content(replay_status):
        return None
    matched = exact_mapping_value(replay_status, "matched")
    mismatches = exact_mapping_value(replay_status, "mismatches", default=exact_mapping_value(replay_status, "replay_mismatches", default=()))
    mismatch_count = list.__len__(mismatches) if type(mismatches) is list else tuple.__len__(mismatches) if type(mismatches) is tuple else 1 if exact_has_content(mismatches) else 0
    if matched is not False and mismatch_count <= 0 and not exact_flag(replay_status, "replay_failure"):
        return None
    category = first_exact_text(replay_status, "error_category", default_text="replay_mismatch")
    return SchedulerEvidenceRecord(
        stage=first_exact_text(replay_status, "stage", default_text="replay_comparison"),
        state="failure",
        error_category=category,
        error_source=first_exact_text(replay_status, "error_source", default_text="scheduler.replay.compare"),
        message=first_exact_text(replay_status, "message", default_text=category),
        context={
            "replay_comparison_result": materialize_scheduler_mapping(replay_status),
            "mismatch_count": mismatch_count,
        },
        queue_id=first_exact_text(record, "queue_id", "queue_claim_id", "claim_id"),
        job_id=first_exact_text(record, "job_id"),
        worker_id=first_exact_text(record, "worker_id"),
        path=first_exact_text(record, "input_file_path", "path", "file"),
        final_json_must_record=True,
        checkpoint_must_record=True,
        replay_must_record=True,
        fatal=exact_flag(replay_status, "fatal"),
    )


__all__ = ("failure_record_from_replay_status",)
