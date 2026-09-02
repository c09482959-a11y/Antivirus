"""Compact-error scheduler evidence projection for final JSON records."""
from __future__ import annotations

import math
from typing import Mapping

from Virus_Scan.scheduler.contracts.evidence_record import SchedulerEvidenceRecord
from Virus_Scan.scheduler.evidence.final_json_exact_fields import first_exact_text
from Virus_Scan.scheduler.evidence.final_json_status_sources import checkpoint_status_from_record, replay_status_from_record
from Virus_Scan.scheduler.evidence.records import build_scheduler_json_evidence_section


def build_final_json_compact_error_section(
    record: Mapping[str, object],
    *,
    error_type: str,
    message: str = "",
) -> dict[str, object]:
    """Return explicit scheduler evidence when compact final-JSON projection fails."""
    error_name = _safe_text_arg(error_type, default_text="compact_record_error")
    path = first_exact_text(record, "input_file_path", "path", "file", "node")
    evidence = SchedulerEvidenceRecord(
        stage="final_json_compaction",
        state="failure",
        error_category="compact_record_error",
        error_source="scheduler.evidence.final_json_projection",
        message=_safe_text_arg(message, default_text=error_name),
        context={
            "error_type": error_name,
            "checkpoint_reference": first_exact_text(record, "checkpoint_reference", "replay_checkpoint_reference"),
        },
        queue_id=first_exact_text(record, "queue_id", "queue_claim_id", "claim_id"),
        job_id=first_exact_text(record, "job_id"),
        worker_id=first_exact_text(record, "worker_id"),
        path=path,
        final_json_must_record=True,
        checkpoint_must_record=True,
        replay_must_record=True,
        fatal=False,
    )
    return build_scheduler_json_evidence_section(
        (evidence,),
        checkpoint_status=checkpoint_status_from_record(record, None),
        replay_status=replay_status_from_record(record, None),
    )



def _safe_text_arg(value: object, *, default_text: str = "") -> str:
    if value is None:
        return default_text
    if type(value) is str:
        return str.__str__(value) or default_text
    if type(value) is bool:
        return ("true" if value else "false") or default_text
    if type(value) is int:
        return int.__str__(value) or default_text
    if type(value) is float and math.isfinite(value):
        return float.__str__(value) or default_text
    return default_text


__all__ = ("build_final_json_compact_error_section",)
