"""Bounded failure-evidence helpers for orphan recovery reclaim gates."""
from __future__ import annotations

from typing import Mapping

from Virus_Scan.scheduler.queue.orphan_recovery_action_evidence import (
    OrphanRecoveryActionEvidenceRequest,
    orphan_recovery_action_evidence,
)


def record_reclaim_gate_failure(
    *,
    record_suppressed: object,
    evidence_records: list[Mapping[str, object]] | None,
    stage: str,
    action: str,
    source_path: object,
    destination_path: object,
    error: BaseException,
    error_source: str,
    job_id: object,
    extra: Mapping[str, object],
) -> None:
    """Record one reclaim-gate probe/schema failure without touching caller hooks."""
    record_suppressed(stage, error, extra=extra)
    if evidence_records is None:
        return
    evidence_records.append(
        orphan_recovery_action_evidence(OrphanRecoveryActionEvidenceRequest(
            stage=stage,
            action=action,
            source_path=source_path,
            destination_path=destination_path,
            error=error,
            error_source=error_source,
            job_id=job_id,
        )).as_record()
    )


__all__ = ("record_reclaim_gate_failure",)
