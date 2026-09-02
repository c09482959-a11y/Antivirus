"""Queue-owned terminal handling for unretryable orphan recovery."""
from __future__ import annotations

from dataclasses import dataclass

from typing import Mapping

from Virus_Scan.scheduler.evidence.process_queue_errors import record_scheduler_suppressed
from Virus_Scan.scheduler.queue.process_queue_finalization import _finish_process_queue_job
from Virus_Scan.scheduler.queue.orphan_recovery_action_evidence import (
    OrphanRecoveryActionEvidenceRequest,
    orphan_recovery_action_evidence,
)
from Virus_Scan.scheduler.internal.no_hook_diagnostics import scheduler_evidence_path


@dataclass(frozen=True, slots=True)
class UnretryableReclaimedJobFinishRequest:
    """Internal request for one unretryable reclaimed-job finalization."""

    queue_dir: object
    src: object
    info: dict[str, object]
    job: dict[str, object]
    evidence_records: list[Mapping[str, object]] | None = None
    finish_process_queue_job: object = _finish_process_queue_job


def finish_unretryable_reclaimed_job(
    request: UnretryableReclaimedJobFinishRequest,
) -> bool:
    """Publish a stale active claim as failed without hiding finalization errors."""
    finished = False
    try:
        request.finish_process_queue_job(
            request.queue_dir,
            request.src,
            ok=False,
            error_info=request.info,
            job=request.job,
        )
        finished = True
    except (OSError, RuntimeError, TypeError, ValueError) as exc:
        record_scheduler_suppressed(
            "process_queue_finish_after_reclaim_failed",
            exc,
            extra={
                "source": scheduler_evidence_path(
                    request.src,
                    field_name="orphan_finish_source",
                )
            },
        )
        if request.evidence_records is not None:
            request.evidence_records.append(
                orphan_recovery_action_evidence(
                    OrphanRecoveryActionEvidenceRequest(
                        stage="process_queue_finish_after_reclaim_failed",
                        action="finish_unretryable_reclaimed_job",
                        source_path=request.src,
                        destination_path=request.queue_dir,
                        error=exc,
                        error_source="orphan_recovery_finish.finish_unretryable_reclaimed_job",
                        job_id=(
                            request.job.get("id")
                            or request.job.get("job_id")
                            or request.job.get("file")
                            if isinstance(request.job, dict)
                            else ""
                        ),
                    )
                ).as_record()
            )
    return finished




__all__ = (
    'UnretryableReclaimedJobFinishRequest',
    'finish_unretryable_reclaimed_job',
)
