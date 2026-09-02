"""Queue-owned worker termination boundary for orphan recovery."""
from __future__ import annotations

import json
from typing import Callable, Mapping, TYPE_CHECKING

from Virus_Scan.scheduler.queue.orphan_recovery_action_evidence import (
    OrphanRecoveryActionEvidenceRequest,
    orphan_recovery_action_evidence,
)

if TYPE_CHECKING:
    from pathlib import Path

RECLAIM_TERMINATION_EXCEPTIONS = (FileNotFoundError, PermissionError, OSError, RuntimeError, TypeError, ValueError, json.JSONDecodeError)


def terminate_reclaimed_worker(
    *,
    worker_terminator: Callable[..., object],
    pid: object,
    reason_stage: str,
    source_path: Path,
    queue_dir: object,
    job: Mapping[str, object],
    evidence_records: list[Mapping[str, object]],
    record_suppressed: Callable[..., object],
) -> tuple[bool, Mapping[str, object], bool]:
    """Terminate a reclaimed worker and return killed/evidence/failed state."""

    try:
        termination_result = worker_terminator(pid, reason=reason_stage)
    except RECLAIM_TERMINATION_EXCEPTIONS as termination_exc:
        termination_record = orphan_recovery_action_evidence(OrphanRecoveryActionEvidenceRequest(
            stage="process_queue_reclaim_worker_termination_failed",
            action="terminate_reclaimed_worker",
            source_path=source_path,
            destination_path=queue_dir,
            error=termination_exc,
            error_source="orphan_recovery.worker_terminator",
            job_id=job.get("id") or job.get("job_id") or job.get("file"),
        )).as_record()
        evidence_records.append(dict(termination_record))
        record_suppressed(
            "process_queue_reclaim_worker_termination_failed",
            termination_exc,
            fatal=True,
            extra={"source": str(source_path), "pid": pid},
        )
        return False, {}, True
    return bool(termination_result.terminated), termination_result.as_evidence(), False


__all__ = ("RECLAIM_TERMINATION_EXCEPTIONS", "terminate_reclaimed_worker")
