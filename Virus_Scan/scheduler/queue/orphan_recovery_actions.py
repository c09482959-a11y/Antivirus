"""Queue-owned active-claim reclaim actions."""
from __future__ import annotations

from typing import Mapping, MutableMapping, TYPE_CHECKING

from Virus_Scan.scheduler.evidence.process_queue_errors import (
    process_queue_log_error as _process_queue_log_error,
    process_queue_record_suppressed as _process_queue_record_suppressed,
)
from Virus_Scan.scheduler.internal.scheduler_config import process_queue_env_int as _process_queue_env_int_value
from Virus_Scan.scheduler.queue.claim_sidecar import _queue_cleanup_orphan_claim_meta, _queue_safe_remove_claim_meta
from Virus_Scan.scheduler.queue.reclaim_publication import _publish_reclaimed_pending_job
from Virus_Scan.scheduler.queue.orphan_recovery_actions_steps import (
    move_reclaimed_active_job_to_pending,
    prepare_reclaim_active_move,
)

if TYPE_CHECKING:
    from pathlib import Path


def requeue_reclaimed_active_job(
    *,
    queue_dir: object,
    active_dir: Path,
    pending_dir: Path,
    src: Path,
    name: str,
    job: MutableMapping[str, object],
    queue_info: MutableMapping[str, object],
    now: float,
    attempt: int,
    info: dict[str, object],
    evidence_records: list[Mapping[str, object]] | None = None,
    safe_remove_claim_meta: object = _queue_safe_remove_claim_meta,
    cleanup_orphan_claim_meta: object = _queue_cleanup_orphan_claim_meta,
    process_queue_env_int: object = _process_queue_env_int_value,
    record_suppressed: object = _process_queue_record_suppressed,
    log_error: object = _process_queue_log_error,
    publish_reclaimed_pending_job: object = _publish_reclaimed_pending_job,
) -> bool | None:
    """Move one stale active claim back to pending and publish retry metadata."""
    _attempt_value, dst = prepare_reclaim_active_move(
        pending_dir=pending_dir,
        name=name,
        job=job,
        queue_info=queue_info,
        now=now,
        attempt=attempt,
        info=info,
    )
    move_result = move_reclaimed_active_job_to_pending(
        active_dir=active_dir,
        src=src,
        dst=dst,
        job=job,
        evidence_records=evidence_records,
        safe_remove_claim_meta=safe_remove_claim_meta,
        cleanup_orphan_claim_meta=cleanup_orphan_claim_meta,
        process_queue_env_int=process_queue_env_int,
        record_suppressed=record_suppressed,
        log_error=log_error,
    )
    if not move_result.moved:
        return move_result.reclaim_deferred
    return publish_reclaimed_pending_job(
        queue_dir,
        move_result.destination_path,
        job,
        source_path=src,
        reason="reclaim_annotate_pending",
        evidence_records=evidence_records,
    )


__all__ = ("requeue_reclaimed_active_job",)
