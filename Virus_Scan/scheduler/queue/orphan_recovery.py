"""Process-queue recovery ownership helpers."""
from __future__ import annotations

from typing import NamedTuple

from Virus_Scan.contracts.no_hook_materialization import no_hook_mapping_items, no_hook_sequence_items
from Virus_Scan.scheduler.internal.no_hook_attrs import scheduler_exact_attr
from Virus_Scan.scheduler.internal.no_hook_diagnostics import scheduler_path_text
from Virus_Scan.scheduler.internal.exception_projection import scheduler_error_detail
from Virus_Scan.scheduler.internal.immutable_outputs import materialize_scheduler_mapping

from Virus_Scan.scheduler.evidence.process_queue_errors import (
    process_queue_log_error as _process_queue_log_error,
    process_queue_record_suppressed as _process_queue_record_suppressed,
)
from Virus_Scan.scheduler.queue.authority import _ensure_process_queue_dirs, queue_now as _process_queue_queue_now
from Virus_Scan.scheduler.queue.orphan_recovery_claim_state import load_active_claim_state
from Virus_Scan.scheduler.queue.orphan_recovery_policy import QueueReclaimPolicy, load_queue_reclaim_policy
from Virus_Scan.scheduler.queue.orphan_recovery_worker_termination import RECLAIM_TERMINATION_EXCEPTIONS
from Virus_Scan.scheduler.queue.reclaim_publication import _publish_reclaimed_pending_job
from Virus_Scan.scheduler.queue.recovery_contract import reset_queue_retry_runtime_metadata as _queue_reset_retry_runtime_metadata
from Virus_Scan.scheduler.runtime.queue_filesystem import queue_job_dirs as _queue_job_dirs
from Virus_Scan.scheduler.queue.orphan_recovery_steps import (
    ReclaimStaleActiveQueueJobsRequest,
    reclaim_stale_active_queue_jobs,
)

_ORPHAN_RECOVERY_DELEGATED_HELPERS = (
    "apply_raw_owner_reclaim_gate",
    "apply_raw_stage_reclaim_gate",
    "classify_reclaim_timeout",
    "requeue_reclaimed_active_job",
)
_PROCESS_QUEUE_RECOVERY_REQUIRES_PROGRESS_PROBES = "process queue recovery requires explicit raw progress probes"


class OrphanReclaimRequest(NamedTuple):
    """Canonical request for process-queue stale active-claim reclaim."""

    queue_dir: object
    stale_sec: object
    max_retries: object
    progress_stall_sec: object
    per_file_timeout_sec: object
    raw_stage_progress_recent: object
    file_has_recent_raw_owner_progress: object
    worker_liveness_checker: object
    worker_terminator: object


def _queue_reclaim_path_text(value: object) -> str:
    text, reason = scheduler_path_text(value)
    if reason == "":
        return text
    return ""


def _queue_reclaim_policy_fields(policy: object) -> tuple[float, int, float, float, tuple[dict[str, object], ...]]:
    if type(policy) is not QueueReclaimPolicy:
        exception_message = "queue reclaim policy rejected"
        raise TypeError(exception_message)
    evidence_records = []
    evidence = scheduler_exact_attr(policy, "evidence", owner_type=QueueReclaimPolicy, default=())
    for policy_record in no_hook_sequence_items(evidence):
        items = no_hook_mapping_items(policy_record)
        if items is not None:
            evidence_records.append(dict(items))
            continue
        materialized_record = materialize_scheduler_mapping(policy_record)
        if type(materialized_record) is dict:
            evidence_records.append(materialized_record)
    return (
        scheduler_exact_attr(policy, "stale", owner_type=QueueReclaimPolicy, default=0.0),
        scheduler_exact_attr(policy, "retries", owner_type=QueueReclaimPolicy, default=0),
        scheduler_exact_attr(policy, "progress_stall", owner_type=QueueReclaimPolicy, default=0.0),
        scheduler_exact_attr(policy, "file_timeout", owner_type=QueueReclaimPolicy, default=0.0),
        tuple(evidence_records),
    )


def _reclaim_stale_process_queue_jobs(request: OrphanReclaimRequest) -> object:
    """Reclaim active jobs without hiding worker/timeout/queue failures."""
    if request.raw_stage_progress_recent is None or request.file_has_recent_raw_owner_progress is None:
        raise RuntimeError(_PROCESS_QUEUE_RECOVERY_REQUIRES_PROGRESS_PROBES)
    try:
        pending, active, _, _ = _queue_job_dirs(request.queue_dir)
        if not _ensure_process_queue_dirs(request.queue_dir):
            return {"requeued": 0, "failed": 0, "killed": 0}
        policy = load_queue_reclaim_policy(
            stale_sec=request.stale_sec,
            max_retries=request.max_retries,
            progress_stall_sec=request.progress_stall_sec,
            per_file_timeout_sec=request.per_file_timeout_sec,
        )
        return reclaim_stale_active_queue_jobs(
            ReclaimStaleActiveQueueJobsRequest(
                queue_dir=request.queue_dir,
                active_dir=active,
                pending_dir=pending,
                now=_process_queue_queue_now(),
                policy_fields=_queue_reclaim_policy_fields(policy),
                raw_stage_progress_recent=request.raw_stage_progress_recent,
                file_has_recent_raw_owner_progress=request.file_has_recent_raw_owner_progress,
                worker_liveness_checker=request.worker_liveness_checker,
                worker_terminator=request.worker_terminator,
                record_suppressed=_process_queue_record_suppressed,
                log_error=_process_queue_log_error,
                path_text=_queue_reclaim_path_text,
                item_failure_message=lambda source_path, error: (
                    "process queue orphan/progress reclaim failed for "
                    + _queue_reclaim_path_text(source_path)
                    + ": "
                    + scheduler_error_detail(error)
                ),
                reclaim_exceptions=RECLAIM_TERMINATION_EXCEPTIONS,
            )
        )
    except RECLAIM_TERMINATION_EXCEPTIONS as e:
        _process_queue_record_suppressed("process_queue_reclaim_failed", e, fatal=True, extra={"queue_dir": _queue_reclaim_path_text(request.queue_dir)})
        _process_queue_log_error(
            "process queue orphan/progress reclaim failed: "
            + scheduler_error_detail(e)
        )
        return {"requeued": 0, "failed": 0, "killed": 0, "reclaim_failed": True}


__all__ = ("OrphanReclaimRequest", "_publish_reclaimed_pending_job", "_queue_reset_retry_runtime_metadata", "_reclaim_stale_process_queue_jobs", "load_active_claim_state")
