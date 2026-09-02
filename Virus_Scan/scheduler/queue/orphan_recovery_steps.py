"""Bounded process-queue orphan recovery step helpers."""
from __future__ import annotations

import logging
from typing import NamedTuple

from Virus_Scan.scheduler.queue.identity import queue_is_job_json_name as _queue_is_job_json_name
from Virus_Scan.scheduler.queue.orphan_recovery_claim_state import load_active_claim_state
from Virus_Scan.scheduler.queue.orphan_recovery_item import (
    ReclaimActiveClaimRequest,
    reclaim_active_claim_state,
)
from Virus_Scan.scheduler.runtime.queue_filesystem import safe_queue_listdir as _safe_queue_listdir
from Virus_Scan.scheduler.runtime.queue_filesystem_listdir_result import queue_listdir_names


class ReclaimStaleActiveQueueJobsRequest(NamedTuple):
    """Canonical request for active-queue reclaim scanning."""

    queue_dir: object
    active_dir: object
    pending_dir: object
    now: float
    policy_fields: tuple[float, int, float, float, tuple[dict[str, object], ...]]
    raw_stage_progress_recent: object
    file_has_recent_raw_owner_progress: object
    worker_liveness_checker: object
    worker_terminator: object
    record_suppressed: object
    log_error: object
    path_text: object
    item_failure_message: object
    reclaim_exceptions: tuple[type[BaseException], ...]


class ReclaimOneActiveQueueJobRequest(NamedTuple):
    """Canonical request for reclaiming one active queue job."""

    queue_dir: object
    active_dir: object
    pending_dir: object
    source_path: object
    name: str
    now: float
    policy_stale: float
    policy_retries: int
    policy_progress_stall: float
    policy_file_timeout: float
    raw_stage_progress_recent: object
    file_has_recent_raw_owner_progress: object
    worker_liveness_checker: object
    worker_terminator: object
    timeout_recovery_evidence: list[dict[str, object]]


def reclaim_stale_active_queue_jobs(request: ReclaimStaleActiveQueueJobsRequest) -> dict[str, object]:
    """Reclaim each stale active queue job using explicit recovery boundaries."""
    policy_stale, policy_retries, policy_progress_stall, policy_file_timeout, policy_evidence = request.policy_fields
    timeout_recovery_evidence = list(policy_evidence)
    requeued = failed_count = killed = 0
    for name in queue_listdir_names(_safe_queue_listdir(request.active_dir), context=request.active_dir):
        name_text = str.__str__(name) if type(name) is str else ""
        if not _queue_is_job_json_name(name_text):
            continue
        src = request.active_dir / name_text
        try:
            item_requeued, item_failed, item_killed = reclaim_one_active_queue_job(
                ReclaimOneActiveQueueJobRequest(
                    queue_dir=request.queue_dir,
                    active_dir=request.active_dir,
                    pending_dir=request.pending_dir,
                    source_path=src,
                    name=name_text,
                    now=request.now,
                    policy_stale=policy_stale,
                    policy_retries=policy_retries,
                    policy_progress_stall=policy_progress_stall,
                    policy_file_timeout=policy_file_timeout,
                    raw_stage_progress_recent=request.raw_stage_progress_recent,
                    file_has_recent_raw_owner_progress=request.file_has_recent_raw_owner_progress,
                    worker_liveness_checker=request.worker_liveness_checker,
                    worker_terminator=request.worker_terminator,
                    timeout_recovery_evidence=timeout_recovery_evidence,
                )
            )
            requeued += item_requeued
            failed_count += item_failed
            killed += item_killed
        except request.reclaim_exceptions as error:
            request.record_suppressed(
                "process_queue_reclaim_item_failed",
                error,
                fatal=True,
                extra={"source": request.path_text(src)},
            )
            request.log_error(request.item_failure_message(src, error))
    return build_reclaim_result(
        requeued=requeued,
        failed_count=failed_count,
        killed=killed,
        timeout_recovery_evidence=timeout_recovery_evidence,
    )


def reclaim_one_active_queue_job(request: ReclaimOneActiveQueueJobRequest) -> tuple[int, int, int]:
    """Load claim state and apply item-level stale-claim recovery."""
    claim_state = load_active_claim_state(
        request.source_path,
        now=request.now,
        stale=request.policy_stale,
        file_timeout=request.policy_file_timeout,
        progress_stall=request.policy_progress_stall,
        worker_liveness_checker=request.worker_liveness_checker,
        deferred_recovery_evidence=request.timeout_recovery_evidence,
    )
    if claim_state is None:
        return 0, 0, 0
    return reclaim_active_claim_state(
        ReclaimActiveClaimRequest(
            queue_dir=request.queue_dir,
            active_dir=request.active_dir,
            pending_dir=request.pending_dir,
            source_path=request.source_path,
            name=request.name,
            claim_state=claim_state,
            stale=request.policy_stale,
            retries=request.policy_retries,
            progress_stall=request.policy_progress_stall,
            file_timeout=request.policy_file_timeout,
            raw_stage_progress_recent=request.raw_stage_progress_recent,
            file_has_recent_raw_owner_progress=request.file_has_recent_raw_owner_progress,
            worker_terminator=request.worker_terminator,
            now=request.now,
            timeout_recovery_evidence=request.timeout_recovery_evidence,
        )
    )


def build_reclaim_result(
    *,
    requeued: int,
    failed_count: int,
    killed: int,
    timeout_recovery_evidence: list[dict[str, object]],
) -> dict[str, object]:
    """Build final reclaim result and log non-empty recovery effects."""
    if requeued or failed_count or killed:
        logging.info(
            "bulk scan queue recovery: requeued=%s failed=%s killed_workers=%s",
            requeued,
            failed_count,
            killed,
        )
    recovered: dict[str, object] = {"requeued": requeued, "failed": failed_count, "killed": killed}
    if timeout_recovery_evidence:
        recovered["timeout_retry_evidence"] = tuple(timeout_recovery_evidence)
    return recovered
