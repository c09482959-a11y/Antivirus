"""Bounded execution steps for one in-memory worker job."""
from __future__ import annotations

import os
import threading
import time
from collections.abc import Callable
from typing import TYPE_CHECKING

from Virus_Scan.scheduler.internal.live_worker_config import freeze_inmemory_worker_config
from Virus_Scan.scheduler.internal.no_hook_diagnostics import scheduler_bool, scheduler_int
from Virus_Scan.scheduler.workers.inmemory_worker_thread_progress import InMemoryWorkerThreadProgress

if TYPE_CHECKING:
    from Virus_Scan.scheduler.workers import inmemory_worker_job_contracts as job_contracts
    from Virus_Scan.scheduler.workers.inmemory_worker_lifecycle_evidence import (
        InMemoryWorkerLifecyclePublicationEvidence,
    )


def worker_job_cancel_output(
    request: object,
    deps: object,
) -> tuple[bool, object | None]:
    """Return a cancellation result before any running publication when requested."""
    cancel_requested_raw = deps.cancel_requested(request.cancel_table, request.job_id, request.generation)
    cancel_requested, _cancel_reason = scheduler_bool(
        cancel_requested_raw,
        reason="inmemory_worker_cancel_request_rejected",
    )
    if cancel_requested:
        return True, deps.cancel_result(request.path, "cancelled_before_start")
    return False, None


def publish_worker_running_state(
    request: object,
    deps: object,
    *,
    running_publication_evidence: Callable[..., object],
) -> InMemoryWorkerLifecyclePublicationEvidence | None:
    """Publish the running lifecycle row and preserve replayable failure evidence."""
    try:
        deps.result_put(
            (
                "running",
                request.job_id,
                request.path,
                os.getpid(),
                time.time(),
                request.generation,
                threading.get_ident(),
            )
        )
    except deps.recoverable_exceptions as suppressed_exc:
        try:
            deps.record_scheduler_suppressed("suppressed_exception", suppressed_exc)
            return running_publication_evidence(request, suppressed_exc)
        except deps.recoverable_exceptions as record_exc:
            return running_publication_evidence(request, suppressed_exc, report_exc=record_exc)
    return None


def execute_worker_scan_with_progress(
    request: object,
    deps: object,
    *,
    running_publication_failure: InMemoryWorkerLifecyclePublicationEvidence | None,
    annotate_thread_progress_heartbeat_failure: Callable[..., object],
    annotate_worker_lifecycle_publication_failure: Callable[..., object],
    build_worker_error_result_evidence: Callable[..., object],
) -> job_contracts.WorkerJobOutput:
    """Run the worker scan, annotate heartbeat/lifecycle evidence, and map errors."""
    try:
        thread_progress = deps.worker_thread_progress_type(
            cfg=dict(request.worker_config),
            job_id=request.job_id,
            generation=request.generation,
            cancel_table=request.cancel_table,
            heartbeat_table=request.heartbeat_table,
            heartbeat_flags=request.heartbeat_flags,
            completed_jobs=request.completed_jobs,
            task_meta=request.task_meta,
            cancel_requested=deps.cancel_requested,
            update_shared_heartbeat=deps.update_shared_heartbeat,
            record_heartbeat_failure=deps.record_scheduler_suppressed,
            recoverable_exceptions=deps.recoverable_exceptions,
        )
        local_cfg = dict(request.worker_config)
        local_cfg["progress_callback"] = thread_progress
        if thread_progress("start") is False:
            raise deps.cooperative_cancel_type("cancelled_at_start")
        if thread_progress("stage_budget_acquired") is False:
            raise deps.cooperative_cancel_type("cancelled_after_stage_budget")
        out = deps.scan_one_file(request.path, freeze_inmemory_worker_config(local_cfg))
        thread_progress("complete")
        output = out
        if type(thread_progress) is InMemoryWorkerThreadProgress:
            heartbeat_failure_count, _count_reason = scheduler_int(
                thread_progress.heartbeat_failure_count,
                minimum=0,
                reason="inmemory_worker_thread_progress_failure_count_rejected",
            )
            if heartbeat_failure_count:
                output = annotate_thread_progress_heartbeat_failure(
                    output,
                    thread_progress.last_heartbeat_failure,
                )
        return annotate_worker_lifecycle_publication_failure(output, running_publication_failure)
    except deps.recoverable_exceptions as exc:
        try:
            result = deps.worker_error_result(request.path, exc)
        except deps.recoverable_exceptions as error_result_exc:
            result = build_worker_error_result_evidence(
                request.path,
                exc,
                error_result_exc=error_result_exc,
            )
        return (request.path, annotate_worker_lifecycle_publication_failure(result, running_publication_failure))



__all__ = (
    "execute_worker_scan_with_progress",
    "publish_worker_running_state",
    "worker_job_cancel_output",
)
