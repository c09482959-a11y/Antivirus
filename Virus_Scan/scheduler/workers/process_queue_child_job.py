"""Worker-owned process-queue child job lifecycle.

This module owns the per-claimed-job worker lifecycle for process-queue child
mode: claim heartbeat start/stop, worker invocation, durable worker failure
metadata, aggregate worker-output publication, and claim finalization.  The
orchestration layer only claims the next job and repeats this bounded lifecycle.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from Virus_Scan.exception_contracts import RECOVERABLE_RUNTIME_ERRORS
from Virus_Scan.scheduler.workers.claim_heartbeat import start_worker_claim_heartbeat
from Virus_Scan.scheduler.workers.process_queue_child_failure_contracts import ChildLoopFailureRequest
from Virus_Scan.scheduler.workers.process_queue_child_failure import record_child_loop_failure
from Virus_Scan.scheduler.workers.process_queue_child_heartbeat_boundary import stop_process_queue_child_heartbeat
from Virus_Scan.scheduler.internal.immutable_outputs import immutable_mapping
from Virus_Scan.scheduler.workers.no_hook_scalars import worker_float, worker_int
from Virus_Scan.scheduler.workers.process_queue_child_job_steps import run_process_queue_child_job_body

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping, MutableMapping
    from pathlib import Path


@dataclass(frozen=True)
class ProcessQueueChildJobRequest:
    work_queue_dir: str | Path | None
    worker_output_path: str | Path | None
    total_files: int
    scan_started_at: float
    progress_every: int
    throttle_sec: float
    worker: Callable[[str, str, bool], tuple[str, Mapping[str, object]]]
    job: Mapping[str, object]
    claim_path: object
    claim_heartbeat_update: Callable[..., bool]
    finish_process_queue_job: Callable[..., object]
    write_queue_file_result: Callable[[object, object, object, Mapping[str, object]], object]
    append_raw_stage_result: Callable[[Mapping[str, object], Mapping[str, object]], object]
    execute_raw_stage_job: Callable[[Mapping[str, object]], Mapping[str, object]]
    bulk_scan_maintenance: Callable[[int], object]
    log_bulk_progress: Callable[..., object]
    sleep: Callable[[float], object]
    log_error: Callable[[str], object]
    record_heartbeat_failure: Callable[[str, BaseException], object]
    done_count: int
    child_results: MutableMapping[str, object]

    def __post_init__(self) -> None:
        total_files = worker_int(self.total_files, minimum=0)[0]
        progress_every = worker_int(self.progress_every, minimum=0)[0]
        throttle_sec = worker_float(self.throttle_sec, minimum=0.0)[0]
        done_count = worker_int(self.done_count, minimum=0)[0]
        object.__setattr__(self, "total_files", total_files)
        object.__setattr__(self, "progress_every", progress_every)
        object.__setattr__(self, "throttle_sec", throttle_sec)
        object.__setattr__(self, "done_count", done_count)
        object.__setattr__(self, "job", immutable_mapping(self.job))


@dataclass(frozen=True)
class ProcessQueueChildJobResult:
    done_count: int


def process_queue_child_job(request: ProcessQueueChildJobRequest) -> ProcessQueueChildJobResult:
    """Run one claimed process-queue child job and finalize its claim."""
    ok = False
    failure_info: dict[str, object] | None = None
    hb_handle = None
    done_count = request.done_count
    job = request.job
    try:
        hb_handle = start_worker_claim_heartbeat(
            request.claim_path,
            job=job,
            worker_id="umige",
            update_callback=request.claim_heartbeat_update,
        )
        outcome = run_process_queue_child_job_body(request, job=job, done_count=done_count)
        ok = outcome.ok
        failure_info = outcome.failure_info
        done_count = outcome.done_count
    except RECOVERABLE_RUNTIME_ERRORS as exc:
        done_count, failure_info = record_child_loop_failure(
            ChildLoopFailureRequest(
                job=request.job,
                child_results=request.child_results,
                worker_output_path=request.worker_output_path,
                queue_dir=request.work_queue_dir,
                claim_path=request.claim_path,
                write_result=request.write_queue_file_result,
                log_error=request.log_error,
                exc=exc,
                done_count=done_count,
            )
        )
        ok = False
    finally:
        heartbeat_status = stop_process_queue_child_heartbeat(
            hb_handle,
            join_timeout=1.0,
            failure_recorder=request.record_heartbeat_failure,
        )
        if heartbeat_status.get("alive"):
            request.log_error("queue-child heartbeat thread remained alive after shutdown signal")
        request.finish_process_queue_job(
            request.work_queue_dir,
            request.claim_path,
            ok=ok,
            error_info=failure_info,
            job=job,
        )
    return ProcessQueueChildJobResult(done_count=done_count)


__all__ = ("ProcessQueueChildJobRequest", "ProcessQueueChildJobResult", "process_queue_child_job")
