"""Process queue-child mode orchestration ownership.

Queue-child workers consume process-queue jobs, publish durable worker output, run
raw-stage jobs, maintain claim heartbeats, and finalize claims.  This module owns
that child-mode orchestration so the scheduler pipeline only selects the mode and
receives an immutable result mapping.
"""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING

from Virus_Scan.contracts.scan_session_snapshot import ScanSessionSnapshot
from Virus_Scan.core.cache import bulk_scan_maintenance
from Virus_Scan.core.logging import log_bulk_progress
from Virus_Scan.runtime.api import log_error
from Virus_Scan.runtime.api import record_suppressed_failure
from Virus_Scan.reporting.result_schema import write_queue_file_result
from Virus_Scan.scheduler.context.inmemory_raw_dependency_factory import execute_inmemory_raw_stage_job
from Virus_Scan.scheduler.queue.claim import claim_process_queue_job
from Virus_Scan.scheduler.queue.claim_heartbeat import umige_update_claim_heartbeat
from Virus_Scan.scheduler.queue.child_job_finalization import append_child_raw_stage_result, finish_child_process_queue_job
from Virus_Scan.scheduler.workers.child_result_publication import (
    WorkerOutputFinalizeRequest,
    finalize_worker_output,
)
from Virus_Scan.scheduler.workers.process_queue_child_job import ProcessQueueChildJobRequest, process_queue_child_job
from Virus_Scan.scheduler.internal.immutable_outputs import immutable_mapping

if TYPE_CHECKING:
    from pathlib import Path
    from collections.abc import Callable, Mapping


@dataclass(frozen=True)
class ProcessQueueChildModeRequest:
    work_queue_dir: str | Path | None
    worker_output_path: str | Path | None
    total_files: int
    scan_started_at: float
    progress_every: int
    throttle_sec: float
    worker: Callable[[str, str, bool], tuple[str, Mapping[str, object]]]
    scan_session_snapshot: ScanSessionSnapshot

    def __post_init__(self) -> None:
        if type(self.scan_session_snapshot) is not ScanSessionSnapshot:
            raise TypeError("process_queue_child_scan_session_snapshot_required")


@dataclass(frozen=True)
class ProcessQueueChildModeResult:
    results: Mapping[str, object]

    def __post_init__(self) -> None:
        object.__setattr__(self, "results", immutable_mapping(self.results))


def run_process_queue_child_mode(request: ProcessQueueChildModeRequest) -> ProcessQueueChildModeResult:
    """Run queue-child orchestration while worker-owned modules process claims."""

    logging.info("bulk scan scheduler=process-queue-child workers=1 global-raw-work-stealing=off")
    done_count = 0
    child_results: dict[str, object] = {}
    while True:
        job, claim_path = claim_process_queue_job(request.work_queue_dir, worker_id="umige") if request.work_queue_dir else (None, None)
        if not job:
            break
        child_result = process_queue_child_job(
            ProcessQueueChildJobRequest(
                work_queue_dir=request.work_queue_dir,
                worker_output_path=request.worker_output_path,
                total_files=request.total_files,
                scan_started_at=request.scan_started_at,
                progress_every=request.progress_every,
                throttle_sec=request.throttle_sec,
                worker=request.worker,
                job=job,
                claim_path=claim_path,
                claim_heartbeat_update=umige_update_claim_heartbeat,
                finish_process_queue_job=finish_child_process_queue_job,
                write_queue_file_result=write_queue_file_result,
                append_raw_stage_result=lambda job, raw_result: append_child_raw_stage_result(request.work_queue_dir, job, raw_result),
                execute_raw_stage_job=lambda job: execute_inmemory_raw_stage_job(dict(job)),
                bulk_scan_maintenance=bulk_scan_maintenance,
                log_bulk_progress=log_bulk_progress,
                sleep=time.sleep,
                log_error=log_error,
                record_heartbeat_failure=lambda label, exc: record_suppressed_failure(label, exc, domain="runtime"),
                done_count=done_count,
                child_results=child_results,
            )
        )
        done_count = child_result.done_count
    finalize_worker_output(
        WorkerOutputFinalizeRequest(
            worker_output_path=request.worker_output_path,
            child_results=child_results,
            context="process_queue_child.worker_output_final",
            report=lambda label, failure: record_suppressed_failure(
                label,
                failure,
                domain="scheduler",
            ),
        )
    )
    return ProcessQueueChildModeResult(results=dict(child_results))
