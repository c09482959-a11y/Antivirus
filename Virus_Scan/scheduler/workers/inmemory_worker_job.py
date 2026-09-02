from __future__ import annotations

from dataclasses import dataclass

from Virus_Scan.scheduler.internal.immutable_outputs import immutable_mapping
from Virus_Scan.scheduler.internal.no_hook_diagnostics import scheduler_int
from Virus_Scan.scheduler.internal.live_worker_config import freeze_inmemory_worker_config
from Virus_Scan.scheduler.workers.inmemory_worker_job_heartbeat import annotate_thread_progress_heartbeat_failure
from Virus_Scan.scheduler.workers.inmemory_worker_job_publication import running_publication_evidence
from Virus_Scan.scheduler.workers.inmemory_worker_job_steps import (
    execute_worker_scan_with_progress,
    publish_worker_running_state,
    worker_job_cancel_output,
)
from Virus_Scan.scheduler.workers.inmemory_worker_lifecycle_evidence import (
    annotate_worker_lifecycle_publication_failure,
    build_worker_error_result_evidence,
)
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from Virus_Scan.scheduler.workers import inmemory_worker_job_contracts as job_contracts

@dataclass(frozen=True)
class InMemoryWorkerJobExecutionDependencies:
    """Explicit dependencies for one in-memory worker job execution."""

    cancel_requested: job_contracts.CancelRequested
    cancel_result: job_contracts.CancelResult
    result_put: job_contracts.ResultPublisher
    worker_thread_progress_type: job_contracts.WorkerThreadProgressFactory
    scan_one_file: job_contracts.WorkerFileScanner
    worker_error_result: job_contracts.WorkerErrorResultBuilder
    update_shared_heartbeat: job_contracts.HeartbeatUpdater
    record_scheduler_suppressed: job_contracts.SuppressionRecorder
    cooperative_cancel_type: type[BaseException]
    recoverable_exceptions: tuple[type[BaseException], ...]

@dataclass(frozen=True)
class InMemoryWorkerJobExecutionRequest:
    """Immutable request for a single in-memory worker job."""

    job_id: int
    path: job_contracts.WorkerJobPath
    generation: int
    worker_config: job_contracts.WorkerConfigMapping
    cancel_table: object
    heartbeat_table: object
    heartbeat_flags: object
    completed_jobs: int
    task_meta: job_contracts.WorkerTaskMetadata | None = None

    def __post_init__(self) -> None:
        job_id, _job_reason = scheduler_int(
            self.job_id,
            minimum=0,
            reason="inmemory_worker_job_id_rejected",
        )
        generation, _generation_reason = scheduler_int(
            self.generation,
            minimum=0,
            reason="inmemory_worker_generation_rejected",
        )
        completed_jobs, _completed_reason = scheduler_int(
            self.completed_jobs,
            minimum=0,
            reason="inmemory_worker_completed_jobs_rejected",
        )
        worker_config_source = {} if self.worker_config is None else self.worker_config
        object.__setattr__(self, "job_id", job_id)
        object.__setattr__(self, "generation", generation)
        object.__setattr__(self, "completed_jobs", completed_jobs)
        object.__setattr__(self, "worker_config", freeze_inmemory_worker_config(worker_config_source))
        object.__setattr__(
            self,
            "task_meta",
            immutable_mapping(self.task_meta) if self.task_meta is not None else None,
        )

    @classmethod
    def build(
        cls,
        *,
        job_id: int,
        path: job_contracts.WorkerJobPath,
        attempt: int,
        worker_config: job_contracts.WorkerConfigMapping | None,
        cancel_table: object,
        heartbeat_table: object,
        heartbeat_flags: object,
        completed_jobs: int,
        task_meta: job_contracts.WorkerTaskMetadata | None,
    ) -> "InMemoryWorkerJobExecutionRequest":
        return cls(
            job_id=job_id,
            path=path,
            generation=attempt,
            worker_config={} if worker_config is None else worker_config,
            cancel_table=cancel_table,
            heartbeat_table=heartbeat_table,
            heartbeat_flags=heartbeat_flags,
            completed_jobs=completed_jobs,
            task_meta=task_meta,
        )


def execute_inmemory_worker_job(
    request: InMemoryWorkerJobExecutionRequest,
    deps: InMemoryWorkerJobExecutionDependencies,
) -> job_contracts.WorkerJobOutput:
    """Execute one in-memory scheduler worker job under worker ownership."""
    cancel_requested, cancel_output = worker_job_cancel_output(request, deps)
    if cancel_requested:
        return cancel_output

    running_publication_failure = publish_worker_running_state(
        request,
        deps,
        running_publication_evidence=running_publication_evidence,
    )
    return execute_worker_scan_with_progress(
        request,
        deps,
        running_publication_failure=running_publication_failure,
        annotate_thread_progress_heartbeat_failure=annotate_thread_progress_heartbeat_failure,
        annotate_worker_lifecycle_publication_failure=annotate_worker_lifecycle_publication_failure,
        build_worker_error_result_evidence=build_worker_error_result_evidence,
    )
