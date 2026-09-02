"""Worker-owned dependency assembly for in-memory job execution."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, cast, TYPE_CHECKING

from Virus_Scan.scheduler.workers.heartbeat import UmigeCooperativeCancel, cooperative_cancel_requested, update_shared_heartbeat
from Virus_Scan.scheduler.workers.inmemory_file_scan import execute_inmemory_scan_one_file
from Virus_Scan.scheduler.workers.inmemory_worker_job import InMemoryWorkerJobExecutionDependencies
from Virus_Scan.scheduler.workers.inmemory_worker_thread_progress import InMemoryWorkerThreadProgress
from Virus_Scan.scheduler.workers.result_contracts import make_scheduler_cancel_result, make_scheduler_worker_error_result

if TYPE_CHECKING:
    from Virus_Scan.scheduler.workers.inmemory_worker_job_contracts import WorkerThreadProgressFactory


@dataclass(frozen=True, slots=True)
class InMemoryWorkerJobDependenciesEvidence:
    """Immutable evidence describing assembled worker job dependencies."""

    cancel_contract: str
    scan_contract: str
    heartbeat_contract: str
    result_contract: str


def build_inmemory_worker_job_dependencies(
    *,
    result_put: Callable[[tuple[object, ...]], object],
    record_scheduler_suppressed: Callable[[str, BaseException], object],
    recoverable_exceptions: tuple[type[BaseException], ...],
) -> tuple[InMemoryWorkerJobExecutionDependencies, InMemoryWorkerJobDependenciesEvidence]:
    """Assemble the canonical in-memory worker job dependency contract."""

    deps = InMemoryWorkerJobExecutionDependencies(
        cancel_requested=cooperative_cancel_requested,
        cancel_result=make_scheduler_cancel_result,
        result_put=result_put,
        worker_thread_progress_type=cast("WorkerThreadProgressFactory", InMemoryWorkerThreadProgress),
        scan_one_file=execute_inmemory_scan_one_file,
        worker_error_result=make_scheduler_worker_error_result,
        update_shared_heartbeat=update_shared_heartbeat,
        record_scheduler_suppressed=record_scheduler_suppressed,
        cooperative_cancel_type=UmigeCooperativeCancel,
        recoverable_exceptions=recoverable_exceptions,
    )
    evidence = InMemoryWorkerJobDependenciesEvidence(
        cancel_contract="worker_cancel_result",
        scan_contract="worker_file_scan",
        heartbeat_contract="worker_heartbeat_progress",
        result_contract="worker_error_result",
    )
    return deps, evidence


__all__ = ("InMemoryWorkerJobDependenciesEvidence", "build_inmemory_worker_job_dependencies")
