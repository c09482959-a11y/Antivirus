"""Process-queue startup integrity repair orchestration."""
from __future__ import annotations

from dataclasses import dataclass

from Virus_Scan.exception_contracts import RECOVERABLE_RUNTIME_ERRORS as RAW_QUEUE_RECOVERABLE_EXCEPTIONS
from Virus_Scan.runtime.api import log_error
from Virus_Scan.scheduler.queue.integrity_pipeline import queue_integrity_verify_and_repair
from Virus_Scan.scheduler.queue.issue_reporting import record_process_queue_suppressed
from Virus_Scan.scheduler.workers.process_liveness import check_process_queue_worker_liveness
from Virus_Scan.scheduler.internal.live_path_entries import freeze_live_scheduler_paths
from Virus_Scan.scheduler.queue.process_queue_integrity_repair import (
    ProcessQueueIntegrityRepairDependencies,
    ProcessQueueIntegrityRepairRequest,
    reconcile_process_queue_integrity_repair,
)
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path


@dataclass(frozen=True)
class ProcessQueueStartupIntegrityRequest:
    queue_dir: Path
    all_files: tuple[str, ...]

    def __post_init__(self) -> None:
        object.__setattr__(self, "all_files", freeze_live_scheduler_paths(self.all_files))


def repair_process_queue_startup_integrity(request: ProcessQueueStartupIntegrityRequest) -> None:
    reconcile_process_queue_integrity_repair(
        ProcessQueueIntegrityRepairRequest(
            queue_dir=request.queue_dir,
            all_files=tuple(request.all_files),
            phase="startup",
            repair=True,
        ),
        ProcessQueueIntegrityRepairDependencies(
            verify_and_repair=queue_integrity_verify_and_repair,
            log_error=log_error,
            report_suppressed=record_process_queue_suppressed,
            recoverable_exceptions=RAW_QUEUE_RECOVERABLE_EXCEPTIONS,
            active_claim_pid_is_alive=lambda worker_pid: check_process_queue_worker_liveness(
                worker_pid,
                record_suppressed=record_process_queue_suppressed,
            ).alive,
        ),
    )
