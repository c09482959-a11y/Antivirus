"""Process-queue monitor recovery and integrity orchestration ownership."""
from __future__ import annotations

import time
from dataclasses import dataclass
from typing import TYPE_CHECKING

from Virus_Scan.runtime.api import log_error
from Virus_Scan.scheduler.queue.integrity_pipeline import queue_integrity_verify_and_repair
from Virus_Scan.scheduler.queue.issue_reporting import record_process_queue_suppressed
from Virus_Scan.scheduler.queue.progress import (
    queue_file_has_recent_raw_owner_progress,
    queue_raw_stage_progress_recent,
)
from Virus_Scan.scheduler.internal.immutable_outputs import immutable_mapping, immutable_tuple
from Virus_Scan.scheduler.internal.live_path_entries import freeze_live_scheduler_paths
from Virus_Scan.scheduler.orchestration.process_queue_monitor_no_hook import (
    monitor_float,
    monitor_immutable_value,
    monitor_int,
    monitor_optional_float,
    monitor_recoverable_exceptions,
)
from Virus_Scan.scheduler.workers.process_snapshots import snapshot_active_process_queue_workers
from Virus_Scan.scheduler.workers.process_liveness import check_process_queue_worker_liveness
from Virus_Scan.scheduler.workers.process_termination import terminate_queue_worker_pid
from Virus_Scan.scheduler.queue.process_queue_integrity_repair import (
    ProcessQueueIntegrityRepairDependencies,
    ProcessQueueIntegrityRepairRequest,
    reconcile_process_queue_integrity_repair,
)
from Virus_Scan.scheduler.queue.process_queue_stale_recovery import (
    ProcessQueueStaleRecoveryDependencies,
    ProcessQueueStaleRecoveryRequest,
    reconcile_process_queue_stale_recovery,
)

if TYPE_CHECKING:
    from Virus_Scan.scheduler.orchestration.process_queue_worker_pool_state import ProcessQueueParentWorkerPool
    from pathlib import Path


@dataclass(frozen=True)
class MonitorRecoveryRequest:
    worker_pool: ProcessQueueParentWorkerPool
    queue_dir: Path
    all_files: tuple[str, ...]
    raw_stage_progress_state: object
    progress_stall_sec: float
    per_file_timeout_sec: float | None
    last_integrity_repair_time: float
    recoverable_exceptions: tuple[type[BaseException], ...]

    def __post_init__(self) -> None:
        object.__setattr__(self, "all_files", freeze_live_scheduler_paths(self.all_files))
        object.__setattr__(self, "raw_stage_progress_state", monitor_immutable_value(self.raw_stage_progress_state))
        object.__setattr__(self, "progress_stall_sec", monitor_float(self.progress_stall_sec, default=0.0, minimum=0.0, reason="process_queue_monitor_progress_stall_rejected"))
        object.__setattr__(self, "per_file_timeout_sec", monitor_optional_float(self.per_file_timeout_sec, default=None, minimum=0.0, reason="process_queue_monitor_per_file_timeout_rejected"))
        object.__setattr__(self, "last_integrity_repair_time", monitor_float(self.last_integrity_repair_time, default=0.0, minimum=0.0, reason="process_queue_monitor_integrity_repair_time_rejected"))
        object.__setattr__(self, "recoverable_exceptions", monitor_recoverable_exceptions(self.recoverable_exceptions))


@dataclass(frozen=True)
class MonitorRecoveryResult:
    live_workers: int
    raw_stage_progress_state: object
    last_integrity_repair_time: float
    stale_recovery_evidence: tuple[object, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "live_workers", monitor_int(self.live_workers, default=0, minimum=0, reason="process_queue_monitor_live_workers_rejected"))
        object.__setattr__(self, "raw_stage_progress_state", monitor_immutable_value(self.raw_stage_progress_state))
        object.__setattr__(self, "last_integrity_repair_time", monitor_float(self.last_integrity_repair_time, default=0.0, minimum=0.0, reason="process_queue_monitor_integrity_repair_time_rejected"))
        object.__setattr__(self, "stale_recovery_evidence", immutable_tuple(self.stale_recovery_evidence))


def recover_monitor_queue(request: MonitorRecoveryRequest) -> MonitorRecoveryResult:
    """Prune inactive workers, recover stale claims, and periodically repair queue integrity."""
    worker_snapshot = snapshot_active_process_queue_workers(
        request.worker_pool.workers_tuple(),
        recoverable_exceptions=request.recoverable_exceptions,
        report_suppressed=record_process_queue_suppressed,
    )
    live = worker_snapshot.live_count
    active_procs = worker_snapshot.active_processes
    if len(active_procs) != len(request.worker_pool.workers):
        request.worker_pool.replace_active_workers(tuple(active_procs))
    stale_recovery_output = reconcile_process_queue_stale_recovery(
        ProcessQueueStaleRecoveryRequest(
            queue_dir=request.queue_dir,
            progress_stall_sec=request.progress_stall_sec,
            per_file_timeout_sec=0.0 if request.per_file_timeout_sec is None else request.per_file_timeout_sec,
            raw_stage_progress_state=request.raw_stage_progress_state,
        ),
        ProcessQueueStaleRecoveryDependencies(
            raw_stage_progress_recent=queue_raw_stage_progress_recent,
            file_has_recent_raw_owner_progress=queue_file_has_recent_raw_owner_progress,
            worker_liveness_checker=check_process_queue_worker_liveness,
            worker_terminator=terminate_queue_worker_pid,
            log_error=log_error,
            recoverable_exceptions=request.recoverable_exceptions,
        ),
    )
    raw_stage_progress_state = immutable_mapping(stale_recovery_output.raw_stage_progress_state)
    last_integrity_repair_time = request.last_integrity_repair_time
    now_for_integrity = time.time()
    if (now_for_integrity - last_integrity_repair_time) >= 60.0:
        if reconcile_process_queue_integrity_repair(
            ProcessQueueIntegrityRepairRequest(
                queue_dir=request.queue_dir,
                all_files=tuple(request.all_files),
                phase="monitor",
                repair=True,
            ),
            ProcessQueueIntegrityRepairDependencies(
                verify_and_repair=queue_integrity_verify_and_repair,
                log_error=log_error,
                report_suppressed=record_process_queue_suppressed,
                recoverable_exceptions=request.recoverable_exceptions,
                active_claim_pid_is_alive=lambda worker_pid: check_process_queue_worker_liveness(
                    worker_pid,
                    record_suppressed=record_process_queue_suppressed,
                ).alive,
            ),
        ):
            last_integrity_repair_time = now_for_integrity
    return MonitorRecoveryResult(
        live_workers=live,
        raw_stage_progress_state=raw_stage_progress_state,
        last_integrity_repair_time=last_integrity_repair_time,
        stale_recovery_evidence=immutable_tuple(stale_recovery_output.evidence),
    )
