"""Process-queue monitor stall escalation ownership."""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING

from Virus_Scan.scheduler.orchestration.process_queue_monitor_no_hook import (
    monitor_float,
    monitor_int,
    monitor_recoverable_exceptions,
)

from Virus_Scan.runtime.api import log_error
from Virus_Scan.scheduler.queue.issue_reporting import record_raw_queue_issue
from Virus_Scan.scheduler.queue.progress import (
    queue_file_has_recent_raw_owner_progress,
    queue_raw_stage_progress_recent,
)
from Virus_Scan.scheduler.internal.immutable_outputs import immutable_mapping, immutable_tuple
from Virus_Scan.scheduler.workers.process_liveness import check_process_queue_worker_liveness
from Virus_Scan.scheduler.workers.process_termination import terminate_queue_worker_pid
from Virus_Scan.scheduler.queue.process_queue_stale_recovery import (
    ProcessQueueStaleRecoveryDependencies,
    ProcessQueueStaleRecoveryRequest,
    reconcile_process_queue_stale_recovery,
)
from Virus_Scan.scheduler.workers.process_termination import terminate_process_queue_worker_handle
from Virus_Scan.scheduler.timeout.escalation_engine import (
    ProcessQueueStallEscalationDependencies,
    ProcessQueueStallEscalationRequest,
    terminate_stalled_process_queue_workers,
)

if TYPE_CHECKING:
    from Virus_Scan.scheduler.orchestration.process_queue_worker_pool_state import ProcessQueueParentWorkerPool
    from pathlib import Path


@dataclass(frozen=True)
class MonitorStallRequest:
    worker_pool: ProcessQueueParentWorkerPool
    live_workers: int
    file_active_count: int
    file_pending_count: int
    raw_live: int
    accounted_total: int
    last_accounted_total: int
    last_accounted_change_time: float
    now: float
    queue_progress_stall_sec: float
    queue_dir: Path
    raw_stage_progress_state: object
    recoverable_exceptions: tuple[type[BaseException], ...]

    def __post_init__(self) -> None:
        object.__setattr__(self, "live_workers", monitor_int(self.live_workers, default=0, minimum=0, reason="process_queue_stall_live_workers_rejected"))
        object.__setattr__(self, "file_active_count", monitor_int(self.file_active_count, default=0, minimum=0, reason="process_queue_stall_active_rejected"))
        object.__setattr__(self, "file_pending_count", monitor_int(self.file_pending_count, default=0, minimum=0, reason="process_queue_stall_pending_rejected"))
        object.__setattr__(self, "raw_live", monitor_int(self.raw_live, default=0, minimum=0, reason="process_queue_stall_raw_live_rejected"))
        object.__setattr__(self, "accounted_total", monitor_int(self.accounted_total, default=0, minimum=0, reason="process_queue_stall_accounted_rejected"))
        object.__setattr__(self, "last_accounted_total", monitor_int(self.last_accounted_total, default=0, minimum=0, reason="process_queue_stall_last_accounted_rejected"))
        object.__setattr__(self, "last_accounted_change_time", monitor_float(self.last_accounted_change_time, default=0.0, minimum=0.0, reason="process_queue_stall_last_change_rejected"))
        object.__setattr__(self, "now", monitor_float(self.now, default=0.0, minimum=0.0, reason="process_queue_stall_now_rejected"))
        object.__setattr__(self, "queue_progress_stall_sec", monitor_float(self.queue_progress_stall_sec, default=0.0, minimum=0.0, reason="process_queue_stall_threshold_rejected"))
        object.__setattr__(self, "raw_stage_progress_state", immutable_mapping(self.raw_stage_progress_state))
        object.__setattr__(self, "recoverable_exceptions", monitor_recoverable_exceptions(self.recoverable_exceptions))


@dataclass(frozen=True)
class MonitorStallResult:
    last_accounted_total: int
    last_accounted_change_time: float
    raw_stage_progress_state: object
    stall_escalation_evidence: tuple[object, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "raw_stage_progress_state", immutable_mapping(self.raw_stage_progress_state))
        object.__setattr__(self, "stall_escalation_evidence", immutable_tuple(self.stall_escalation_evidence))


def reconcile_monitor_stall(request: MonitorStallRequest) -> MonitorStallResult:
    raw_stage_progress_state = immutable_mapping(request.raw_stage_progress_state)
    last_accounted_change_time = request.last_accounted_change_time
    if request.accounted_total != request.last_accounted_total:
        return MonitorStallResult(
            last_accounted_total=monitor_int(request.accounted_total, default=0, minimum=0, reason="process_queue_stall_accounted_rejected"),
            last_accounted_change_time=monitor_float(request.now, default=0.0, minimum=0.0, reason="process_queue_stall_now_rejected"),
            raw_stage_progress_state=raw_stage_progress_state,
            stall_escalation_evidence=(),
        )
    if (
        request.live_workers
        and (request.file_active_count + request.file_pending_count + request.raw_live) > 0
        and (request.now - request.last_accounted_change_time) >= request.queue_progress_stall_sec
    ):
        stall_escalation_result = terminate_stalled_process_queue_workers(
            ProcessQueueStallEscalationRequest(
                procs=request.worker_pool.workers_tuple(),
                elapsed_sec=request.now - request.last_accounted_change_time,
            ),
            ProcessQueueStallEscalationDependencies(
                log_error=logging.error,
                record_issue=record_raw_queue_issue,
                sleep=time.sleep,
                worker_terminator=terminate_process_queue_worker_handle,
            ),
        )
        stale_recovery_output = reconcile_process_queue_stale_recovery(
            ProcessQueueStaleRecoveryRequest(
                queue_dir=request.queue_dir,
                stale_sec=1.0,
                progress_stall_sec=1.0,
                per_file_timeout_sec=1.0,
                raw_stage_progress_state=raw_stage_progress_state,
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
        last_accounted_change_time = request.now
        stall_evidence = tuple(stall_escalation_result.evidence)
    else:
        stall_evidence = ()
    return MonitorStallResult(
        last_accounted_total=monitor_int(request.last_accounted_total, default=0, minimum=0, reason="process_queue_stall_last_accounted_rejected"),
        last_accounted_change_time=monitor_float(last_accounted_change_time, default=0.0, minimum=0.0, reason="process_queue_stall_last_change_rejected"),
        raw_stage_progress_state=raw_stage_progress_state,
        stall_escalation_evidence=stall_evidence,
    )
