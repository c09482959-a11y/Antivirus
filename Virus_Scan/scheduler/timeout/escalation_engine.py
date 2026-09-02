"""Process-queue timeout escalation ownership.

This module owns process-queue stall termination/kill escalation decisions and
returns immutable evidence for degraded escalation reporting. Hard per-file
signal timeout enforcement is owned only by scheduler.timeout.longtask_controller.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Mapping

from Virus_Scan.scheduler.internal.immutable_outputs import immutable_tuple
from Virus_Scan.scheduler.internal.live_worker_entries import freeze_live_worker_entries
from Virus_Scan.scheduler.timeout.process_queue_stall_reporting import (
    pid_for_process,
    termination_result_snapshot,
)
from Virus_Scan.scheduler.timeout.escalation_engine_support import (
    apply_worker_escalation_action,
    record_progress_stall_log,
    sleep_before_kill_escalation,
)


@dataclass(frozen=True)
class ProcessQueueStallEscalationRequest:
    procs: tuple[tuple[object, object, object, object], ...]
    elapsed_sec: float

    def __post_init__(self) -> None:
        object.__setattr__(self, "procs", freeze_live_worker_entries(self.procs))


@dataclass(frozen=True)
class ProcessQueueStallEscalationDependencies:
    log_error: Callable[[str], None]
    record_issue: Callable[..., None]
    sleep: Callable[[float], None]
    worker_terminator: Callable[..., object]


@dataclass(frozen=True)
class ProcessQueueStallEscalationResult:
    terminated: int
    killed: int
    evidence: tuple[Mapping[str, object], ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "evidence", immutable_tuple(self.evidence))


def _termination_snapshot_for_process(result: object, proc: object) -> Mapping[str, object]:
    return termination_result_snapshot(result, replacement_pid=pid_for_process(proc))


def terminate_stalled_process_queue_workers(
    request: ProcessQueueStallEscalationRequest,
    deps: ProcessQueueStallEscalationDependencies,
) -> ProcessQueueStallEscalationResult:
    """Terminate and then kill live process-queue workers after progress stall.

    Timeout escalation owns the kill decision. Queue recovery/reclaim remains with
    reconciliation and is intentionally performed by the caller after this
    escalation step completes.
    """
    evidence_records: list[Mapping[str, object]] = []
    record_progress_stall_log(
        request=request,
        deps=deps,
        evidence_records=evidence_records,
    )
    terminated = apply_worker_escalation_action(
        request=request,
        deps=deps,
        evidence_records=evidence_records,
        action="terminate",
        failure_stage="process_queue_stall_worker_terminate_failed",
        termination_snapshot_for_process=_termination_snapshot_for_process,
    )
    sleep_before_kill_escalation(
        request=request,
        deps=deps,
        evidence_records=evidence_records,
    )
    killed = apply_worker_escalation_action(
        request=request,
        deps=deps,
        evidence_records=evidence_records,
        action="kill",
        failure_stage="process_queue_stall_worker_kill_failed",
        termination_snapshot_for_process=_termination_snapshot_for_process,
    )
    return ProcessQueueStallEscalationResult(
        terminated=terminated,
        killed=killed,
        evidence=tuple(evidence_records),
    )
