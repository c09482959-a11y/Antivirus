"""Typed contracts for the in-memory timeout sweep orchestration boundary."""
from __future__ import annotations

from dataclasses import dataclass

from Virus_Scan.scheduler.queue.inmemory_lifecycle_requests import LifecycleRequestRecorder
from Virus_Scan.scheduler.timeout.inmemory_timeout_history_contract import TimeoutHistoryTransitionProvider
from typing import Callable, Mapping, Protocol, TypeAlias

TimeoutRecord: TypeAlias = dict[str, object]
TimeoutRecordView: TypeAlias = Mapping[str, object]
SweepJobRecords: TypeAlias = dict[object, TimeoutRecord]
SchedulerActiveRecords: TypeAlias = Mapping[object, object]
SchedulerTerminalSet: TypeAlias = set[object]
SchedulerWorkerTable: TypeAlias = dict[object, object]
SweepEvidenceRecord: TypeAlias = Mapping[str, object]
EwmaState: TypeAlias = dict[str, object]
TimeoutStartWaitBudget: TypeAlias = Callable[[Mapping[str, object], float], float]
TimeoutSuppressionRecorder: TypeAlias = Callable[[str, BaseException], object]
MonotonicClock: TypeAlias = Callable[[], int]
WallClock: TypeAlias = Callable[[], float]
StagePredicate: TypeAlias = Callable[[str], bool]
SweepCallback: TypeAlias = Callable[..., object]


@dataclass(slots=True)
class TimeoutSweepJobCounters:
    """Counters accumulated while evaluating only deadline-due live jobs."""

    evaluated: int = 0
    queued_waits: int = 0
    assigned_waits: int = 0
    hard_timeouts: int = 0
    orphaned_workers: int = 0
    progress_stalls: int = 0
    cancelled_after_stall: int = 0


@dataclass(frozen=True, slots=True)
class RunningProgressStallRequest:
    """Inputs for one running-worker progress-stall decision."""

    jid: object
    rec: TimeoutRecordView
    now: float
    pid: object
    progress_age: float
    budget_info: TimeoutRecordView
    recovery: object
    cancel_grace_sec: float
    stage_is_pre_execution: StagePredicate
    update_ewma: SweepCallback
    ewma_state: EwmaState
    timeout_retry_evidence: list[SweepEvidenceRecord]
    timeout_reporting_failures: list[SweepEvidenceRecord]
    record_scheduler_suppressed: TimeoutSuppressionRecorder
    recoverable_exceptions: tuple[type[BaseException], ...]


@dataclass(frozen=True, slots=True)
class SharedHeartbeatIngestionRequest:
    """Inputs for shared-heartbeat ingestion during one timeout sweep."""

    active_job_ids: tuple[int, ...]
    job_records: SweepJobRecords
    active: SchedulerActiveRecords
    terminal: SchedulerTerminalSet
    worker_heartbeats: SchedulerWorkerTable
    worker_metrics: SchedulerWorkerTable
    heartbeat_table: object
    heartbeat_flags: object
    read_heartbeat: SweepCallback
    cancel_job: SweepCallback
    lifecycle_recorder: LifecycleRequestRecorder
    heartbeat_ingester: SweepCallback
    monotonic_ns: MonotonicClock
    wall_time: WallClock
    record_scheduler_suppressed: TimeoutSuppressionRecorder
    recoverable_exceptions: tuple[type[BaseException], ...]
    timeout_reporting_failures: list[SweepEvidenceRecord]


@dataclass(frozen=True, slots=True)
class TimeoutSweepWallTimeFailureRequest:
    """Inputs required to materialize an explicit wall-clock failure result."""

    error: BaseException
    shared_heartbeat_result: object
    timeout_retry_evidence: tuple[SweepEvidenceRecord, ...]
    timeout_reporting_failures: list[SweepEvidenceRecord]
    record_scheduler_suppressed: TimeoutSuppressionRecorder
    recoverable_exceptions: tuple[type[BaseException], ...]


class SweepRecovery(TimeoutHistoryTransitionProvider, Protocol):
    """Recovery coordinator operations consumed by timeout sweep submodules."""

    def retry_or_fail(self, job_id: object, reason: str, *, pid: object | None = None) -> object: ...


__all__ = (
    "EwmaState",
    "MonotonicClock",
    "RunningProgressStallRequest",
    "SchedulerActiveRecords",
    "SchedulerTerminalSet",
    "SchedulerWorkerTable",
    "SharedHeartbeatIngestionRequest",
    "StagePredicate",
    "SweepCallback",
    "SweepEvidenceRecord",
    "SweepJobRecords",
    "SweepRecovery",
    "TimeoutRecord",
    "TimeoutRecordView",
    "TimeoutStartWaitBudget",
    "TimeoutSuppressionRecorder",
    "TimeoutSweepJobCounters",
    "TimeoutSweepWallTimeFailureRequest",
    "WallClock",
)
