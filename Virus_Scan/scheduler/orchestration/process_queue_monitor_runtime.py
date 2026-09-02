"""Process-queue monitor runtime-state initialization ownership."""
from __future__ import annotations

import time
from dataclasses import dataclass

from Virus_Scan.exception_contracts import RECOVERABLE_RUNTIME_ERRORS as RAW_QUEUE_RECOVERABLE_EXCEPTIONS
from Virus_Scan.scheduler.timeout.process_queue_monitor_policy import process_queue_monitor_policy
from Virus_Scan.scheduler.runtime.env_policy import scheduler_environment_snapshot
from Virus_Scan.scheduler.internal.immutable_outputs import immutable_tuple


@dataclass(frozen=True)
class ProcessQueueMonitorRuntimeState:
    monitor_policy: object
    monitor_sleep_sec: float
    per_file_timeout_sec: float
    queue_progress_stall_sec: float
    last_accounted_total: int
    last_accounted_change_time: float
    idle_done_since: float | None
    last_integrity_repair_time: float
    last_monitor_heartbeat_time: float
    idle_grace_sec: float
    idle_notice_sec: float
    progress_interval_sec: float
    timeout_config_evidence: tuple[object, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "timeout_config_evidence", immutable_tuple(self.timeout_config_evidence))


def build_process_queue_monitor_runtime_state(*, configured_per_file_timeout_sec: float, env: object=None, current_time: object=time.time) -> ProcessQueueMonitorRuntimeState:
    env_mapping = scheduler_environment_snapshot(env)
    monitor_policy = process_queue_monitor_policy(
        env=env_mapping,
        configured_per_file_timeout_sec=configured_per_file_timeout_sec,
        recoverable_exceptions=RAW_QUEUE_RECOVERABLE_EXCEPTIONS,
    )
    per_file_timeout_sec = monitor_policy.per_file_timeout_sec
    idle_grace_sec = monitor_policy.idle_grace_sec
    return ProcessQueueMonitorRuntimeState(
        monitor_policy=monitor_policy,
        monitor_sleep_sec=monitor_policy.monitor_sleep_sec,
        per_file_timeout_sec=per_file_timeout_sec,
        queue_progress_stall_sec=monitor_policy.progress_stall_sec,
        last_accounted_total=-1,
        last_accounted_change_time=current_time(),
        idle_done_since=None,
        last_integrity_repair_time=0.0,
        last_monitor_heartbeat_time=current_time(),
        idle_grace_sec=idle_grace_sec,
        idle_notice_sec=min(30.0, max(2.0, idle_grace_sec)),
        progress_interval_sec=15.0,
        timeout_config_evidence=tuple(monitor_policy.timeout_config_evidence),
    )
