"""Immutable scheduler loop guard contracts."""
from __future__ import annotations
from dataclasses import dataclass
from typing import Mapping

from Virus_Scan.scheduler.internal.immutable_outputs import immutable_tuple
from Virus_Scan.scheduler.internal.no_hook_attrs import scheduler_exact_attr
from Virus_Scan.scheduler.runtime.loop_guard_values import (
    guard_float,
    guard_int,
    guard_text,
)

@dataclass(frozen=True, slots=True)
class SchedulerLoopGuard:
    loop_name: str
    max_iterations: int
    max_no_progress_iterations: int
    max_wall_time_sec: float
    no_progress_reason: str
    config_evidence: tuple[Mapping[str, object], ...] = ()

    def __post_init__(self) -> None:
        evidence = tuple(self.config_evidence) if type(self.config_evidence) is tuple else ()
        loop_name, issue = guard_text(
            self.loop_name, field_name="loop_name", default_value="scheduler_loop"
        )
        evidence += issue
        max_iterations, issue = guard_int(
            self.max_iterations,
            field_name="max_iterations",
            default_value=1,
            minimum=1,
        )
        evidence += issue
        max_no_progress, issue = guard_int(
            self.max_no_progress_iterations,
            field_name="max_no_progress_iterations",
            default_value=1,
            minimum=1,
        )
        evidence += issue
        max_wall_time, issue = guard_float(
            self.max_wall_time_sec,
            field_name="max_wall_time_sec",
            default_value=0.0,
        )
        evidence += issue
        no_progress_reason, issue = guard_text(
            self.no_progress_reason,
            field_name="no_progress_reason",
            default_value="scheduler_loop_no_progress",
        )
        evidence += issue
        object.__setattr__(self, "loop_name", loop_name)
        object.__setattr__(self, "max_iterations", max_iterations)
        object.__setattr__(self, "max_no_progress_iterations", max_no_progress)
        object.__setattr__(self, "max_wall_time_sec", max_wall_time)
        object.__setattr__(self, "no_progress_reason", no_progress_reason)
        object.__setattr__(self, "config_evidence", immutable_tuple(evidence))

    @classmethod
    def for_monitor(
        cls, *, total_work: int, sleep_sec: float, per_item_timeout_sec: float
    ) -> "SchedulerLoopGuard":
        work, work_issue = guard_int(
            total_work, field_name="total_work", default_value=1, minimum=1
        )
        sleep, sleep_issue = guard_float(
            sleep_sec, field_name="sleep_sec", default_value=0.01
        )
        item_timeout, timeout_issue = guard_float(
            per_item_timeout_sec,
            field_name="per_item_timeout_sec",
            default_value=30.0,
        )
        sleep, item_timeout = max(0.01, sleep), max(30.0, item_timeout)
        no_progress = max(64, int((item_timeout / sleep) * 2))
        return cls(
            "process_queue_monitor",
            max(512, no_progress * work * 2),
            no_progress,
            max(300.0, item_timeout * work * 4.0),
            "queue_drain_stalled",
            work_issue + sleep_issue + timeout_issue,
        )

    @classmethod
    def for_inmemory_parent(
        cls, *, total_work: int, per_item_timeout_sec: float
    ) -> "SchedulerLoopGuard":
        work, work_issue = guard_int(
            total_work, field_name="total_work", default_value=1, minimum=1
        )
        timeout, timeout_issue = guard_float(
            per_item_timeout_sec,
            field_name="per_item_timeout_sec",
            default_value=30.0,
        )
        timeout = max(30.0, timeout)
        return cls(
            "inmemory_parent_loop",
            max(512, work * 4096),
            max(128, work * 256),
            max(300.0, timeout * work * 4.0),
            "parent_loop_stalled",
            work_issue + timeout_issue,
        )

    @classmethod
    def for_inmemory_worker(
        cls, *, max_jobs_per_worker: int, heartbeat_interval: float
    ) -> "SchedulerLoopGuard":
        jobs, jobs_issue = guard_int(
            max_jobs_per_worker,
            field_name="max_jobs_per_worker",
            default_value=1,
            minimum=1,
        )
        heartbeat, heartbeat_issue = guard_float(
            heartbeat_interval,
            field_name="heartbeat_interval",
            default_value=0.1,
        )
        heartbeat = max(0.1, heartbeat)
        return cls(
            "inmemory_worker_loop",
            max(1024, jobs * 4096),
            max(128, int((heartbeat * 60.0) / 0.02)),
            max(300.0, jobs * max(heartbeat, 1.0) * 240.0),
            "worker_loop_stalled",
            jobs_issue + heartbeat_issue,
        )

@dataclass(frozen=True, slots=True)
class SchedulerLoopGuardState:
    iteration_count: int
    no_progress_iterations: int
    last_progress_total: int
    start_time: float
    last_progress_time: float
    input_evidence: tuple[Mapping[str, object], ...] = ()

    def __post_init__(self) -> None:
        evidence = tuple(self.input_evidence) if type(self.input_evidence) is tuple else ()
        for field_name in (
            "iteration_count",
            "no_progress_iterations",
            "last_progress_total",
        ):
            parsed_int, int_issue = guard_int(
                scheduler_exact_attr(self, field_name, owner_type=SchedulerLoopGuardState),
                field_name=field_name,
                default_value=0,
            )
            object.__setattr__(self, field_name, parsed_int)
            evidence += int_issue
        for field_name in ("start_time", "last_progress_time"):
            parsed_float, float_issue = guard_float(
                scheduler_exact_attr(self, field_name, owner_type=SchedulerLoopGuardState),
                field_name=field_name,
                default_value=0.0,
            )
            object.__setattr__(self, field_name, parsed_float)
            evidence += float_issue
        object.__setattr__(self, "input_evidence", immutable_tuple(evidence))

    @classmethod
    def start(
        cls, *, now: float, progress_total: int = 0
    ) -> "SchedulerLoopGuardState":
        progress, progress_issue = guard_int(
            progress_total, field_name="progress_total", default_value=0
        )
        current_time, time_issue = guard_float(now, field_name="now", default_value=0.0)
        return cls(
            0,
            0,
            progress,
            current_time,
            current_time,
            progress_issue + time_issue,
        )

@dataclass(frozen=True, slots=True)
class SchedulerLoopGuardDecision:
    state: SchedulerLoopGuardState
    exhausted: bool
    reason: str
    evidence: Mapping[str, object] | None = None

__all__ = (
    "SchedulerLoopGuard",
    "SchedulerLoopGuardDecision",
    "SchedulerLoopGuardState",
)
