"""Idle process-queue terminal accounting owner.

This module owns the parent-side decision for idle process-queue finalization.
The execution loop supplies an immutable observation of queue progress and receives
an immutable output describing whether execution should stop and whether terminal
accounting introduced an error.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from Virus_Scan.scheduler.internal.immutable_outputs import immutable_tuple
from Virus_Scan.scheduler.internal.no_hook_diagnostics import scheduler_bool, scheduler_float, scheduler_int
from Virus_Scan.scheduler.queue.process_queue_finalization_decisions import idle_optional_float_decision
from Virus_Scan.scheduler.queue.process_queue_idle_finalization_steps import (
    completed_accounting_idle_decision,
    missing_accounting_idle_decision,
)
from Virus_Scan.scheduler.internal.live_path_entries import freeze_live_scheduler_paths



def _idle_optional_float(value: object, *, reason: str) -> float | None:
    return idle_optional_float_decision(value, reason=reason).as_value()


@dataclass(frozen=True)
class ProcessQueueIdleFinalizationRequest:
    feed_complete: bool
    no_live_queue_work: bool
    accounted_files: int
    total_files: int
    idle_done_since: float | None
    now: float
    idle_grace_sec: float
    idle_notice_sec: float
    all_files: tuple[object, ...]
    queue_dir: object
    outputs_dir: object
    procs: tuple[object, ...]
    live_workers: int

    def __post_init__(self) -> None:
        object.__setattr__(self, "feed_complete", scheduler_bool(self.feed_complete, default=False, reason="idle_feed_complete_rejected")[0])
        object.__setattr__(self, "no_live_queue_work", scheduler_bool(self.no_live_queue_work, default=False, reason="idle_no_live_queue_work_rejected")[0])
        object.__setattr__(self, "accounted_files", scheduler_int(self.accounted_files, default=0, minimum=0, reason="idle_accounted_files_rejected")[0])
        object.__setattr__(self, "total_files", scheduler_int(self.total_files, default=0, minimum=0, reason="idle_total_files_rejected")[0])
        object.__setattr__(self, "idle_done_since", _idle_optional_float(self.idle_done_since, reason="idle_done_since_rejected"))
        object.__setattr__(self, "now", scheduler_float(self.now, default=0.0, minimum=0.0, reason="idle_now_rejected")[0])
        object.__setattr__(self, "idle_grace_sec", scheduler_float(self.idle_grace_sec, default=0.0, minimum=0.0, reason="idle_grace_rejected")[0])
        object.__setattr__(self, "idle_notice_sec", scheduler_float(self.idle_notice_sec, default=0.0, minimum=0.0, reason="idle_notice_rejected")[0])
        object.__setattr__(self, "all_files", freeze_live_scheduler_paths(self.all_files))
        object.__setattr__(self, "procs", immutable_tuple(self.procs))
        object.__setattr__(self, "live_workers", scheduler_int(self.live_workers, default=0, minimum=0, reason="idle_live_workers_rejected")[0])


@dataclass(frozen=True)
class ProcessQueueIdleFinalizationDependencies:
    load_queue_file_results: Callable[..., object]
    worker_error_result: Callable[..., object]
    terminate_worker: Callable[..., object]
    report: Callable[..., object]
    log_error: Callable[..., object]
    log_info: Callable[..., object]
    sleep: Callable[[float], object]
    idle_queue_finalization_request_factory: Callable[..., object]
    idle_queue_finalization_request_owner: Callable[[object], tuple[bool, float]]


@dataclass(frozen=True)
class ProcessQueueIdleFinalizationOutput:
    idle_done_since: float | None
    idle_notice_sec: float
    had_error: bool
    should_stop: bool

    def __post_init__(self) -> None:
        object.__setattr__(self, "idle_done_since", _idle_optional_float(self.idle_done_since, reason="idle_output_done_since_rejected"))
        object.__setattr__(self, "idle_notice_sec", scheduler_float(self.idle_notice_sec, default=0.0, minimum=0.0, reason="idle_output_notice_rejected")[0])
        object.__setattr__(self, "had_error", scheduler_bool(self.had_error, default=True, reason="idle_output_had_error_rejected")[0])
        object.__setattr__(self, "should_stop", scheduler_bool(self.should_stop, default=False, reason="idle_output_should_stop_rejected")[0])


def reconcile_process_queue_idle_finalization(
    request: ProcessQueueIdleFinalizationRequest,
    dependencies: ProcessQueueIdleFinalizationDependencies,
) -> ProcessQueueIdleFinalizationOutput:
    """Apply deterministic terminal-accounting decisions for an idle queue."""
    if type(request) is not ProcessQueueIdleFinalizationRequest:
        return ProcessQueueIdleFinalizationOutput(
            idle_done_since=None,
            idle_notice_sec=0.0,
            had_error=True,
            should_stop=False,
        )
    if type(dependencies) is not ProcessQueueIdleFinalizationDependencies:
        return ProcessQueueIdleFinalizationOutput(
            idle_done_since=request.idle_done_since,
            idle_notice_sec=request.idle_notice_sec,
            had_error=True,
            should_stop=False,
        )
    idle_done_since = request.idle_done_since
    idle_notice_sec = request.idle_notice_sec
    had_error = False
    should_stop = False

    if request.feed_complete and request.no_live_queue_work and request.accounted_files < request.total_files:
        idle_done_since, had_error, should_stop = missing_accounting_idle_decision(
            request=request,
            dependencies=dependencies,
            idle_done_since=idle_done_since,
            coerce_missing_had_error=lambda value: scheduler_bool(
                value,
                default=True,
                reason="idle_missing_had_error_rejected",
            )[0],
            coerce_missing_terminated=lambda value: scheduler_bool(
                value,
                default=False,
                reason="idle_missing_terminated_rejected",
            )[0],
        )
    elif request.no_live_queue_work and request.accounted_files >= request.total_files:
        idle_done_since, idle_notice_sec, should_stop = completed_accounting_idle_decision(
            request=request,
            dependencies=dependencies,
            idle_done_since=idle_done_since,
            idle_notice_sec=idle_notice_sec,
            coerce_terminated=lambda value: scheduler_bool(
                value,
                default=False,
                reason="idle_terminated_rejected",
            )[0],
        )
    else:
        idle_done_since = None

    return ProcessQueueIdleFinalizationOutput(
        idle_done_since=idle_done_since,
        idle_notice_sec=idle_notice_sec,
        had_error=had_error,
        should_stop=should_stop,
    )


__all__ = (
    "ProcessQueueIdleFinalizationDependencies",
    "ProcessQueueIdleFinalizationOutput",
    "ProcessQueueIdleFinalizationRequest",
    "reconcile_process_queue_idle_finalization",
)
