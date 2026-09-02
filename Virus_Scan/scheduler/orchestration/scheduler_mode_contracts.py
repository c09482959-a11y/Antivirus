"""Immutable contracts for canonical scheduler-mode dispatch."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from Virus_Scan.contracts.scan_session_snapshot import ScanSessionSnapshot
from Virus_Scan.scheduler.internal.live_path_entries import freeze_live_scheduler_paths
from Virus_Scan.scheduler.internal.no_hook_diagnostics import (
    scheduler_bool,
    scheduler_float,
    scheduler_int,
)

@dataclass(frozen=True)
class SchedulerModeDispatchRequest:
    scheduler: str
    workers: int
    root: object
    all_files: tuple[object, ...]
    total_files: int
    scan_started_at: float
    strict: bool
    yara_enabled: bool
    progress_every: int
    throttle_sec: float
    partial_output_path: object
    partial_output_every: int
    slow_file_warn_sec: float
    per_file_timeout_sec: float
    work_queue_dir: object
    worker_output_path: object
    scan_session_snapshot: ScanSessionSnapshot
    def __post_init__(self) -> None:
        total_files, total_reason = scheduler_int(
            self.total_files,
            default=0,
            minimum=0,
            reason="scheduler_dispatch_total_files_rejected",
        )
        scan_started_at, started_reason = scheduler_float(
            self.scan_started_at,
            default=0.0,
            minimum=0.0,
            reason="scheduler_dispatch_started_at_rejected",
        )
        strict, strict_reason = scheduler_bool(
            self.strict,
            default=False,
            reason="scheduler_dispatch_strict_rejected",
        )
        yara_enabled, yara_reason = scheduler_bool(
            self.yara_enabled,
            default=True,
            reason="scheduler_dispatch_yara_enabled_rejected",
        )
        progress_every, progress_reason = scheduler_int(
            self.progress_every,
            default=10,
            minimum=1,
            reason="scheduler_dispatch_progress_every_rejected",
        )
        throttle_sec, throttle_reason = scheduler_float(
            self.throttle_sec,
            default=0.0,
            minimum=0.0,
            reason="scheduler_dispatch_throttle_rejected",
        )
        partial_output_every, partial_reason = scheduler_int(
            self.partial_output_every,
            default=10,
            minimum=0,
            reason="scheduler_dispatch_partial_every_rejected",
        )
        slow_file_warn_sec, slow_reason = scheduler_float(
            self.slow_file_warn_sec,
            default=2.0,
            minimum=0.0,
            reason="scheduler_dispatch_slow_warn_rejected",
        )
        per_file_timeout_sec, timeout_reason = scheduler_float(
            self.per_file_timeout_sec,
            default=20.0,
            minimum=0.0,
            reason="scheduler_dispatch_timeout_rejected",
        )
        reasons = tuple(
            reason
            for reason in (
                total_reason, started_reason, strict_reason, yara_reason, progress_reason,
                throttle_reason, partial_reason, slow_reason, timeout_reason,
            )
            if reason
        )
        if reasons:
            raise ValueError(",".join(reasons))
        object.__setattr__(self, "all_files", freeze_live_scheduler_paths(self.all_files))
        object.__setattr__(self, "total_files", total_files)
        object.__setattr__(self, "scan_started_at", scan_started_at)
        object.__setattr__(self, "strict", strict)
        object.__setattr__(self, "yara_enabled", yara_enabled)
        object.__setattr__(self, "progress_every", progress_every)
        object.__setattr__(self, "throttle_sec", throttle_sec)
        object.__setattr__(self, "partial_output_every", partial_output_every)
        object.__setattr__(self, "slow_file_warn_sec", slow_file_warn_sec)
        object.__setattr__(self, "per_file_timeout_sec", per_file_timeout_sec)
        if type(self.scan_session_snapshot) is not ScanSessionSnapshot:
            raise TypeError("scheduler_scan_session_snapshot_invalid")
@dataclass(frozen=True)
class SchedulerModeDispatchDependencies:
    worker: Callable[..., object]
    write_partial: Callable[..., object]
    result_retainer: Callable[[object, object], object]
    derived_cache_writer: Callable[[object], object]
    results: dict[object, object] | None = None

__all__ = ("SchedulerModeDispatchDependencies", "SchedulerModeDispatchRequest")
