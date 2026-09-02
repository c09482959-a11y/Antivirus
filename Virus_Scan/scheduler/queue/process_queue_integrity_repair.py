"""Process-queue integrity repair reconciliation ownership."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from Virus_Scan.scheduler.internal.live_path_entries import freeze_live_scheduler_paths
from Virus_Scan.scheduler.internal.exception_projection import scheduler_exception_text
from Virus_Scan.scheduler.internal.no_hook_diagnostics import scheduler_bool, scheduler_text


@dataclass(frozen=True)
class ProcessQueueIntegrityRepairRequest:
    """Immutable request for process-queue integrity repair."""

    queue_dir: object
    all_files: tuple[object, ...]
    phase: str
    repair: bool = True

    def __post_init__(self) -> None:
        object.__setattr__(self, "all_files", freeze_live_scheduler_paths(self.all_files))


@dataclass(frozen=True)
class ProcessQueueIntegrityRepairDependencies:
    """Explicit dependencies for process-queue integrity repair."""

    verify_and_repair: Callable[..., object]
    log_error: Callable[[str], object]
    report_suppressed: Callable[[str, BaseException], object]
    recoverable_exceptions: tuple[type[BaseException], ...]
    active_claim_pid_is_alive: Callable[..., bool] | None = None



def reconcile_process_queue_integrity_repair(
    request: ProcessQueueIntegrityRepairRequest,
    deps: ProcessQueueIntegrityRepairDependencies,
) -> bool:
    """Run queue integrity repair under reconciliation ownership."""

    try:
        repair_value, _repair_reason = scheduler_bool(
            request.repair,
            default=False,
            reason="process_queue_integrity_repair_bool_rejected",
        )
        deps.verify_and_repair(
            request.queue_dir,
            all_files=request.all_files,
            phase=request.phase,
            repair=repair_value,
            active_claim_pid_is_alive=deps.active_claim_pid_is_alive,
        )
        return True
    except deps.recoverable_exceptions as exc:
        try:
            phase_text, phase_reason = scheduler_text(
                request.phase,
                replacement_text="unknown",
                unsupported_reason="process_queue_integrity_phase_rejected",
            )
            safe_phase = phase_text if phase_reason == "" and phase_text else "unknown"
            deps.log_error(
                "process queue "
                + safe_phase
                + " integrity repair failed: "
                + scheduler_exception_text(exc)
            )
        except deps.recoverable_exceptions as suppressed_exc:
            try:
                deps.report_suppressed("monitor_loop_suppressed", suppressed_exc)
            except deps.recoverable_exceptions as reporting_exc:
                _ = reporting_exc
        return False
