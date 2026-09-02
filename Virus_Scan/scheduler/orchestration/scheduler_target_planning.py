"""Scheduler target collection and workload planning ownership."""
from dataclasses import dataclass
from typing import Callable, Tuple

from Virus_Scan.exception_contracts import RECOVERABLE_RUNTIME_ERRORS
from Virus_Scan.scheduler.execution.target_collection import collect_target_files
from Virus_Scan.scheduler.queue.admission import (
    build_workload_classification_plan,
    workload_plan_summary,
)
from Virus_Scan.scheduler.queue.admission_fairness import interleave_workloads, weighted_fair_interleave
from Virus_Scan.runtime.api import publish_workload_queue_plan
from Virus_Scan.scheduler.internal.immutable_outputs import immutable_value
from Virus_Scan.scheduler.internal.live_path_entries import freeze_live_scheduler_paths
from Virus_Scan.scheduler.internal.exception_projection import scheduler_exception_text
from Virus_Scan.scheduler.internal.no_hook_diagnostics import scheduler_int, scheduler_text


@dataclass(frozen=True)
class SchedulerTargetPlanningRequest:
    root: object
    file_list_path: object = None
    max_files: object = None
    scheduler_requested: str = "process"


@dataclass(frozen=True)
class SchedulerTargetPlanningResult:
    files: Tuple[str, ...]
    total_files: int
    workload_plan: object = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "files", freeze_live_scheduler_paths(self.files))
        object.__setattr__(self, "workload_plan", immutable_value(self.workload_plan))


def plan_scheduler_targets(
    request: SchedulerTargetPlanningRequest,
    *,
    log_error: Callable[[str], None],
    logging_module: object,
) -> SchedulerTargetPlanningResult:
    """Collect and workload-plan scheduler targets without executing files."""
    scheduler_requested, scheduler_reason = scheduler_text(
        request.scheduler_requested,
        replacement_text="process",
        unsupported_reason="scheduler_requested_mode_rejected",
    )
    if scheduler_reason:
        log_error(scheduler_reason)
        raise ValueError(scheduler_reason)
    scheduler_requested = scheduler_requested.lower()
    if scheduler_requested == "queue-child":
        return SchedulerTargetPlanningResult(files=(), total_files=0, workload_plan=None)
    all_files = list(freeze_live_scheduler_paths(
        tuple(collect_target_files(request.root, file_list_path=request.file_list_path))
    ))
    if request.max_files is not None:
        max_files_i, max_files_reason = scheduler_int(
            request.max_files,
            default=0,
            minimum=0,
            reason="scheduler_max_files_rejected",
        )
        if max_files_reason:
            log_error(max_files_reason)
        elif max_files_i > 0:
            all_files = all_files[:max_files_i]
    workload_plan = None
    if all_files:
        try:
            classification_plan = build_workload_classification_plan(all_files)
            workload_plan = workload_plan_summary(classification_plan)
            publish_workload_queue_plan(workload_plan)
            ordered_targets = weighted_fair_interleave(
                interleave_workloads(classification_plan)
            )
            all_files = [target.path for target in ordered_targets]
            logging_module.info("workload-separated queue plan: %s", workload_plan)
        except RECOVERABLE_RUNTIME_ERRORS as exc:
            log_error(
                "workload queue planning failed; preserving collected order: "
                + scheduler_exception_text(exc, max_length=500)
            )
    return SchedulerTargetPlanningResult(
        files=tuple(all_files),
        total_files=len(all_files),
        workload_plan=workload_plan,
    )
