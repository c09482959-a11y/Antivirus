"""No-hook scheduler file execution diagnostic message builders."""
from __future__ import annotations

from dataclasses import dataclass
import math
from typing import Callable

from Virus_Scan.contracts.no_hook_materialization import no_hook_text, no_hook_type_name
from Virus_Scan.scheduler.internal.no_hook_diagnostics import (
    scheduler_evidence_path,
    scheduler_exception_text,
)


@dataclass(frozen=True, slots=True)
class SchedulerFileMetricDecision:
    value: float
    reason: str
    replacement_used: bool


def _exact_metric_decision(value: object) -> SchedulerFileMetricDecision:
    if type(value) is bool:
        return SchedulerFileMetricDecision(0.0, "scheduler_file_metric_bool_rejected", replacement_used=True)
    if type(value) is int:
        metric = value + 0.0
        if math.isfinite(metric):
            return SchedulerFileMetricDecision(metric, "", replacement_used=False)
        return SchedulerFileMetricDecision(0.0, "scheduler_file_metric_non_finite", replacement_used=True)
    if type(value) is float:
        if math.isfinite(value):
            return SchedulerFileMetricDecision(value, "", replacement_used=False)
        return SchedulerFileMetricDecision(0.0, "scheduler_file_metric_non_finite", replacement_used=True)
    return SchedulerFileMetricDecision(0.0, "scheduler_file_metric_rejected", replacement_used=True)



def scheduler_slow_file_message(
    *,
    elapsed_file: object,
    path_text: object,
    basename: Callable[[object], object],
) -> str:
    """Build the slow-file warning without invoking caller-owned format hooks."""
    base_value = basename(path_text)
    base_raw_text, base_rejected = no_hook_text(
        base_value,
        missing_reason="scheduler_file_basename_missing",
        unsupported_reason="scheduler_file_basename_rejected",
    )
    if base_rejected == "" and base_raw_text:
        base_text = base_raw_text
    else:
        base_text = "<" + no_hook_type_name(base_value) + " " + base_rejected + ">"
    metric = _exact_metric_decision(elapsed_file)
    seconds_text = "unavailable" if metric.reason else float.__format__(metric.value, ".2f")
    return "SLOW FILE: " + seconds_text + "s " + base_text


def safe_pipeline_worker_log_message(*, prefix: str, path: object, exc: BaseException) -> str:
    """Build safe-pipeline worker diagnostics without caller-owned text hooks."""
    prefix_text = str.__str__(prefix) if type(prefix) is str else "safe pipeline worker failed"
    path_text = scheduler_evidence_path(
        path,
        field_name="safe_pipeline_worker_path",
    )
    error_text = scheduler_exception_text(exc, max_length=500)
    return prefix_text + " for " + path_text + ": " + error_text


__all__ = (
    "SchedulerFileMetricDecision",
    "safe_pipeline_worker_log_message",
    "scheduler_slow_file_message",
)
