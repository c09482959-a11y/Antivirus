"""Workload-specific timeout budget policy calculations."""
from __future__ import annotations

import math

from Virus_Scan.scheduler.timeout.timeout_budget_policy_steps import (
    NormalizedTimeoutBudgetPolicyInputs,
)


def _archive_ratio_complexity(ratio: float, expanded_mb: float) -> float:
    if ratio < 20.0:
        return 0.0
    return math.log2(max(1.0, ratio / 20.0)) * min(
        600.0,
        max(30.0, expanded_mb * 90.0),
    )


def compute_workload_budget(inputs: NormalizedTimeoutBudgetPolicyInputs) -> tuple[float, float]:
    """Compute the workload-specific hard/stall timeout budget pair."""
    if inputs.workload == "image_fast_triage":
        budget = 60.0 + inputs.size_mb * 10.0 + inputs.pixel_megapixels * 2.0
        stall = max(30.0, min(180.0, budget / 2.0))
        if inputs.inspection_error and inputs.size_mb >= 0.5:
            budget = min(budget, 40.0 + inputs.size_mb * 5.0)
            stall = min(stall, max(20.0, budget / 2.0))
    elif inputs.workload == "deep_image_scan":
        budget = 300.0 + inputs.size_mb * 120.0 + inputs.pixel_megapixels * 45.0
        stall = max(90.0, min(600.0, budget / 3.0))
    elif inputs.workload == "media_scan":
        budget = 120.0 + inputs.size_mb * 20.0
        stall = max(45.0, min(240.0, budget / 3.0))
    elif inputs.workload == "yara_scan":
        budget = 300.0 + inputs.size_mb * 45.0
        stall = max(90.0, min(600.0, budget / 3.0))
    elif inputs.workload == "dotnet_decompile":
        budget = 600.0 + inputs.size_mb * 90.0
        stall = max(180.0, min(900.0, budget / 3.0))
    elif inputs.workload == "archive":
        budget = (
            900.0
            + inputs.size_mb * 120.0
            + inputs.expanded_mb * 10.0
            + inputs.member_count * 1.0
            + inputs.largest_mb * 20.0
            + inputs.depth * 300.0
            + inputs.nested * 240.0
            + _archive_ratio_complexity(inputs.ratio, inputs.expanded_mb)
        )
        stall = max(180.0, min(1800.0, budget / 4.0))
    elif inputs.workload == "deep_scan":
        budget = 600.0 + inputs.size_mb * 90.0
        stall = max(120.0, min(900.0, budget / 3.0))
    else:
        budget = 120.0 + inputs.size_mb * 20.0
        stall = max(45.0, min(300.0, budget / 3.0))
    return budget, stall


__all__ = ("compute_workload_budget",)
