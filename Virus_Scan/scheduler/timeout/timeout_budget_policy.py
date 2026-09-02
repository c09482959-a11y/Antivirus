"""Deterministic timeout budget policy calculations.

This module owns timeout policy math so timeout_budget.py remains the public
budget contract/assembly point rather than a semantic-density hotspot.
"""
from __future__ import annotations

from dataclasses import dataclass
import math

from Virus_Scan.scheduler.timeout.timeout_budget_policy_steps import (
    apply_timeout_policy_bounds,
    normalize_timeout_budget_policy_request,
)
from Virus_Scan.scheduler.timeout.timeout_budget_policy_workloads import (
    compute_workload_budget,
)


@dataclass(frozen=True)
class TimeoutBudgetPolicyRequest:
    """Immutable request for hard/stall timeout policy computation."""

    workload: str
    file_size_mb: float
    expanded_size_mb: float
    largest_member_mb: float
    archive_member_count: int
    compression_ratio: float
    recursion_depth: int
    nested_archive_count: int
    image_pixels: int | None
    inspection_error: str | None
    deep_scan: bool
    configured_floor: float


@dataclass(frozen=True)
class TimeoutBudgetPolicyOutput:
    """Immutable budget policy output."""

    hard_timeout_seconds: float
    stall_timeout_seconds: float
    heartbeat_stale_seconds: float

def compute_timeout_budget_policy(
    request: TimeoutBudgetPolicyRequest,
    *,
    clamp_hard_budget: object,
) -> TimeoutBudgetPolicyOutput:
    """Compute deterministic timeout policy without owning file inspection."""
    normalized = normalize_timeout_budget_policy_request(request)
    budget, stall = compute_workload_budget(normalized)
    budget, stall, heartbeat_stale = apply_timeout_policy_bounds(
        normalized,
        budget=budget,
        stall=stall,
        clamp_hard_budget=clamp_hard_budget,
    )
    return TimeoutBudgetPolicyOutput(
        hard_timeout_seconds=float(math.ceil(budget)),
        stall_timeout_seconds=float(math.ceil(stall)),
        heartbeat_stale_seconds=float(math.ceil(heartbeat_stale)),
    )


__all__ = (
    "TimeoutBudgetPolicyOutput",
    "TimeoutBudgetPolicyRequest",
    "compute_timeout_budget_policy",
)
