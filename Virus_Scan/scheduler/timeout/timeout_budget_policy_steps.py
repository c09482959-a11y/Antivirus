"""Bounded timeout budget policy normalization and bounds steps."""
from __future__ import annotations

from dataclasses import dataclass
from Virus_Scan.scheduler.internal.no_hook_diagnostics import (
    scheduler_bool,
    scheduler_float,
    scheduler_int,
    scheduler_text,
)


@dataclass(frozen=True)
class NormalizedTimeoutBudgetPolicyInputs:
    """No-hook-normalized timeout policy input fields."""

    workload: str
    size_mb: float
    expanded_mb: float
    largest_mb: float
    member_count: int
    ratio: float
    depth: int
    nested: int
    pixel_megapixels: float
    inspection_error: str
    deep_scan: bool
    configured_floor: float


def normalize_timeout_budget_policy_request(
    request: object,
) -> NormalizedTimeoutBudgetPolicyInputs:
    """Normalize caller-facing request fields without invoking field hooks."""
    workload, _workload_reason = scheduler_text(
        request.workload,
        replacement_text="generic_scan",
        unsupported_reason="timeout_policy_workload_rejected",
    )
    size_mb, _size_reason = scheduler_float(
        request.file_size_mb,
        default=0.0,
        minimum=0.0,
        reason="timeout_policy_file_size_mb_rejected",
    )
    expanded_mb, _expanded_reason = scheduler_float(
        request.expanded_size_mb,
        default=0.0,
        minimum=0.0,
        reason="timeout_policy_expanded_size_mb_rejected",
    )
    largest_mb, _largest_reason = scheduler_float(
        request.largest_member_mb,
        default=0.0,
        minimum=0.0,
        reason="timeout_policy_largest_member_mb_rejected",
    )
    member_count, _member_reason = scheduler_int(
        request.archive_member_count,
        default=0,
        minimum=0,
        reason="timeout_policy_member_count_rejected",
    )
    ratio, _ratio_reason = scheduler_float(
        request.compression_ratio,
        default=0.0,
        minimum=0.0,
        reason="timeout_policy_compression_ratio_rejected",
    )
    depth, _depth_reason = scheduler_int(
        request.recursion_depth,
        default=0,
        minimum=0,
        reason="timeout_policy_recursion_depth_rejected",
    )
    nested, _nested_reason = scheduler_int(
        request.nested_archive_count,
        default=0,
        minimum=0,
        reason="timeout_policy_nested_count_rejected",
    )
    pixels, _pixel_reason = scheduler_int(
        request.image_pixels,
        default=0,
        minimum=0,
        reason="timeout_policy_image_pixels_rejected",
    )
    inspection_error, _inspection_reason = scheduler_text(
        request.inspection_error,
        replacement_text="",
        unsupported_reason="timeout_policy_inspection_error_rejected",
    )
    deep_scan, _deep_scan_reason = scheduler_bool(
        request.deep_scan,
        default=False,
        reason="timeout_policy_deep_scan_rejected",
    )
    configured_floor, _configured_reason = scheduler_float(
        request.configured_floor,
        default=0.0,
        minimum=0.0,
        reason="timeout_policy_configured_floor_rejected",
    )
    pixel_megapixels = pixels / 1000000.0
    return NormalizedTimeoutBudgetPolicyInputs(
        workload=workload,
        size_mb=size_mb,
        expanded_mb=expanded_mb,
        largest_mb=largest_mb,
        member_count=member_count,
        ratio=ratio,
        depth=depth,
        nested=nested,
        pixel_megapixels=pixel_megapixels,
        inspection_error=inspection_error,
        deep_scan=deep_scan,
        configured_floor=configured_floor,
    )


def apply_timeout_policy_bounds(
    inputs: NormalizedTimeoutBudgetPolicyInputs,
    *,
    budget: float,
    stall: float,
    clamp_hard_budget: object,
) -> tuple[float, float, float]:
    """Apply global configured-floor, deep-scan, and heartbeat bounds."""
    if inputs.deep_scan:
        budget *= 2.0
        stall *= 1.5
    if inputs.configured_floor > 0:
        budget = clamp_hard_budget(budget)
        stall = max(
            stall,
            min(max(inputs.configured_floor, 30.0), max(30.0, budget / 2.0)),
        )
    budget = clamp_hard_budget(budget)
    stall = min(max(15.0, stall), max(15.0, budget * 0.75))
    heartbeat_stale = min(max(15.0, stall / 3.0), 300.0)
    return budget, stall, heartbeat_stale


__all__ = (
    "NormalizedTimeoutBudgetPolicyInputs",
    "apply_timeout_policy_bounds",
    "normalize_timeout_budget_policy_request",
)
