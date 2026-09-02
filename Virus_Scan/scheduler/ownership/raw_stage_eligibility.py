"""Raw-stage admission eligibility ownership."""
from __future__ import annotations

from typing import Callable

from Virus_Scan.scheduler.internal.no_hook_diagnostics import scheduler_bool
from Virus_Scan.scheduler.ownership.raw_stage_eligibility_decision import (
    RawStageEligibilityDecision,
)
from Virus_Scan.scheduler.ownership.raw_stage_eligibility_steps import (
    continue_raw_stage_eligibility_decision,
)


def global_raw_eligibility_decision(
    path: object,
    *,
    effective_stage: object | None = None,
    raw_queue_enabled: Callable[[], bool],
    raw_queue_min_bytes: Callable[[], int],
    get_size: Callable[[object], int],
    get_scan_extension: Callable[[object], str],
    normalize_stage: Callable[[object], str],
    runtime_value: Callable[..., object],
) -> RawStageEligibilityDecision:
    """Return a typed raw-stage admission decision with explicit rejection evidence."""
    enabled, enabled_reason = scheduler_bool(
        raw_queue_enabled(),
        reason="raw_queue_enabled_flag_rejected",
    )
    if enabled_reason:
        raise ValueError(enabled_reason)
    if not enabled:
        return RawStageEligibilityDecision.rejected("raw_queue_disabled")
    return continue_raw_stage_eligibility_decision(
        path,
        effective_stage=effective_stage,
        raw_queue_min_bytes=raw_queue_min_bytes,
        get_size=get_size,
        get_scan_extension=get_scan_extension,
        normalize_stage=normalize_stage,
        runtime_value=runtime_value,
    )


def global_raw_eligible(
    path: object,
    *,
    effective_stage: object | None = None,
    raw_queue_enabled: Callable[[], bool],
    raw_queue_min_bytes: Callable[[], int],
    get_size: Callable[[object], int],
    get_scan_extension: Callable[[object], str],
    normalize_stage: Callable[[object], str],
    runtime_value: Callable[..., object],
) -> bool:
    """Return whether a file may enter global raw-stage queueing."""
    return global_raw_eligibility_decision(
        path,
        effective_stage=effective_stage,
        raw_queue_enabled=raw_queue_enabled,
        raw_queue_min_bytes=raw_queue_min_bytes,
        get_size=get_size,
        get_scan_extension=get_scan_extension,
        normalize_stage=normalize_stage,
        runtime_value=runtime_value,
    ).eligible


__all__ = (
    "RawStageEligibilityDecision",
    "global_raw_eligibility_decision",
    "global_raw_eligible",
)
