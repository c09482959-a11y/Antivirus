"""Support contracts for bounded scheduler runner orchestration."""
from __future__ import annotations

from dataclasses import dataclass

from Virus_Scan.scheduler.internal.no_hook_diagnostics import scheduler_bool, scheduler_text


@dataclass(frozen=True, slots=True)
class SchedulerPipelineControlValues:
    scheduler_requested: str
    strict: bool
    defer_profile_flush: bool
    freeze_existing_baselines: bool
    yara_enabled: bool


def resolve_scheduler_pipeline_controls(
    *,
    scheduler: object,
    strict: object,
    defer_profile_flush: object,
    freeze_existing_baselines: object,
    yara_enabled: object,
) -> SchedulerPipelineControlValues:
    scheduler_requested, scheduler_reason = scheduler_text(
        scheduler,
        replacement_text="process",
        unsupported_reason="scheduler_pipeline_mode_rejected",
    )
    if scheduler_reason:
        raise ValueError(scheduler_reason)
    strict_value, strict_reason = scheduler_bool(
        strict,
        default=False,
        reason="scheduler_pipeline_strict_rejected",
    )
    if strict_reason:
        raise ValueError(strict_reason)
    defer_profile_flush_value, defer_reason = scheduler_bool(
        defer_profile_flush,
        default=True,
        reason="scheduler_pipeline_defer_profile_flush_rejected",
    )
    if defer_reason:
        raise ValueError(defer_reason)
    freeze_existing_baselines_value, freeze_reason = scheduler_bool(
        freeze_existing_baselines,
        default=True,
        reason="scheduler_pipeline_freeze_baselines_rejected",
    )
    if freeze_reason:
        raise ValueError(freeze_reason)
    yara_enabled_value, yara_reason = scheduler_bool(
        yara_enabled,
        default=True,
        reason="scheduler_pipeline_yara_enabled_rejected",
    )
    if yara_reason:
        raise ValueError(yara_reason)
    return SchedulerPipelineControlValues(
        scheduler_requested=scheduler_requested.lower(),
        strict=strict_value,
        defer_profile_flush=defer_profile_flush_value,
        freeze_existing_baselines=freeze_existing_baselines_value,
        yara_enabled=yara_enabled_value,
    )


__all__ = ("SchedulerPipelineControlValues", "resolve_scheduler_pipeline_controls")
