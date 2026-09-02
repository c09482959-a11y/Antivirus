"""No-hook profile-policy and finalization boundaries for scheduler pipeline."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from Virus_Scan.scheduler.internal.no_hook_diagnostics import scheduler_bool, scheduler_int


@dataclass(frozen=True, slots=True)
class SchedulerProfilePolicyRequest:
    """Internal request for one scheduler profile-policy configuration."""

    scheduler_runtime: object
    dependencies: object
    defer_profile_flush: bool
    freeze_existing_baselines: bool
    profile_flush_every: int
    bulk_profile_flush_every: int


@dataclass(frozen=True, slots=True)
class SchedulerPipelineRunFinalizationRequest:
    """Internal request for one scheduler pipeline finalization."""

    state: object
    dependencies: object
    scheduler_runtime: object
    finalization_request_factory: Callable[..., object]
    finalization_dependencies_factory: Callable[..., object]
    scheduler_mode: str
    strict: bool
    freeze_existing_baselines: bool
    profile_policy_snapshot: object
    write_partial: Callable[..., object]
    recoverable_exceptions: object


def configure_scheduler_profile_policy(
    request: SchedulerProfilePolicyRequest,
) -> object:
    """Configure parent profile persistence policy for one scheduler run."""
    defer_profile_flush_value, defer_reason = scheduler_bool(
        request.defer_profile_flush,
        default=False,
        reason="scheduler_profile_defer_flush_rejected",
    )
    freeze_existing_baselines_value, freeze_reason = scheduler_bool(
        request.freeze_existing_baselines,
        default=False,
        reason="scheduler_profile_freeze_baselines_rejected",
    )
    profile_flush_every_value, flush_reason = scheduler_int(
        request.profile_flush_every,
        default=25,
        minimum=1,
        reason="scheduler_profile_flush_every_rejected",
    )
    bulk_profile_flush_every_value, bulk_reason = scheduler_int(
        request.bulk_profile_flush_every,
        default=1000000000,
        minimum=1,
        reason="scheduler_bulk_profile_flush_every_rejected",
    )
    reasons = tuple(
        reason
        for reason in (defer_reason, freeze_reason, flush_reason, bulk_reason)
        if reason
    )
    if reasons:
        raise ValueError(",".join(reasons))
    profile_policy_snapshot = request.scheduler_runtime.configure_profile_policy(
        defer_profile_writes=defer_profile_flush_value,
        profile_flush_every=profile_flush_every_value,
        bulk_profile_flush_every=bulk_profile_flush_every_value,
    )
    if freeze_existing_baselines_value:
        request.dependencies.freeze_profile_scoring_snapshot()
    return profile_policy_snapshot



def finalize_scheduler_pipeline_run(
    request: SchedulerPipelineRunFinalizationRequest,
) -> None:
    """Finalize one scheduler pipeline run through explicit dependencies."""
    strict_value, strict_reason = scheduler_bool(
        request.strict,
        default=False,
        reason="scheduler_finalization_strict_rejected",
    )
    freeze_existing_baselines_value, freeze_reason = scheduler_bool(
        request.freeze_existing_baselines,
        default=False,
        reason="scheduler_finalization_freeze_baselines_rejected",
    )
    reasons = tuple(reason for reason in (strict_reason, freeze_reason) if reason)
    if reasons:
        raise ValueError(",".join(reasons))
    request.dependencies.finalize_scheduler_pipeline(
        request.finalization_request_factory(
            results=request.state.results,
            scheduler_mode=request.scheduler_mode,
            strict=strict_value,
            process_shard=request.dependencies.environ_get("UMIGE_PROCESS_SHARD", None) == "1",
            freeze_existing_baselines=freeze_existing_baselines_value,
            profile_policy_snapshot=request.profile_policy_snapshot,
        ),
        request.finalization_dependencies_factory(
            persist_parent_learning_from_results=request.dependencies.persist_parent_learning_from_results,
            flush_all_persistent_models=request.dependencies.flush_all_persistent_models,
            restore_profile_policy=request.scheduler_runtime.restore_profile_policy,
            clear_profile_scoring_snapshot=request.dependencies.clear_profile_scoring_snapshot,
            write_partial=request.write_partial,
            log_error=request.dependencies.log_error,
            recoverable_exceptions=request.recoverable_exceptions,
        ),
    )



__all__ = (
    'SchedulerPipelineRunFinalizationRequest',
    'SchedulerProfilePolicyRequest',
    'configure_scheduler_profile_policy',
    'finalize_scheduler_pipeline_run',
)
