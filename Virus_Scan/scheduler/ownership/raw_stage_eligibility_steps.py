"""Bounded raw-stage eligibility decision steps."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from Virus_Scan.scheduler.internal.no_hook_diagnostics import (
    scheduler_bool,
    scheduler_int,
    scheduler_text,
)
from Virus_Scan.scheduler.ownership.raw_stage_eligibility_decision import (
    RawStageEligibilityDecision,
)


_GLOBAL_RAW_ELIGIBLE_STAGES = frozenset({"binary", "runtime", "other", "unknown"})
_GLOBAL_RAW_EXCLUDED_STAGES = frozenset({"archive", "asset", "image"})
_GLOBAL_RAW_ELIGIBLE_EXTENSIONS = frozenset(
    {".exe", ".dll", ".sys", ".py", ".pyc", ".rpy", ".rpyc", ".js"}
)


@dataclass(frozen=True, slots=True)
class _RawStageEligibilityScalars:
    """Materialized primitive values for raw-stage eligibility."""

    size: int
    minimum_size: int
    extension: str
    rpa_enabled: bool


def _raise_if_materialization_failed(reason: str | None) -> None:
    """Fail closed for hostile or unsupported raw-stage scalar inputs."""
    if reason:
        raise ValueError(reason)


def _materialize_raw_stage_sizes(
    path: object,
    *,
    get_size: Callable[[object], int],
    raw_queue_min_bytes: Callable[[], int],
) -> tuple[RawStageEligibilityDecision | None, int, int]:
    """Return size scalars or an explicit unavailable-size decision."""
    try:
        size_value = get_size(path)
    except OSError:
        return (
            RawStageEligibilityDecision.rejected("raw_queue_file_size_unavailable"),
            0,
            0,
        )

    size, size_reason = scheduler_int(
        size_value,
        default=0,
        minimum=0,
        reason="raw_queue_file_size_rejected",
    )
    minimum_size, minimum_reason = scheduler_int(
        raw_queue_min_bytes(),
        default=0,
        minimum=0,
        reason="raw_queue_minimum_size_rejected",
    )
    _raise_if_materialization_failed(size_reason or minimum_reason)
    return None, size, minimum_size


def _materialize_raw_stage_scalars(
    path: object,
    *,
    raw_queue_min_bytes: Callable[[], int],
    get_size: Callable[[object], int],
    get_scan_extension: Callable[[object], str],
    runtime_value: Callable[..., object],
) -> tuple[RawStageEligibilityDecision | None, _RawStageEligibilityScalars]:
    """Materialize primitive raw-stage scalars without path hooks."""
    size_decision, size, minimum_size = _materialize_raw_stage_sizes(
        path,
        get_size=get_size,
        raw_queue_min_bytes=raw_queue_min_bytes,
    )
    if size_decision is not None:
        return size_decision, _RawStageEligibilityScalars(0, 0, "", False)
    if size < minimum_size:
        return (
            RawStageEligibilityDecision.rejected(
                "raw_queue_file_size_below_minimum",
                size=size,
                minimum_size=minimum_size,
            ),
            _RawStageEligibilityScalars(size, minimum_size, "", False),
        )

    extension, extension_reason = scheduler_text(
        get_scan_extension(path),
        unsupported_reason="raw_queue_extension_rejected",
    )
    _raise_if_materialization_failed(extension_reason)
    rpa_enabled, rpa_reason = scheduler_bool(
        runtime_value("RPA_USE_GLOBAL_RAW_QUEUE", False),
        reason="raw_queue_rpa_flag_rejected",
    )
    _raise_if_materialization_failed(rpa_reason)
    return None, _RawStageEligibilityScalars(
        size=size,
        minimum_size=minimum_size,
        extension=extension,
        rpa_enabled=rpa_enabled,
    )


def _materialize_raw_stage_name(
    *,
    extension: str,
    effective_stage: object | None,
    normalize_stage: Callable[[object], str],
) -> str:
    """Materialize the raw-stage name while rejecting hostile values."""
    stage_value = normalize_stage(extension) if effective_stage is None else effective_stage
    stage, stage_reason = scheduler_text(
        stage_value,
        unsupported_reason="raw_queue_stage_rejected",
    )
    _raise_if_materialization_failed(stage_reason)
    if stage == "":
        return "unknown"
    return stage


def _raw_stage_decision_from_scalars(
    *,
    stage: str,
    scalars: _RawStageEligibilityScalars,
) -> RawStageEligibilityDecision:
    """Return the final replayable raw-stage eligibility decision."""
    if scalars.extension == ".rpa" and not scalars.rpa_enabled:
        return RawStageEligibilityDecision.rejected(
            "raw_queue_rpa_global_queue_disabled",
            extension=scalars.extension,
            size=scalars.size,
            minimum_size=scalars.minimum_size,
        )
    if stage in _GLOBAL_RAW_EXCLUDED_STAGES:
        return RawStageEligibilityDecision.rejected(
            "raw_queue_stage_not_global_raw_eligible",
            stage=stage,
            extension=scalars.extension,
            size=scalars.size,
            minimum_size=scalars.minimum_size,
        )
    if stage in _GLOBAL_RAW_ELIGIBLE_STAGES or scalars.extension in _GLOBAL_RAW_ELIGIBLE_EXTENSIONS:
        return RawStageEligibilityDecision.accepted(
            stage=stage,
            extension=scalars.extension,
            size=scalars.size,
            minimum_size=scalars.minimum_size,
        )
    return RawStageEligibilityDecision.rejected(
        "raw_queue_stage_extension_not_eligible",
        stage=stage,
        extension=scalars.extension,
        size=scalars.size,
        minimum_size=scalars.minimum_size,
    )


def continue_raw_stage_eligibility_decision(
    path: object,
    *,
    effective_stage: object | None,
    raw_queue_min_bytes: Callable[[], int],
    get_size: Callable[[object], int],
    get_scan_extension: Callable[[object], str],
    normalize_stage: Callable[[object], str],
    runtime_value: Callable[..., object],
) -> RawStageEligibilityDecision:
    """Continue raw-stage eligibility after the enabled flag is proven enabled."""
    early_decision, scalars = _materialize_raw_stage_scalars(
        path,
        raw_queue_min_bytes=raw_queue_min_bytes,
        get_size=get_size,
        get_scan_extension=get_scan_extension,
        runtime_value=runtime_value,
    )
    if early_decision is not None:
        return early_decision
    stage = _materialize_raw_stage_name(
        extension=scalars.extension,
        effective_stage=effective_stage,
        normalize_stage=normalize_stage,
    )
    return _raw_stage_decision_from_scalars(stage=stage, scalars=scalars)
