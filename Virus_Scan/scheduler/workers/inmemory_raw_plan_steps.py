"""Bounded in-memory raw planning steps."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping, TYPE_CHECKING

from Virus_Scan.contracts.no_hook_materialization import no_hook_sequence_items
from Virus_Scan.scheduler.internal.immutable_outputs import immutable_mapping
from Virus_Scan.scheduler.internal.no_hook_diagnostics import (
    scheduler_bool,
    scheduler_float,
    scheduler_int,
    scheduler_text,
)

if TYPE_CHECKING:
    from Virus_Scan.scheduler.contracts.inmemory_raw import InMemoryRawScanDependencies, RawIdentity


@dataclass(frozen=True, slots=True)
class RawPlanStageDecision:
    """Stage, identity, and eligibility state for a raw-plan request."""

    identity: RawIdentity
    ext: str
    ext_stage: str
    effective_stage: str

@dataclass(frozen=True, slots=True)
class RawPlanCapacityDecision:
    """Bounded raw job capacity and local worker decision."""

    capped_jobs: tuple[Mapping[str, object], ...]
    local_workers: int


def truthy_raw_plan_bool(value: object, *, reason: str) -> bool:
    """Normalize a raw-plan truth value without caller-owned hooks."""

    parsed, parse_reason = scheduler_bool(value, default=False, reason=reason)
    return parse_reason == "" and parsed


def raw_plan_stage_text(value: object, *, replacement: str = "") -> str:
    """Normalize raw-plan stage text with an explicit replacement."""

    text, reason = scheduler_text(value, replacement_text=replacement)
    if reason == "":
        return text
    return replacement


def raw_plan_is_requested(
    *,
    pretriage_suspicious: object,
    pretriage_tags: object,
    deps: InMemoryRawScanDependencies,
) -> bool:
    """Return whether raw enrichment is requested by tags, suspicion, or mode."""

    suspicious = truthy_raw_plan_bool(
        pretriage_suspicious,
        reason="pretriage_suspicious_rejected",
    )
    tag_items = no_hook_sequence_items(pretriage_tags)
    thorough = truthy_raw_plan_bool(
        deps.deep_scan_thorough(),
        reason="deep_scan_thorough_rejected",
    )
    return suspicious or len(tag_items) > 0 or thorough


def resolve_raw_plan_stage(
    *,
    path: object,
    pretriage_stage: object,
    deps: InMemoryRawScanDependencies,
) -> RawPlanStageDecision | str:
    """Resolve raw-plan stage/identity or return a replayable rejection reason."""

    identity = deps.sniff_file_identity(path)
    ext = raw_plan_stage_text(deps.get_scan_extension(path), replacement="")
    rpa_enabled = truthy_raw_plan_bool(
        deps.runtime_value("RPA_USE_GLOBAL_RAW_QUEUE", False),
        reason="rpa_global_raw_queue_rejected",
    )
    if ext == ".rpa" and not rpa_enabled:
        return "inmemory_raw_plan_rpa_disabled"
    ext_stage = raw_plan_stage_text(deps.normalize_stage(ext), replacement="raw")
    pretriage_stage_text = raw_plan_stage_text(pretriage_stage, replacement="")
    effective_stage = pretriage_stage_text or raw_plan_stage_text(
        deps.choose_effective_stage(ext_stage, identity),
        replacement=ext_stage,
    )
    if not deps.global_raw_eligible(path, effective_stage=effective_stage):
        return "inmemory_raw_plan_not_eligible"
    return RawPlanStageDecision(
        identity=identity,
        ext=ext,
        ext_stage=ext_stage,
        effective_stage=effective_stage,
    )


def load_raw_plan_jobs(
    *,
    path: object,
    file_id: str,
    stage: RawPlanStageDecision,
    deps: InMemoryRawScanDependencies,
) -> tuple[Mapping[str, object], ...] | str:
    """Load raw-stage jobs or return an insufficient-jobs reason."""

    jobs_source = deps.build_raw_stage_jobs(
        path,
        file_id,
        stage.effective_stage,
        stage.ext_stage,
        stage.identity,
        deps=deps.raw_stage_job_build_dependencies(),
    )
    jobs = no_hook_sequence_items(jobs_source)
    if len(jobs) < 2:
        return "inmemory_raw_plan_insufficient_jobs"
    return tuple(immutable_mapping(job) for job in jobs)


def resolve_raw_plan_capacity(
    *,
    jobs: tuple[Mapping[str, object], ...],
    deps: InMemoryRawScanDependencies,
) -> RawPlanCapacityDecision:
    """Apply raw per-file cap and local worker limits."""

    cap_default_source = deps.runtime_value("RAW_PER_FILE_ACTIVE_CAP", 128)
    cap_default, _cap_default_reason = scheduler_int(
        cap_default_source,
        default=128,
        minimum=1,
        reason="raw_per_file_cap_rejected",
    )
    cap_source = deps.environ_get("UMIGE_INMEMORY_RAW_PER_FILE_CAP", int.__str__(cap_default))
    per_file_cap, _cap_reason = scheduler_int(
        cap_source,
        default=cap_default,
        minimum=1,
        reason="inmemory_raw_per_file_cap_rejected",
    )
    capped_jobs = tuple(immutable_mapping(job) for job in jobs[:per_file_cap])
    worker_source = deps.environ_get("UMIGE_INMEMORY_RAW_THREADS_PER_PROCESS", "4")
    requested_workers, _worker_reason = scheduler_int(
        worker_source,
        default=4,
        minimum=1,
        reason="inmemory_raw_threads_rejected",
    )
    return RawPlanCapacityDecision(
        capped_jobs=capped_jobs,
        local_workers=max(1, min(len(capped_jobs), requested_workers)),
    )


def resolve_raw_plan_deadline(
    *,
    timeout_sec: object,
    capped_jobs: tuple[Mapping[str, object], ...],
    deps: InMemoryRawScanDependencies,
) -> float:
    """Return the deadline for a bounded raw-plan execution window."""

    timeout_value, timeout_reason = scheduler_float(
        timeout_sec,
        default=0.0,
        minimum=0.0,
        reason="inmemory_raw_timeout_rejected",
    )
    now_value, _now_reason = scheduler_float(
        deps.now(),
        default=0.0,
        minimum=0.0,
        reason="inmemory_raw_now_rejected",
    )
    if timeout_reason == "" and timeout_value > 0.0:
        budget = timeout_value
    else:
        budget = max(60.0, len(capped_jobs) * 2.0)
    return now_value + budget

__all__ = (
    "RawPlanCapacityDecision", "RawPlanStageDecision", "load_raw_plan_jobs",
    "raw_plan_is_requested", "raw_plan_stage_text", "resolve_raw_plan_capacity",
    "resolve_raw_plan_deadline", "resolve_raw_plan_stage", "truthy_raw_plan_bool",
)
