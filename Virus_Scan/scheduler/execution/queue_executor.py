from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from Virus_Scan.contracts.no_hook_materialization import no_hook_sequence_items
from Virus_Scan.scheduler.execution.exact_int_support import execution_exact_int
from Virus_Scan.scheduler.execution.queue_executor_contracts import GlobalRawQueueScanDependencies
from Virus_Scan.scheduler.execution.queue_executor_results import completed_raw_scan_outcome
from Virus_Scan.scheduler.execution.queue_executor_support import (
    GlobalRawQueueTimeoutError,
    exact_stage_text,
    exact_timeout_seconds,
    queue_timeout_message,
    record_queue_failure_outcome,
    router_stage_tag,
)
from Virus_Scan.scheduler.execution.queue_scan_outcome import (
    GlobalRawQueueScanOutcome,
    raw_queue_scan_rejected,
    raw_queue_scan_skipped,
)

if TYPE_CHECKING:
    from Virus_Scan.scheduler.execution.queue_executor_contracts import RawQueueRecord


__all__ = (
    "GlobalRawQueueScanDependencies",
    "scan_file_via_global_raw_queue",
)


@dataclass(frozen=True)
class _RawQueueScanPlan:
    identity: RawQueueRecord
    ext: str
    ext_stage: str
    effective_stage: str
    common_tags: tuple[object, ...]
    file_id: str
    jobs: tuple[RawQueueRecord, ...]



def _resolve_scan_plan(
    path: object,
    pretriage_tags: object,
    *,
    pretriage_suspicious: bool,
    pretriage_stage: object,
    deps: GlobalRawQueueScanDependencies,
) -> _RawQueueScanPlan | GlobalRawQueueScanOutcome:
    identity = deps.sniff_file_identity(path)
    ext_value = deps.get_scan_extension(path)
    ext = str.__str__(ext_value) if type(ext_value) is str else ""
    ext_stage, ext_stage_reason = exact_stage_text(deps.normalize_stage(ext))
    if ext_stage_reason:
        deps.record_issue("raw_queue_ext_stage_rejected", ValueError(ext_stage_reason))
    stage_value = deps.choose_effective_stage(ext_stage, identity) if pretriage_stage is None or (type(pretriage_stage) is str and pretriage_stage == "") else pretriage_stage
    effective_stage, stage_reason = exact_stage_text(stage_value)
    if effective_stage == "":
        deps.record_issue("raw_queue_effective_stage_rejected", ValueError(stage_reason))
        return raw_queue_scan_rejected(stage_reason or "raw_queue_effective_stage_rejected")
    if not (pretriage_suspicious or pretriage_tags):
        return raw_queue_scan_skipped("raw_queue_not_pretriaged")
    if ext == ".rpa" and not bool(deps.runtime_value("RPA_USE_GLOBAL_RAW_QUEUE", False)):
        return raw_queue_scan_skipped("rpa_global_raw_queue_disabled")
    if not deps.global_raw_eligible(path, effective_stage=effective_stage):
        return raw_queue_scan_skipped("global_raw_not_eligible")
    file_id = deps.global_raw_file_id(path)
    common_tags = (
        *no_hook_sequence_items(identity.get("tags", ())),
        *no_hook_sequence_items(pretriage_tags),
        router_stage_tag(effective_stage),
        "global_raw_post_triage_escalated",
    )
    jobs = deps.build_raw_stage_jobs(path, file_id, effective_stage, ext_stage, identity, deps=deps.raw_stage_job_build_dependencies())
    return _RawQueueScanPlan(identity=identity, ext=ext, ext_stage=ext_stage, effective_stage=effective_stage, common_tags=common_tags, file_id=file_id, jobs=tuple(jobs))


def _bounded_jobs(plan: _RawQueueScanPlan, queue_dir: object, deps: GlobalRawQueueScanDependencies) -> _RawQueueScanPlan | GlobalRawQueueScanOutcome:
    raw_live_now = deps.raw_queue_live_count(queue_dir)
    hard_cap, hard_cap_reason = execution_exact_int(deps.runtime_value("RAW_LIVE_HARD_CAP", 900), 900, minimum=1, reason="raw_live_hard_cap_rejected")
    if hard_cap_reason:
        deps.record_issue("raw_live_hard_cap_rejected", ValueError(hard_cap_reason))
    if raw_live_now >= hard_cap:
        return raw_queue_scan_skipped("raw_live_hard_cap_reached")
    soft_cap, soft_cap_reason = execution_exact_int(deps.runtime_value("RAW_LIVE_SOFT_CAP", 500), 500, minimum=1, reason="raw_live_soft_cap_rejected")
    batch_cap, batch_cap_reason = execution_exact_int(deps.runtime_value("RAW_PUBLISH_BATCH_MAX", 64), 64, minimum=1, reason="raw_publish_batch_max_rejected")
    if soft_cap_reason:
        deps.record_issue("raw_live_soft_cap_rejected", ValueError(soft_cap_reason))
    if batch_cap_reason:
        deps.record_issue("raw_publish_batch_max_rejected", ValueError(batch_cap_reason))
    jobs = plan.jobs[: max(4, min(len(plan.jobs), batch_cap))] if raw_live_now >= soft_cap else plan.jobs
    active_cap, active_cap_reason = execution_exact_int(deps.runtime_value("RAW_GLOBAL_ACTIVE_CAP", 768), 768, minimum=1, reason="raw_global_active_cap_rejected")
    if active_cap_reason:
        deps.record_issue("raw_publish_capacity_invalid", ValueError(active_cap_reason))
    room = max(0, active_cap - raw_live_now)
    if room > 0:
        jobs = jobs[: min(len(jobs), room)]
    if len(jobs) < 4:
        return raw_queue_scan_skipped("raw_stage_job_count_below_minimum")
    return _RawQueueScanPlan(identity=plan.identity, ext=plan.ext, ext_stage=plan.ext_stage, effective_stage=plan.effective_stage, common_tags=plan.common_tags, file_id=plan.file_id, jobs=jobs)


def _publish_jobs(path: object, queue_dir: object, plan: _RawQueueScanPlan, deps: GlobalRawQueueScanDependencies) -> GlobalRawQueueScanOutcome | int:
    deps.raw_accumulator_store(queue_dir, plan.file_id).init(path, expected=len(plan.jobs), initial_tags=[*list(plan.common_tags), "global_raw_queue_scan"], effective_stage=plan.effective_stage, ext_stage=plan.ext_stage, identity=plan.identity)
    published = 0
    for job in plan.jobs:
        if deps.global_raw_publish_job(queue_dir, job):
            published += 1
    if published < len(plan.jobs):
        deps.raw_accumulator_store(queue_dir, plan.file_id).reconcile_expected(published, reason="global_raw_publish_throttled")
    if published < 4:
        return raw_queue_scan_skipped("raw_publish_count_below_minimum")
    return published


def _wait_for_completion(path: object, queue_dir: object, file_id: str, job_count: int, timeout_sec: object, deps: GlobalRawQueueScanDependencies) -> RawQueueRecord:
    timeout_window, timeout_reason = exact_timeout_seconds(timeout_sec, job_count=job_count)
    if timeout_reason:
        deps.record_issue("raw_queue_timeout_rejected", ValueError(timeout_reason))
    deadline = deps.now() + timeout_window
    while True:
        accum = deps.raw_accumulator_store(queue_dir, file_id).load()
        if deps.raw_accumulator_store.is_complete(accum):
            return accum
        if not deps.global_raw_process_one_job(queue_dir, only_file_id=file_id):
            if deps.now() > deadline:
                raise GlobalRawQueueTimeoutError(queue_timeout_message(path, accum))
            deps.sleep(0.03)


def scan_file_via_global_raw_queue(
    path: object,
    queue_dir: object,
    timeout_sec: object = 0,
    pretriage_tags: object = None,
    *,
    pretriage_suspicious: bool = False,
    pretriage_stage: object = None,
    deps: GlobalRawQueueScanDependencies,
) -> GlobalRawQueueScanOutcome:
    """Decompose a large file into global raw jobs and return typed queue outcome."""
    if not queue_dir:
        return raw_queue_scan_rejected("queue_dir_missing")
    try:
        plan_or_outcome = _resolve_scan_plan(
            path,
            pretriage_tags,
            pretriage_suspicious=pretriage_suspicious,
            pretriage_stage=pretriage_stage,
            deps=deps,
        )
        if isinstance(plan_or_outcome, GlobalRawQueueScanOutcome):
            return plan_or_outcome
        bounded_or_outcome = _bounded_jobs(plan_or_outcome, queue_dir, deps)
        if isinstance(bounded_or_outcome, GlobalRawQueueScanOutcome):
            return bounded_or_outcome
        published_or_outcome = _publish_jobs(path, queue_dir, bounded_or_outcome, deps)
        if isinstance(published_or_outcome, GlobalRawQueueScanOutcome):
            return published_or_outcome
        accum = _wait_for_completion(path, queue_dir, bounded_or_outcome.file_id, len(bounded_or_outcome.jobs), timeout_sec, deps)
        return completed_raw_scan_outcome(
            path,
            bounded_or_outcome,
            accum,
            deps,
        )
    except (TimeoutError, OSError, ValueError, TypeError, RuntimeError, KeyError) as exc:
        return record_queue_failure_outcome(deps, path, exc)
