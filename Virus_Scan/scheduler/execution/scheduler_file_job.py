"""Canonical single-file scheduler execution ownership.

This module owns the public scheduler pipeline's single-file execution boundary.
Routing/terminal/deep-analysis details are delegated to bounded execution
submodules so this file stays a thin execution coordinator.
"""
from __future__ import annotations

from typing import cast

from Virus_Scan.contracts.artifact_read_snapshot import attach_artifact_read_record
from Virus_Scan.scheduler.execution.file_result_boundary import execution_bool, execution_mapping, execution_sequence
from Virus_Scan.scheduler.execution.scheduler_file_analysis import execute_scheduler_file_analysis
from Virus_Scan.scheduler.execution.scheduler_file_job_types import (
    FastResultDecision,
    SchedulerFileExecutionDependencies,
    SchedulerFileExecutionRequest,
    SchedulerJobResult,
    SchedulerPath,
    SchedulerPrefilterInfo,
    SchedulerRouteOutcome,
    SchedulerTags,
    SchedulerTimeoutBudget,
)
from Virus_Scan.scheduler.execution.scheduler_file_message_support import safe_pipeline_worker_log_message
from Virus_Scan.scheduler.execution.scheduler_file_terminal import maybe_return_terminal_result
from Virus_Scan.scheduler.execution.scheduler_yara_result import (
    obtain_scheduler_yara_result,
    publish_scheduler_yara_result,
)


def execute_scheduler_file_job(request: SchedulerFileExecutionRequest, deps: SchedulerFileExecutionDependencies) -> SchedulerJobResult:
    """Execute one scheduler file job under worker ownership."""
    path = request.path
    started_file = deps.time()
    active_timeout_budget = deps.compute_timeout_budget(
        path,
        configured_timeout_seconds=request.per_file_timeout_sec,
        method="routing_triage",
        artifact_read_snapshot=request.artifact_read_snapshot,
    )
    try:
        prefilter_info: SchedulerPrefilterInfo = {"fast_result": None, "hits": (), "tags": ()}
        route_outcome, tags, suspicious, router_identity, curr_stage = _route_file(
            request=request,
            deps=deps,
            path=path,
            active_timeout_budget=active_timeout_budget,
            prefilter_info=prefilter_info,
        )
        fast_result = _fast_result_decision(path, started_file, prefilter_info, deps)
        if fast_result.available and fast_result.result is not None:
            fast_path, fast_record = fast_result.result
            yara_result = obtain_scheduler_yara_result(
                path=fast_path,
                yara_enabled=request.yara_enabled,
                compiled_rules=request.compiled_rules,
                yara_scan_with_optional_zip=deps.yara_scan_with_optional_zip,
            )
            publish_scheduler_yara_result(fast_record, yara_result)
            attach_artifact_read_record(fast_record, request.artifact_read_snapshot)
            return fast_path, fast_record
        terminal_result = maybe_return_terminal_result(
            request=request,
            deps=deps,
            path=path,
            started_file=started_file,
            tags=tags,
            suspicious=suspicious,
            curr_stage=curr_stage,
            router_identity=router_identity,
            active_timeout_budget=active_timeout_budget,
            cache_sha256="",
        )
        if terminal_result is not None:
            attach_artifact_read_record(terminal_result[1], request.artifact_read_snapshot)
            return terminal_result
        return execute_scheduler_file_analysis(
            request=request,
            deps=deps,
            path=path,
            started_file=started_file,
            tags=tags,
            suspicious=suspicious,
            curr_stage=curr_stage,
            router_identity=router_identity,
            route_tag_evidence=route_outcome.tag_evidence,
            route_static_program_analyses=route_outcome.static_program_analyses,
            prefilter_info=prefilter_info,
            global_raw_info=None,
        )
    except deps.timeout_exception_type as exc:
        if request.strict:
            raise
        deps.log_error(
            safe_pipeline_worker_log_message(
                prefix="safe pipeline worker timed out",
                path=path,
                exc=exc,
            )
        )
        timeout_result = deps.make_timeout_result(path, active_timeout_budget.hard_timeout_seconds, prev_stage=request.previous_stage)
        timeout_result = deps.annotate_timeout_result(timeout_result, active_timeout_budget, worker_state="queue_worker_hard_timeout", reason="hard_timeout_signal")
        attach_artifact_read_record(timeout_result, request.artifact_read_snapshot)
        return (path, timeout_result)
    except deps.recoverable_exceptions as exc:
        if request.strict:
            raise
        deps.log_error(
            safe_pipeline_worker_log_message(
                prefix="safe pipeline worker failed",
                path=path,
                exc=exc,
            )
        )
        error_result = deps.make_worker_error_result(path, exc)
        attach_artifact_read_record(error_result, request.artifact_read_snapshot)
        return (path, error_result)


def _route_file(
    *,
    request: SchedulerFileExecutionRequest,
    deps: SchedulerFileExecutionDependencies,
    path: SchedulerPath,
    active_timeout_budget: SchedulerTimeoutBudget,
    prefilter_info: SchedulerPrefilterInfo,
) -> tuple[SchedulerRouteOutcome, SchedulerTags, bool, object, str]:
    routing_guard = deps.per_file_timeout(active_timeout_budget.hard_timeout_seconds) if (
        request.use_signal_timeout and deps.current_thread() is deps.main_thread()
    ) else deps.nullcontext_factory()
    with routing_guard:
        route_outcome = deps.scan_file_by_type(
            path,
            scan_session_snapshot=request.scan_session_snapshot,
            artifact_read_snapshot=request.artifact_read_snapshot,
        )
        tags, suspicious = route_outcome
        route_tags = execution_sequence(tags, field_name="route_tags")
        prefilter_tags = execution_sequence(dict.get(prefilter_info, "tags"), field_name="prefilter_tags")
        router_identity = route_outcome.identity
        curr_stage = deps.effective_stage_for_path(route_tags, path)
        normalized_tags = execution_sequence(
            deps.normalize_tags(tuple(route_tags + prefilter_tags)),
            field_name="normalized_tags",
        )
        return route_outcome, normalized_tags, execution_bool(suspicious, field_name="route_suspicious"), router_identity, curr_stage


def _fast_result_decision(
    path: SchedulerPath,
    started_file: float,
    prefilter_info: SchedulerPrefilterInfo,
    deps: SchedulerFileExecutionDependencies,
) -> FastResultDecision:
    raw_fast_result = dict.get(prefilter_info, "fast_result")
    if raw_fast_result is None:
        return FastResultDecision(available=False, result=None, reason="prefilter_fast_result_absent")
    fast_result = cast("dict[str, object]", execution_mapping(raw_fast_result, field_name="prefilter_fast_result"))
    fast_result["scan_duration_seconds"] = round(deps.time() - started_file, 6)
    return FastResultDecision(available=True, result=(path, fast_result), reason="prefilter_fast_result_present")
