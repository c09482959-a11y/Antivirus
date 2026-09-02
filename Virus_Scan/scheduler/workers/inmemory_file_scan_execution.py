"""Execution helpers for in-memory single-file worker scans."""
from __future__ import annotations
from collections.abc import Callable
from Virus_Scan.utils.tagging import normalize_tags
from Virus_Scan.scheduler.workers.inmemory_file_scan_analysis_steps import inmemory_analysis_method
from Virus_Scan.scheduler.execution.scheduler_yara_result import (
    obtain_scheduler_yara_result,
    publish_scheduler_yara_result,
)
from Virus_Scan.scheduler.workers.inmemory_file_scan_cache_prefilter import (
    cached_inmemory_scan_result,
    prefilter_inmemory_context,
)
from Virus_Scan.scheduler.evidence.inmemory_route_identity import attach_inmemory_route_identity
from Virus_Scan.scheduler.workers.inmemory_triage_result import InMemoryTriageResult
from Virus_Scan.scheduler.workers.inmemory_file_scan_execution_steps import (
    cache_or_prefilter_inmemory_state,
    prepare_full_inmemory_analysis_inputs,
    terminal_or_triaged_inmemory_state,
)
def terminal_inmemory_triage_result(
    *,
    path: object,
    prefilter_info: object,
    prev_stage: str,
    cache_sha256: object,
    active_timeout_budget: object,
    compiled_rules: object,
    yara_enabled: bool,
    scan_session_snapshot: object,
    artifact_read_snapshot: object,
    yara_scan_with_optional_zip: Callable[..., object],
    scan_file_by_type: Callable[..., object],
    effective_stage_for_path: Callable[..., object],
    is_terminal_clean_asset_triage: Callable[..., bool],
    make_terminal_asset_result: Callable[..., object],
) -> InMemoryTriageResult:
    """Run type triage and return a terminal result when the asset is clean."""
    route_outcome = scan_file_by_type(
        path,
        scan_session_snapshot=scan_session_snapshot,
        artifact_read_snapshot=artifact_read_snapshot,
    )
    tags, suspicious = route_outcome
    route_tag_evidence = route_outcome.tag_evidence
    router_identity = route_outcome.identity
    curr_stage = effective_stage_for_path(tags, path)
    tags = normalize_tags(list(tags or []) + list((prefilter_info or {}).get('tags') or []))
    if is_terminal_clean_asset_triage(tags, suspicious=suspicious):
        result = make_terminal_asset_result(
            path,
            tags,
            prev_stage=prev_stage,
            curr_stage=curr_stage,
            cache_sha256=cache_sha256,
        )
        if type(result) is not dict:
            raise TypeError("inmemory_terminal_result_record_invalid")
        yara_result = obtain_scheduler_yara_result(
            path=path,
            yara_enabled=yara_enabled,
            compiled_rules=compiled_rules,
            yara_scan_with_optional_zip=yara_scan_with_optional_zip,
        )
        publish_scheduler_yara_result(result, yara_result)
        result['timeout_evidence'] = active_timeout_budget.as_evidence()
        attach_inmemory_route_identity(result, router_identity)
        return InMemoryTriageResult(
            tags, suspicious, curr_stage, (path, result), route_tag_evidence, router_identity,
        )
    return InMemoryTriageResult(
        tags, suspicious, curr_stage, None, route_tag_evidence, router_identity,
    )
def prepare_inmemory_analysis_inputs(
    *,
    path: object,
    prev_stage: str,
    started_file: float,
    slow_file_warn_sec: float,
    per_file_timeout_sec: int,
    active_timeout_budget: object,
    compiled_rules: object,
    yara_enabled: bool,
    cache_execution_identity: object,
    scan_session_snapshot: object,
    artifact_read_snapshot: object,
    progress: Callable[[str], object],
    timeout_budget_factory: Callable[..., object],
    recoverable_exceptions: tuple[type[BaseException], ...],
    pre_scan_cache_lookup: Callable[..., object],
    strict_fast_prefilter: Callable[..., object],
    scan_file_by_type: Callable[..., object],
    effective_stage_for_path: Callable[..., object],
    is_terminal_clean_asset_triage: Callable[..., bool],
    make_terminal_asset_result: Callable[..., object],
    should_escalate_after_inmemory_triage: Callable[..., object],
    get_scan_extension: Callable[[object], str],
    scan_file_inmemory_raw: Callable[..., object],
    inmemory_raw_scan_dependencies: Callable[[], object],
    yara_scan_with_optional_zip: Callable[..., object],
) -> tuple[object | None, object, object, object, object, object, object, bool, list[object], object, object]:
    """Prepare scan state up to the full-analysis publication boundary."""
    short_result, cache_sha256, prefilter_info = cache_or_prefilter_inmemory_state(
        path=path,
        started_file=started_file,
        slow_file_warn_sec=slow_file_warn_sec,
        active_timeout_budget=active_timeout_budget,
        compiled_rules=compiled_rules,
        cache_execution_identity=cache_execution_identity,
        artifact_read_snapshot=artifact_read_snapshot,
        progress=progress,
        cached_inmemory_scan_result=cached_inmemory_scan_result,
        prefilter_inmemory_context=prefilter_inmemory_context,
        pre_scan_cache_lookup=pre_scan_cache_lookup,
        strict_fast_prefilter=strict_fast_prefilter,
    )
    if short_result is not None:
        return short_result, active_timeout_budget, cache_sha256, (), False, '', None, False, [], None, None
    terminal_result, tags, suspicious, curr_stage, route_tag_evidence, router_identity = terminal_or_triaged_inmemory_state(
        path=path,
        prefilter_info=prefilter_info,
        prev_stage=prev_stage,
        cache_sha256=cache_sha256,
        active_timeout_budget=active_timeout_budget,
        compiled_rules=compiled_rules,
        yara_enabled=yara_enabled,
        scan_session_snapshot=scan_session_snapshot,
        artifact_read_snapshot=artifact_read_snapshot,
        progress=progress,
        terminal_inmemory_triage_result=terminal_inmemory_triage_result,
        scan_file_by_type=scan_file_by_type,
        effective_stage_for_path=effective_stage_for_path,
        is_terminal_clean_asset_triage=is_terminal_clean_asset_triage,
        make_terminal_asset_result=make_terminal_asset_result,
        yara_scan_with_optional_zip=yara_scan_with_optional_zip,
    )
    if terminal_result is not None:
        return terminal_result, active_timeout_budget, cache_sha256, tags, suspicious, curr_stage, None, False, [], route_tag_evidence, router_identity
    return prepare_full_inmemory_analysis_inputs(
        path=path,
        tags=tags,
        tag_evidence=route_tag_evidence,
        router_identity=router_identity,
        suspicious=suspicious,
        curr_stage=curr_stage,
        per_file_timeout_sec=per_file_timeout_sec,
        active_timeout_budget=active_timeout_budget,
        cache_sha256=cache_sha256,
        timeout_budget_factory=timeout_budget_factory,
        recoverable_exceptions=recoverable_exceptions,
        should_escalate_after_inmemory_triage=lambda *args: should_escalate_after_inmemory_triage(
            path, tags, suspicious, prefilter_info, curr_stage
        ),
        get_scan_extension=get_scan_extension,
        scan_file_inmemory_raw=scan_file_inmemory_raw,
        inmemory_raw_scan_dependencies=inmemory_raw_scan_dependencies,
        compiled_rules=compiled_rules,
        yara_enabled=yara_enabled,
        yara_scan_with_optional_zip=yara_scan_with_optional_zip,
        progress=progress,
    )
__all__ = (
    "cached_inmemory_scan_result",
    "cache_or_prefilter_inmemory_state",
    "inmemory_analysis_method",
    "prefilter_inmemory_context",
    "prepare_inmemory_analysis_inputs",
    "terminal_inmemory_triage_result",
    "terminal_or_triaged_inmemory_state",
)
