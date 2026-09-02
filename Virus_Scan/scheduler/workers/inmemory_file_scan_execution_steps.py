"""Bounded preparation steps for in-memory file scan execution."""
from __future__ import annotations

from collections.abc import Callable

from Virus_Scan.scheduler.workers.inmemory_file_scan_analysis_steps import build_inmemory_full_analysis_inputs
from Virus_Scan.scheduler.workers.inmemory_triage_result import InMemoryTriageResult


def cache_or_prefilter_inmemory_state(
    *,
    path: object,
    started_file: float,
    slow_file_warn_sec: float,
    active_timeout_budget: object,
    compiled_rules: object,
    cache_execution_identity: object,
    artifact_read_snapshot: object,
    progress: Callable[[str], object],
    cached_inmemory_scan_result: Callable[..., tuple[object, object | None]],
    prefilter_inmemory_context: Callable[..., object],
    pre_scan_cache_lookup: Callable[..., object],
    strict_fast_prefilter: Callable[..., object],
) -> tuple[object | None, object, object]:
    """Run cache and fast-prefilter short-circuit checks before type scan."""
    progress('cache_lookup')
    cache_sha256, cache_result = cached_inmemory_scan_result(
        path=path,
        started_file=started_file,
        slow_file_warn_sec=slow_file_warn_sec,
        active_timeout_budget=active_timeout_budget,
        compiled_rules=compiled_rules,
        cache_execution_identity=cache_execution_identity,
        artifact_read_snapshot=artifact_read_snapshot,
        pre_scan_cache_lookup=pre_scan_cache_lookup,
    )
    if cache_result is not None:
        return cache_result, cache_sha256, {}
    progress('prefilter')
    prefilter_info = prefilter_inmemory_context(
        path=path,
        compiled_rules=compiled_rules,
        artifact_read_snapshot=artifact_read_snapshot,
        strict_fast_prefilter=strict_fast_prefilter,
    )
    return None, cache_sha256, prefilter_info


def terminal_or_triaged_inmemory_state(
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
    progress: Callable[[str], object],
    terminal_inmemory_triage_result: Callable[..., InMemoryTriageResult],
    scan_file_by_type: Callable[..., object],
    effective_stage_for_path: Callable[..., object],
    is_terminal_clean_asset_triage: Callable[..., bool],
    make_terminal_asset_result: Callable[..., object],
    yara_scan_with_optional_zip: Callable[..., object],
) -> tuple[object | None, object, object, object, object, object]:
    """Return terminal triage result or the state required for full analysis."""
    progress('type_scan')
    triage = terminal_inmemory_triage_result(
        path=path,
        prefilter_info=prefilter_info,
        prev_stage=prev_stage,
        cache_sha256=cache_sha256,
        active_timeout_budget=active_timeout_budget,
        compiled_rules=compiled_rules,
        yara_enabled=yara_enabled,
        scan_session_snapshot=scan_session_snapshot,
        artifact_read_snapshot=artifact_read_snapshot,
        yara_scan_with_optional_zip=yara_scan_with_optional_zip,
        scan_file_by_type=scan_file_by_type,
        effective_stage_for_path=effective_stage_for_path,
        is_terminal_clean_asset_triage=is_terminal_clean_asset_triage,
        make_terminal_asset_result=make_terminal_asset_result,
    )
    if type(triage) is not InMemoryTriageResult:
        raise TypeError("inmemory_triage_result_contract_invalid")
    return (
        triage.terminal_result, triage.tags, triage.suspicious, triage.current_stage,
        triage.tag_evidence, triage.router_identity,
    )


def prepare_full_inmemory_analysis_inputs(
    *,
    path: object,
    tags: object,
    tag_evidence: object,
    router_identity: object,
    suspicious: object,
    curr_stage: object,
    per_file_timeout_sec: int,
    active_timeout_budget: object,
    cache_sha256: object,
    timeout_budget_factory: Callable[..., object],
    recoverable_exceptions: tuple[type[BaseException], ...],
    should_escalate_after_inmemory_triage: Callable[..., object],
    get_scan_extension: Callable[[object], str],
    scan_file_inmemory_raw: Callable[..., object],
    inmemory_raw_scan_dependencies: Callable[[], object],
    compiled_rules: object,
    yara_enabled: bool,
    yara_scan_with_optional_zip: Callable[..., object],
    progress: Callable[[str], object],
) -> tuple[object | None, object, object, object, object, object, object, bool, list[object], object, object]:
    """Build full-analysis inputs after cache, prefilter, and terminal triage miss."""
    (
        active_timeout_budget,
        tags,
        suspicious,
        curr_stage,
        global_raw_info,
        raw_info_available,
        yara_hits,
        tag_evidence,
    ) = build_inmemory_full_analysis_inputs(
        path=path,
        tags=tags,
        tag_evidence=tag_evidence,
        suspicious=suspicious,
        curr_stage=curr_stage,
        per_file_timeout_sec=per_file_timeout_sec,
        timeout_budget_factory=timeout_budget_factory,
        recoverable_exceptions=recoverable_exceptions,
        should_escalate_after_inmemory_triage=should_escalate_after_inmemory_triage,
        get_scan_extension=get_scan_extension,
        scan_file_inmemory_raw=scan_file_inmemory_raw,
        inmemory_raw_scan_dependencies=inmemory_raw_scan_dependencies,
        compiled_rules=compiled_rules,
        yara_enabled=yara_enabled,
        yara_scan_with_optional_zip=yara_scan_with_optional_zip,
        progress=progress,
    )
    return None, active_timeout_budget, cache_sha256, tags, suspicious, curr_stage, global_raw_info, raw_info_available, yara_hits, tag_evidence, router_identity


__all__ = (
    "cache_or_prefilter_inmemory_state",
    "prepare_full_inmemory_analysis_inputs",
    "terminal_or_triaged_inmemory_state",
)
