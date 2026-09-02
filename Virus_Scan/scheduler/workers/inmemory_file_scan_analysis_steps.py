"""Bounded full-analysis preparation steps for in-memory file scans."""
from __future__ import annotations

from collections.abc import Callable

from Virus_Scan.scheduler.workers.inmemory_file_scan_support import collect_inmemory_raw_triage
from Virus_Scan.detection.api.tag_evidence_contracts import TagEvidence
from Virus_Scan.scheduler.execution.scheduler_yara_result import obtain_scheduler_yara_result


def inmemory_analysis_method(
    *,
    path: object,
    deep_scan_escalated: bool,
    get_scan_extension: Callable[[object], str],
    recoverable_exceptions: tuple[type[BaseException], ...],
) -> str:
    """Return the timeout-budget analysis method for the selected worker path."""
    analysis_method = 'deep_scan' if deep_scan_escalated else 'file_scan'
    try:
        ext_for_budget = get_scan_extension(path)
    except recoverable_exceptions:
        ext_for_budget = ''
    if deep_scan_escalated and ext_for_budget in {'.png', '.jpg', '.jpeg', '.webp', '.bmp', '.gif'}:
        return 'deep_image_scan'
    return analysis_method


def build_inmemory_full_analysis_inputs(
    *,
    path: object,
    tags: object,
    tag_evidence: object,
    suspicious: object,
    curr_stage: object,
    per_file_timeout_sec: int,
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
) -> tuple[object, object, object, object, object, bool, object, object]:
    """Prepare full-analysis timeout budget and optional raw triage context."""
    deep_scan_escalated = bool(
        should_escalate_after_inmemory_triage(
            path,
            tags,
            suspicious,
            None,
            curr_stage,
        )
    )
    analysis_method = inmemory_analysis_method(
        path=path,
        deep_scan_escalated=deep_scan_escalated,
        get_scan_extension=get_scan_extension,
        recoverable_exceptions=recoverable_exceptions,
    )
    active_timeout_budget = timeout_budget_factory(
        path,
        configured_timeout_seconds=per_file_timeout_sec,
        method=analysis_method,
        tags=tags,
        deep_scan=deep_scan_escalated,
    )
    global_raw_info = None
    raw_info_available = False
    if deep_scan_escalated:
        progress('raw_collect')
        global_raw_info, raw_info_available, tags, suspicious, curr_stage = collect_inmemory_raw_triage(
            path=path,
            tags=tags,
            suspicious=suspicious,
            curr_stage=curr_stage,
            per_file_timeout_sec=per_file_timeout_sec,
            scan_file_inmemory_raw=scan_file_inmemory_raw,
            inmemory_raw_scan_dependencies=inmemory_raw_scan_dependencies,
        )
        if type(global_raw_info) is dict:
            raw_tag_evidence = dict.get(global_raw_info, 'tag_evidence')
            if type(raw_tag_evidence) is TagEvidence:
                route_records = tag_evidence.records if type(tag_evidence) is TagEvidence else ()
                tag_evidence = TagEvidence.from_records(
                    (*route_records, *raw_tag_evidence.records),
                )
    raw_yara_result = (
        dict.get(global_raw_info, "yara_evidence")
        if type(global_raw_info) is dict
        else None
    )
    if raw_yara_result is None:
        progress('yara_full')
    yara_hits = obtain_scheduler_yara_result(
        path=path,
        yara_enabled=yara_enabled,
        compiled_rules=compiled_rules,
        yara_scan_with_optional_zip=yara_scan_with_optional_zip,
        existing_result=raw_yara_result,
    )
    return (
        active_timeout_budget,
        tags,
        suspicious,
        curr_stage,
        global_raw_info,
        raw_info_available,
        yara_hits,
        tag_evidence,
    )


__all__ = ("build_inmemory_full_analysis_inputs", "inmemory_analysis_method")
