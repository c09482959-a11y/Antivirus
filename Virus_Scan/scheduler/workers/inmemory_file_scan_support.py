"""No-hook support helpers for in-memory single-file worker scans."""
from __future__ import annotations

import time
from collections.abc import Callable

from Virus_Scan.contracts.no_hook_materialization import no_hook_mapping_items
from Virus_Scan.scheduler.execution.scheduler_yara_result import publish_scheduler_yara_result
from Virus_Scan.scheduler.evidence.inmemory_route_identity import attach_inmemory_route_identity
from Virus_Scan.scheduler.workers.inmemory_file_scan_support_evidence import inmemory_worker_config_decision, inmemory_worker_text_decision
from Virus_Scan.scheduler.internal.mapping_item_lookup import scheduler_mapping_value
from Virus_Scan.scheduler.internal.no_hook_diagnostics import (
    scheduler_bool,
    scheduler_evidence_path,
    scheduler_exception_text,
    scheduler_float,
    scheduler_int,
)
from Virus_Scan.utils.tagging import normalize_tags


def owned_cfg_snapshot(cfg: object) -> dict[object, object] | None:
    return inmemory_worker_config_decision(cfg).snapshot


def cfg_value(cfg: dict[object, object], name: str, default: object = None) -> object:
    return dict.get(cfg, name, default)


def worker_int(value: object, *, default: int = 0, minimum: int = 0, reason: str) -> int:
    parsed, _parse_reason = scheduler_int(value, default=default, minimum=minimum, reason=reason)
    return parsed


def worker_float(value: object, *, default: float = 0.0, minimum: float = 0.0, reason: str) -> float:
    parsed, _parse_reason = scheduler_float(value, default=default, minimum=minimum, reason=reason)
    return parsed


def worker_bool(value: object, *, default: bool = False) -> bool:
    parsed, _parse_reason = scheduler_bool(value, default=default, reason="inmemory_worker_bool_rejected")
    return parsed


def worker_mapping_available(value: object) -> bool:
    return no_hook_mapping_items(value) is not None


def worker_non_empty_text(value: object) -> str:
    return inmemory_worker_text_decision(value).text

def collect_inmemory_raw_triage(
    *,
    path: object,
    tags: object,
    suspicious: object,
    curr_stage: object,
    per_file_timeout_sec: int,
    scan_file_inmemory_raw: Callable[..., object],
    inmemory_raw_scan_dependencies: Callable[[], object],
) -> tuple[object, bool, list[object], bool, object]:
    """Collect deep raw worker evidence and merge replayable triage fields."""
    global_raw_info = scan_file_inmemory_raw(
        path,
        timeout_sec=per_file_timeout_sec,
        pretriage_tags=tags,
        pretriage_suspicious=suspicious,
        pretriage_stage=curr_stage,
        deps=inmemory_raw_scan_dependencies(),
    )
    raw_info_available = worker_mapping_available(global_raw_info)
    if raw_info_available:
        tags = normalize_tags(list(tags or []) + list(scheduler_mapping_value(global_raw_info, 'tags', ()) or ()))
        raw_suspicious = worker_bool(scheduler_mapping_value(global_raw_info, 'suspicious'), default=False)
        suspicious = bool(suspicious is True or raw_suspicious is True)
        curr_stage = worker_non_empty_text(scheduler_mapping_value(global_raw_info, 'effective_stage')) or curr_stage
    return global_raw_info, raw_info_available, tags, suspicious, curr_stage

def complete_inmemory_analysis_result(
    *,
    path: object,
    tags: object,
    tag_evidence: object,
    yara_hits: object,
    prev_stage: str,
    curr_stage: object,
    suspicious: object,
    global_raw_info: object,
    raw_info_available: bool,
    started_file: float,
    slow_file_warn_sec: float,
    active_timeout_budget: object,
    cache_sha256: object,
    compiled_rules: object,
    analyze_file_full_observe_only: Callable[..., object],
    scan_session_snapshot: object,
    artifact_read_snapshot: object,
    routing_evidence_context: object,
    router_identity: object,
) -> tuple[object, object]:
    """Build the full-analysis result and attach worker-owned evidence fields."""
    raw_strings_blob = scheduler_mapping_value(global_raw_info, 'strings_blob', '') if raw_info_available else ''
    strings_blob = worker_non_empty_text(raw_strings_blob)
    result = analyze_file_full_observe_only(
        path,
        tags=tag_evidence,
        yara_hits=yara_hits,
        prev_stage=prev_stage,
        curr_stage=curr_stage,
        strings_blob=strings_blob,
        strings_already_enriched=raw_info_available,
        scan_session_snapshot=scan_session_snapshot,
        artifact_read_snapshot=artifact_read_snapshot,
        routing_evidence_context=routing_evidence_context,
        router_identity=router_identity,
    )
    if isinstance(result, dict):
        result['tags'] = normalize_tags(list(tags or []) + list(result.get('tags') or []))
    result['effective_stage'] = curr_stage
    result['suspicious_type_router'] = suspicious
    publish_scheduler_yara_result(result, yara_hits)
    elapsed_file = time.time() - started_file
    result['scan_duration_seconds'] = round(elapsed_file, 6)
    result['timeout_evidence'] = active_timeout_budget.as_evidence()
    if slow_file_warn_sec and elapsed_file > slow_file_warn_sec:
        result['slow_file_seconds'] = round(elapsed_file, 3)
    attach_inmemory_route_identity(result, router_identity)
    return path, result


def build_inmemory_timeout_result(
    *,
    path: object,
    error: BaseException,
    active_timeout_budget: object,
    timeout_result_annotator: Callable[..., object],
) -> tuple[object, object]:
    """Return a timeout result annotated by the injected timeout owner."""
    timeout_result = {
        'file': scheduler_evidence_path(path, field_name='worker_scan_path'),
        'error': scheduler_exception_text(error),
        'class': 'ERROR',
        'score': 0,
        'tags': ['file_timeout'],
    }
    return (
        path,
        timeout_result_annotator(
            timeout_result,
            active_timeout_budget,
            worker_state='queue_worker_hard_timeout',
            reason='hard_timeout_signal',
        ),
    )


def report_inmemory_worker_failure(
    *,
    path: object,
    error: BaseException,
    log_error: Callable[[str], object],
    record_scheduler_suppressed: Callable[..., object],
    recoverable_exceptions: tuple[type[BaseException], ...],
) -> None:
    """Log an in-memory worker failure without invoking caller-owned hooks."""
    try:
        log_error(
            str.__add__(
                str.__add__(
                    "in-memory worker failed for ",
                    scheduler_evidence_path(path, field_name='worker_scan_path'),
                ),
                str.__add__(": ", scheduler_exception_text(error)),
            )
        )
    except recoverable_exceptions as suppressed_exc:
        try:
            record_scheduler_suppressed('suppressed_exception', suppressed_exc)
        except recoverable_exceptions as reporting_exc:
            _ = reporting_exc


__all__ = (
    "build_inmemory_timeout_result",
    "cfg_value",
    "collect_inmemory_raw_triage",
    "complete_inmemory_analysis_result",
    "owned_cfg_snapshot",
    "report_inmemory_worker_failure",
    "worker_bool",
    "worker_float",
    "worker_int",
    "worker_mapping_available",
    "worker_non_empty_text",
)
