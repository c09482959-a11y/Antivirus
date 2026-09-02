"""Bounded helper steps for scheduler file analysis execution."""
from __future__ import annotations

from Virus_Scan.scheduler.execution.file_result_boundary import (
    execution_bool,
    execution_float,
    execution_path_text,
)
from Virus_Scan.scheduler.execution.scheduler_file_message_support import scheduler_slow_file_message


_IMAGE_DEEP_SCAN_EXTENSIONS = frozenset({".png", ".jpg", ".jpeg", ".webp", ".bmp", ".gif"})


def record_scheduler_slow_file(
    *,
    request: object,
    deps: object,
    path: object,
    result: dict[str, object],
    elapsed_file: float,
) -> None:
    """Record slow-file evidence when the configured threshold is exceeded."""
    slow_threshold = execution_float(
        request.slow_file_warn_sec,
        field_name="slow_file_warn_sec",
        minimum=0.0,
    )
    if slow_threshold <= 0.0 or elapsed_file <= slow_threshold:
        return
    path_text = execution_path_text(path, field_name="scan_path")
    deps.warn_slow_file(
        scheduler_slow_file_message(
            elapsed_file=elapsed_file,
            path_text=path_text,
            basename=deps.basename,
        )
    )
    result["slow_file_seconds"] = round(elapsed_file, 3)


def resolve_analysis_method(
    path: object,
    request: object,
    deps: object,
    *,
    deep_scan_escalated: bool,
) -> str:
    """Resolve the timeout-budget method for the analysis path."""
    analysis_method = "deep_scan" if deep_scan_escalated else "file_scan"
    try:
        ext_for_budget = deps.get_scan_extension(path)
    except deps.recoverable_exceptions:
        ext_for_budget = ""
    if deep_scan_escalated and ext_for_budget in _IMAGE_DEEP_SCAN_EXTENSIONS:
        return "deep_image_scan"
    if request.yara_enabled:
        return "yara_scan"
    return analysis_method


def compute_scheduler_analysis_budget(
    *,
    request: object,
    deps: object,
    path: object,
    tags: object,
    suspicious: bool,
    prefilter_info: dict[str, object],
    curr_stage: str,
) -> tuple[bool, object]:
    """Compute escalation state and the active analysis timeout budget."""
    deep_scan_escalated = execution_bool(
        deps.should_escalate_after_triage(
            path,
            tags,
            suspicious,
            prefilter_info,
            curr_stage,
            get_scan_extension=deps.get_scan_extension,
            deep_scan_thorough=deps.deep_scan_thorough,
            contextual_dangerous_anchor_hits=deps.contextual_dangerous_anchor_hits,
            record_suppressed_failure=deps.record_runtime_suppressed,
            recoverable_exceptions=deps.recoverable_exceptions,
        ),
        field_name="deep_scan_escalated",
    )
    analysis_method = resolve_analysis_method(
        path,
        request,
        deps,
        deep_scan_escalated=deep_scan_escalated,
    )
    active_timeout_budget = deps.compute_timeout_budget(
        path,
        configured_timeout_seconds=request.per_file_timeout_sec,
        method=analysis_method,
        tags=tags,
        deep_scan=deep_scan_escalated,
        artifact_read_snapshot=request.artifact_read_snapshot,
    )
    return deep_scan_escalated, active_timeout_budget


def build_scheduler_analysis_guard(*, request: object, deps: object, active_timeout_budget: object) -> object:
    """Build the timeout guard used around deep scheduler analysis."""
    if request.use_signal_timeout and deps.current_thread() is deps.main_thread():
        return deps.per_file_timeout(active_timeout_budget.hard_timeout_seconds)
    return deps.nullcontext_factory()


__all__ = (
    "build_scheduler_analysis_guard",
    "compute_scheduler_analysis_budget",
    "record_scheduler_slow_file",
)
