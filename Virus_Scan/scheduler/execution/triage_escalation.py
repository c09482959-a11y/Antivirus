"""Scheduler scan-job post-triage escalation policy."""
from __future__ import annotations

from typing import Callable, Mapping, TYPE_CHECKING

from Virus_Scan.scheduler.execution.triage_escalation_support import (
    ESCALATION_TAGS,
    EXECUTION_TAGS,
    HIGH_RISK_EXTS,
    anchor_requires_escalation,
    prefilter_requires_escalation,
    record_boundary_rejection,
    scheduler_text,
    tag_snapshot,
    truthy_scheduler_flag,
)

if TYPE_CHECKING:
    from collections.abc import Iterable


def _extension_snapshot(
    *,
    path: object,
    get_scan_extension: Callable[[object], str],
    record_suppressed_failure: Callable[[str, BaseException], object],
    recoverable_exceptions: tuple[type[BaseException], ...],
) -> tuple[str, bool]:
    extension_failure_reason = ""
    try:
        ext_value = get_scan_extension(path)
    except recoverable_exceptions as exc:
        record_suppressed_failure("scheduler_triage_extension_failed", exc)
        extension_failure_reason = "scheduler_triage_extension_failed"
        ext_value = ""
    if extension_failure_reason:
        return "", True
    ext, ext_reason = scheduler_text(
        ext_value,
        unsupported_reason="scheduler_triage_extension_rejected",
    )
    if ext_reason:
        record_boundary_rejection(
            record_suppressed_failure,
            "scheduler_triage_extension_rejected",
            ext_reason,
        )
        return "", True
    return ext, False


def should_escalate_after_triage(
    path: object,
    tags: object,
    suspicious: object,
    prefilter_info: Mapping[str, object] | None,
    curr_stage: object,
    *,
    get_scan_extension: Callable[[object], str],
    deep_scan_thorough: Callable[[], bool],
    contextual_dangerous_anchor_hits: Callable[[Iterable[object] | None], list[str]],
    record_suppressed_failure: Callable[[str, BaseException], object],
    recoverable_exceptions: tuple[type[BaseException], ...],
) -> bool:
    """Return whether scheduler execution should escalate after fast triage."""
    _ = curr_stage
    tagset, tag_reason = tag_snapshot(tags)
    if tag_reason:
        record_boundary_rejection(
            record_suppressed_failure,
            "scheduler_triage_tags_rejected",
            tag_reason,
        )
        return True
    ext, extension_rejected = _extension_snapshot(
        path=path,
        get_scan_extension=get_scan_extension,
        record_suppressed_failure=record_suppressed_failure,
        recoverable_exceptions=recoverable_exceptions,
    )
    if extension_rejected:
        return True
    thorough, thorough_escalates = truthy_scheduler_flag(
        value=deep_scan_thorough(),
        reason="scheduler_deep_scan_mode_rejected",
        record_suppressed_failure=record_suppressed_failure,
    )
    if thorough or thorough_escalates:
        return True
    suspicious_flag, suspicious_escalates = truthy_scheduler_flag(
        value=suspicious,
        reason="scheduler_suspicious_flag_rejected",
        record_suppressed_failure=record_suppressed_failure,
    )
    if suspicious_flag or suspicious_escalates:
        return True
    if prefilter_requires_escalation(
        prefilter_info=prefilter_info,
        record_suppressed_failure=record_suppressed_failure,
    ):
        return True
    if tagset & ESCALATION_TAGS:
        return True
    if anchor_requires_escalation(
        tagset=tagset,
        contextual_dangerous_anchor_hits=contextual_dangerous_anchor_hits,
        record_suppressed_failure=record_suppressed_failure,
        recoverable_exceptions=recoverable_exceptions,
    ):
        return True
    return ext in HIGH_RISK_EXTS and len(tagset & EXECUTION_TAGS) > 0


__all__ = ("should_escalate_after_triage",)
