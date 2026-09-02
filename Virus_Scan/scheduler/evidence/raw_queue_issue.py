"""Attributable raw-queue infrastructure issue telemetry."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Mapping

from Virus_Scan.contracts.no_hook_materialization import no_hook_mapping_items, no_hook_text
from Virus_Scan.scheduler.internal.immutable_outputs import materialize_scheduler_mapping
from Virus_Scan.scheduler.internal.immutable_output_support import unsupported_scheduler_value_evidence


_UNSUPPORTED_EXTRA_KEY_PREFIX = "unsupported_extra_key_"


@dataclass(frozen=True, slots=True)
class RawQueueIssueExtraDecision:
    extra: dict[str, object]
    reason: str
    accepted: bool


def _issue_extra_decision(extra: Mapping[str, object] | None) -> RawQueueIssueExtraDecision:
    if extra is None:
        return RawQueueIssueExtraDecision(extra={}, reason="raw_queue_issue_extra_absent", accepted=True)
    items = no_hook_mapping_items(extra)
    if items is None:
        return RawQueueIssueExtraDecision(
            extra={
                "raw_queue_extra_unavailable": True,
                "raw_queue_extra_failure": unsupported_scheduler_value_evidence(extra, field_name="raw_queue_issue_extra"),
            },
            reason="raw_queue_issue_extra_unsupported",
            accepted=False,
        )
    out: dict[str, object] = {}
    accepted = True
    for index, (key, value) in enumerate(items):
        key_text, reason = no_hook_text(
            key,
            missing_reason="raw_queue_issue_extra_key_missing",
            unsupported_reason="raw_queue_issue_extra_key_unsafe",
        )
        if reason or key_text == "":
            accepted = False
            field_name = _UNSUPPORTED_EXTRA_KEY_PREFIX + int.__str__(index)
            out[field_name] = unsupported_scheduler_value_evidence(key, field_name=field_name)
            continue
        out[key_text] = materialize_scheduler_mapping(value)
    return RawQueueIssueExtraDecision(
        extra=out,
        reason="raw_queue_issue_extra_materialized" if accepted else "raw_queue_issue_extra_key_rejected",
        accepted=accepted,
    )


def _issue_extra(extra: Mapping[str, object] | None) -> dict[str, object]:
    return _issue_extra_decision(extra).extra


def record_raw_queue_issue(
    stage: object,
    exc: BaseException,
    *,
    fatal: bool = False,
    extra: Mapping[str, object] | None = None,
    record_scheduler_suppressed: Callable[..., object],
    record_raw_suppressed: Callable[[str, BaseException], object],
    recoverable_exceptions: tuple[type[BaseException], ...],
) -> None:
    """Record raw-queue infrastructure issues without hiding failures."""
    marker, marker_reason = no_hook_text(
        stage,
        missing_reason="raw_queue_issue_stage_missing",
        unsupported_reason="raw_queue_issue_stage_unsafe",
    )
    if marker_reason or marker == "":
        marker = "raw_queue_issue"
        if not marker_reason:
            marker_reason = "raw_queue_issue_stage_missing"
    fatal_value = fatal if type(fatal) is bool else False
    try:
        payload: dict[str, object] = {"raw_queue_stage": marker, "fatal": fatal_value}
        if marker_reason:
            payload["raw_queue_stage_rejected"] = True
            payload["raw_queue_stage_rejection_reason"] = marker_reason
        if type(fatal) is not bool:
            payload["fatal_rejected"] = True
            payload["fatal_rejection"] = unsupported_scheduler_value_evidence(fatal, field_name="raw_queue_issue_fatal")
        payload.update(_issue_extra(extra))
        try:
            record_scheduler_suppressed(marker, exc, extra=payload)
        except TypeError:
            record_scheduler_suppressed(marker, exc)
    except recoverable_exceptions:
        try:
            record_raw_suppressed(marker, exc)
        except recoverable_exceptions as telemetry_exc:
            record_raw_suppressed(marker + ".telemetry_failed", telemetry_exc)
