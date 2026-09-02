"""Canonical raw queue failure payload construction."""

from __future__ import annotations

import os
import time
from dataclasses import dataclass

from Virus_Scan.contracts.no_hook_materialization import no_hook_mapping_items, no_hook_text, no_hook_type_name
from Virus_Scan.scheduler.evidence.queue_failure_text_support import queue_failure_text_value
from Virus_Scan.scheduler.internal.immutable_outputs import materialize_scheduler_mapping
from Virus_Scan.scheduler.internal.immutable_output_support import unsupported_scheduler_value_evidence


_UNSUPPORTED_EXTRA_KEY_PREFIX = "unsupported_extra_key_"


@dataclass(frozen=True, slots=True)
class QueueExtraItemsDecision:
    items: tuple[tuple[str, object], ...]
    reason: str
    accepted: bool


def _queue_extra_items_decision(extra: object) -> QueueExtraItemsDecision:
    items = no_hook_mapping_items(extra)
    if items is None:
        if extra is None:
            return QueueExtraItemsDecision(items=(), reason="failure_info_extra_absent", accepted=True)
        return QueueExtraItemsDecision(
            items=((
                "extra_unavailable",
                unsupported_scheduler_value_evidence(extra, field_name="failure_info_extra"),
            ),),
            reason="failure_info_extra_unsupported",
            accepted=False,
        )
    out: list[tuple[str, object]] = []
    accepted = True
    for index, (key, value) in enumerate(items):
        fallback_field = _UNSUPPORTED_EXTRA_KEY_PREFIX + int.__str__(index)
        field, reason = queue_failure_text_value(
            key,
            default=fallback_field,
            missing_reason="failure_info_extra_key_missing",
            unsupported_reason="failure_info_extra_key_unsafe",
        )
        if reason:
            accepted = False
            out.append((field, unsupported_scheduler_value_evidence(key, field_name=field)))
            continue
        out.append((field, materialize_scheduler_mapping(value)))
    return QueueExtraItemsDecision(
        items=tuple(out),
        reason="failure_info_extra_materialized" if accepted else "failure_info_extra_key_rejected",
        accepted=accepted,
    )


def _queue_extra_items(extra: object) -> tuple[tuple[str, object], ...]:
    return _queue_extra_items_decision(extra).items


def default_failure_info(
    stage: object="queue_failed",
    error: object="queue job failed",
    *,
    exception_type: object="QueueFailure",
    worker_pid: object=None,
    attempt: object=None,
    extra: object=None,
) -> object:
    """Build a durable queue failure_info payload without scanner-score side effects."""
    stage_text, stage_reason = queue_failure_text_value(
        stage,
        default="queue_failed",
        missing_reason="queue_failure_stage_missing",
        unsupported_reason="queue_failure_stage_unsafe",
    )
    exception_type_text, exception_type_reason = no_hook_text(
        exception_type,
        missing_reason="queue_failure_exception_type_missing",
        unsupported_reason="queue_failure_exception_type_unsafe",
    )
    if exception_type_reason or exception_type_text == "":
        exception_type_text = no_hook_type_name(exception_type)
        if not exception_type_reason:
            exception_type_reason = "queue_failure_exception_type_missing"
    error_text, error_reason = queue_failure_text_value(
        error,
        default="queue job failed",
        missing_reason="queue_failure_error_missing",
        unsupported_reason="queue_failure_error_unsafe",
    )
    if type(worker_pid) is int and type(worker_pid) is not bool:
        worker_pid_value: object = worker_pid
    elif type(worker_pid) is str:
        worker_pid_text = str.__str__(worker_pid).strip()
        worker_pid_value = int(worker_pid_text) if worker_pid_text.lstrip("-").isdigit() else worker_pid_text
    elif worker_pid is None:
        worker_pid_value = os.getpid()
    else:
        worker_pid_value = unsupported_scheduler_value_evidence(worker_pid, field_name="worker_pid")
    info = {
        "stage": stage_text,
        "exception_type": exception_type_text,
        "error": error_text[:2000],
        "worker_pid": worker_pid_value,
        "attempt": attempt if type(attempt) is int and type(attempt) is not bool else attempt if attempt is None else unsupported_scheduler_value_evidence(attempt, field_name="attempt"),
        "time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    reasons = tuple(reason for reason in (stage_reason, exception_type_reason, error_reason) if reason)
    if reasons:
        info["failure_info_rejection_reasons"] = reasons
        info["failure_info_has_rejected_fields"] = True
    for key, value in _queue_extra_items(extra):
        if key not in info:
            info[key] = value
    return info
