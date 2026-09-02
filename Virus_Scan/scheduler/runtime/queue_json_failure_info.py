"""Queue failure info materialization for scheduler JSON diagnostics."""
from __future__ import annotations

import time

from Virus_Scan.contracts.no_hook_materialization import no_hook_mapping_items
from Virus_Scan.scheduler.evidence.queue_failure_text_support import queue_failure_text_value
from Virus_Scan.scheduler.internal.immutable_output_support import unsupported_scheduler_value_evidence
from Virus_Scan.scheduler.internal.immutable_outputs import materialize_scheduler_mapping


def _queue_failure_extra(extra: object) -> tuple[tuple[str, object], ...]:
    items = no_hook_mapping_items(extra)
    if items is None:
        if extra is None:
            return ()
        return ((
            "extra_unavailable",
            unsupported_scheduler_value_evidence(extra, field_name="queue_failure_extra"),
        ),)
    out: list[tuple[str, object]] = []
    for index, (key, value) in enumerate(items):
        field, reason = queue_failure_text_value(
            key,
            default="_".join(("unsupported_extra_key", int.__str__(index))),
            missing_reason="queue_failure_extra_key_missing",
            unsupported_reason="queue_failure_extra_key_unsafe",
        )
        if reason:
            out.append((field, unsupported_scheduler_value_evidence(key, field_name=field)))
            continue
        out.append((field, materialize_scheduler_mapping(value)))
    return tuple(out)


def queue_default_failure_info(
    stage: str,
    *,
    exception_type: object = None,
    error: object = None,
    worker_pid: object = None,
    attempt: object = None,
    extra: object = None,
) -> dict[str, object]:
    stage_text, stage_reason = queue_failure_text_value(
        stage,
        default="queue_failed",
        missing_reason="queue_failure_stage_missing",
        unsupported_reason="queue_failure_stage_unsafe",
    )
    exception_type_text, exception_type_reason = queue_failure_text_value(
        "QueueFailure" if exception_type is None else exception_type,
        default="QueueFailure",
        missing_reason="queue_failure_exception_type_missing",
        unsupported_reason="queue_failure_exception_type_unsafe",
    )
    error_text, error_reason = queue_failure_text_value(
        "queue job failed" if error is None else error,
        default="queue job failed",
        missing_reason="queue_failure_error_missing",
        unsupported_reason="queue_failure_error_unsafe",
    )
    info: dict[str, object] = {
        "stage": stage_text,
        "exception_type": exception_type_text,
        "error": error_text,
        "time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    reasons = tuple(reason for reason in (stage_reason, exception_type_reason, error_reason) if reason)
    if reasons:
        info["failure_info_rejection_reasons"] = reasons
        info["failure_info_has_rejected_fields"] = True
    if worker_pid is not None:
        info["worker_pid"] = worker_pid if type(worker_pid) in {str, int} else unsupported_scheduler_value_evidence(worker_pid, field_name="worker_pid")
    if attempt is not None:
        info["attempt"] = attempt if type(attempt) is int and type(attempt) is not bool else unsupported_scheduler_value_evidence(attempt, field_name="attempt")
    for key, value in _queue_failure_extra(extra):
        _queue_failure_field(info, key, value)
    return info


def _queue_failure_field(info: dict[str, object], key: str, value: object) -> None:
    if key not in info:
        info[key] = value
