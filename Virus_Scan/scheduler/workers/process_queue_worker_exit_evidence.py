"""No-hook worker-exit result evidence materialization."""
from __future__ import annotations

import math

from Virus_Scan.contracts.no_hook_materialization import no_hook_type_name
from Virus_Scan.scheduler.internal.no_hook_attrs import scheduler_exact_attr
from Virus_Scan.scheduler.internal.exact_int_text_decision import ExactIntTextDecision, exact_int_text_decision
from Virus_Scan.scheduler.internal.no_hook_diagnostics import (
    scheduler_path_text,
    scheduler_tag_texts,
    scheduler_text,
)
from Virus_Scan.scheduler.workers.cleanup import WorkerExitWaitResult
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Mapping

def _worker_exit_output_text(output: object) -> tuple[str, str]:
    text, reason = scheduler_path_text(output)
    if reason == "" and text:
        return text, ""
    return "", reason or "worker_output_unavailable"


def _worker_exit_int_text_decision(value: str) -> ExactIntTextDecision:
    return exact_int_text_decision(
        value,
        empty_reason="worker_exit_integer_text_empty",
        sign_only_reason="worker_exit_integer_text_sign_only",
        digit_reason="worker_exit_integer_text_digits_rejected",
    )


def _worker_exit_int(value: object, replacement: int) -> tuple[int, str]:
    safe_replacement = replacement if type(replacement) is int and type(replacement) is not bool else 0
    if value is None:
        return safe_replacement, ""
    parsed: int
    if type(value) is bool:
        return safe_replacement, "worker_exit_integer_rejected"
    if type(value) is int:
        parsed = value
    elif type(value) is float:
        if not math.isfinite(value) or not value.is_integer():
            return safe_replacement, "worker_exit_integer_rejected"
        parsed = int(value)
    elif type(value) is str:
        decision = _worker_exit_int_text_decision(value)
        if not decision.accepted:
            return safe_replacement, "worker_exit_integer_rejected"
        parsed = decision.value
    elif type(value) is bytes:
        decision = _worker_exit_int_text_decision(bytes(value).decode("utf-8", "replace"))
        if not decision.accepted:
            return safe_replacement, "worker_exit_integer_rejected"
        parsed = decision.value
    elif type(value) is bytearray:
        decision = _worker_exit_int_text_decision(bytes(value).decode("utf-8", "replace"))
        if not decision.accepted:
            return safe_replacement, "worker_exit_integer_rejected"
        parsed = decision.value
    else:
        return safe_replacement, "worker_exit_integer_rejected"
    return parsed, ""


def _worker_exit_bool(value: object, replacement: bool) -> tuple[bool, str]:
    safe_replacement = replacement if type(replacement) is bool else False
    if type(value) is bool:
        return value, ""
    if type(value) is int:
        return value != 0, ""
    if type(value) is str:
        text = str.__str__(value).strip().lower()
        if text in {"1", "true", "yes", "on", "enabled"}:
            return True, ""
        if text in {"0", "false", "no", "off", "disabled", ""}:
            return False, ""
    return safe_replacement, "worker_exit_bool_rejected"


def _owned_worker_exit_wait_evidence(result: WorkerExitWaitResult) -> dict[str, object]:
    worker_idx, idx_reason = _worker_exit_int(scheduler_exact_attr(result, "worker_idx", owner_type=WorkerExitWaitResult), -1)
    worker_pid, pid_reason = _worker_exit_int(scheduler_exact_attr(result, "pid", owner_type=WorkerExitWaitResult), 0)
    worker_output, output_reason = _worker_exit_output_text(scheduler_exact_attr(result, "output", owner_type=WorkerExitWaitResult))
    status, status_reason = _worker_exit_int(scheduler_exact_attr(result, "status", owner_type=WorkerExitWaitResult), -1)
    timed_out, timed_out_reason = _worker_exit_bool(scheduler_exact_attr(result, "timed_out", owner_type=WorkerExitWaitResult), False)
    reason_text, reason_reason = scheduler_text(
        scheduler_exact_attr(result, "reason", owner_type=WorkerExitWaitResult),
        replacement_text="worker_final_wait",
        unsupported_reason="worker_exit_reason_rejected",
    )
    cleanup_actions = scheduler_tag_texts(scheduler_exact_attr(result, "cleanup_actions", owner_type=WorkerExitWaitResult))
    failure_markers = scheduler_tag_texts(scheduler_exact_attr(result, "failure_markers", owner_type=WorkerExitWaitResult))
    evidence: dict[str, object] = {
        "worker_idx": worker_idx,
        "worker_pid": worker_pid,
        "worker_output": worker_output,
        "worker_exit_status": status,
        "worker_wait_timed_out": timed_out,
        "worker_cleanup_actions": cleanup_actions,
        "worker_failure_markers": failure_markers,
        "worker_cleanup_reason": reason_text or "worker_final_wait",
    }
    rejected = tuple(
        reason
        for reason in (idx_reason, pid_reason, output_reason, status_reason, timed_out_reason, reason_reason)
        if reason
    )
    if rejected:
        evidence["worker_exit_field_rejections"] = rejected
        evidence["worker_exit_status_materialization_failed"] = True
    return evidence


def _int_worker_exit_status_evidence(exit_result: int, *, idx: object, output: object) -> dict[str, object]:
    worker_idx, idx_reason = _worker_exit_int(idx, -1)
    worker_output, output_reason = _worker_exit_output_text(output)
    status = int.__int__(exit_result)
    evidence: dict[str, object] = {
        "worker_idx": worker_idx,
        "worker_output": worker_output,
        "worker_exit_status": status,
        "worker_wait_timed_out": False,
        "worker_cleanup_actions": (),
        "worker_failure_markers": (),
        "worker_cleanup_reason": "worker_final_wait_status",
    }
    rejected = tuple(reason for reason in (idx_reason, output_reason) if reason)
    if rejected:
        evidence["worker_exit_field_rejections"] = rejected
    return evidence


def _unsupported_worker_exit_result_evidence(exit_result: object, *, idx: object, output: object) -> dict[str, object]:
    worker_idx, idx_reason = _worker_exit_int(idx, -1)
    worker_output, output_reason = _worker_exit_output_text(output)
    evidence: dict[str, object] = {
        "worker_idx": worker_idx,
        "worker_output": worker_output,
        "worker_exit_status": -1,
        "worker_wait_timed_out": False,
        "worker_cleanup_actions": (),
        "worker_failure_markers": ("queue_worker_exit_result_unsupported",),
        "worker_cleanup_reason": "worker_exit_result_unsupported",
        "worker_exit_result_unsupported": True,
        "worker_exit_result_type": no_hook_type_name(exit_result),
        "error_category": "scheduler_worker_exit_result_unsupported",
        "error_source": "scheduler.workers.process_queue_worker_exit",
        "final_json_must_record": True,
        "checkpoint_must_record": True,
        "replay_must_record": True,
    }
    rejected = tuple(reason for reason in (idx_reason, output_reason) if reason)
    if rejected:
        evidence["worker_exit_field_rejections"] = rejected
    return evidence


def _worker_exit_result_evidence(exit_result: object, *, idx: object, output: object) -> dict[str, object]:
    if type(exit_result) is WorkerExitWaitResult:
        return _owned_worker_exit_wait_evidence(exit_result)
    if type(exit_result) is int:
        return _int_worker_exit_status_evidence(exit_result, idx=idx, output=output)
    return _unsupported_worker_exit_result_evidence(exit_result, idx=idx, output=output)


def _worker_exit_status(evidence: Mapping[str, object]) -> int:
    status, _reason = _worker_exit_int(evidence.get("worker_exit_status"), -1)
    return status


def _worker_exit_infrastructure_failed(evidence: Mapping[str, object]) -> bool:
    unsupported, _reason = _worker_exit_bool(evidence.get("worker_exit_result_unsupported"), False)
    if unsupported:
        return True
    status = _worker_exit_status(evidence)
    return status == 4 or status < 0


def _worker_tuple_parts(worker_entry: object, position: int) -> tuple[object, object | None, object | None, bool]:
    if type(worker_entry) is tuple and len(worker_entry) >= 3:
        return worker_entry[0], worker_entry[1], worker_entry[2], True
    evidence_idx = position
    return evidence_idx, None, None, False


__all__ = (
    "_unsupported_worker_exit_result_evidence",
    "_worker_exit_bool",
    "_worker_exit_infrastructure_failed",
    "_worker_exit_int",
    "_worker_exit_output_text",
    "_worker_exit_result_evidence",
    "_worker_exit_status",
    "_worker_tuple_parts",
)
