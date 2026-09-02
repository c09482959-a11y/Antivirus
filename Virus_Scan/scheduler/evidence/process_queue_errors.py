"""Process-queue evidence/error reporting owner.

Batch 2 scheduler decomposition assigns operator diagnostics and suppressed
failure telemetry to scheduler.evidence.  This module owns process-queue
suppressed-failure publication and best-effort error logging without mutating
queue lifecycle, scanner results, or reconciliation state.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from typing import Mapping

from Virus_Scan.contracts.no_hook_materialization import no_hook_text, no_hook_type_name
from Virus_Scan.core.logging import log_error as _process_queue_core_log_error
from Virus_Scan.runtime.api import record_suppressed_failure as _runtime_record_suppressed_failure
from Virus_Scan.scheduler.internal.immutable_outputs import materialize_scheduler_mapping
from Virus_Scan.scheduler.internal.no_hook_diagnostics import scheduler_error_detail



@dataclass(frozen=True, slots=True)
class ProcessQueueExtraDecision:
    extra: dict[str, object]
    reason: str
    accepted: bool

def _process_queue_token(value: object, *, default_value: str = "process_queue") -> str:
    text, reason = no_hook_text(value, unsupported_reason="process_queue_token_rejected")
    if reason == "" and text:
        return text
    return default_value


def _process_queue_extra_decision(extra: Mapping[str, object] | None) -> ProcessQueueExtraDecision:
    if extra is None:
        return ProcessQueueExtraDecision(extra={}, reason="process_queue_extra_absent", accepted=True)
    if type(extra) is not dict:
        return ProcessQueueExtraDecision(
            extra={"extra_unavailable_reason": "unsupported_process_queue_extra", "extra_type": no_hook_type_name(extra)},
            reason="unsupported_process_queue_extra",
            accepted=False,
        )
    materialized = materialize_scheduler_mapping(extra)
    if type(materialized) is dict:
        return ProcessQueueExtraDecision(extra=materialized, reason="process_queue_extra_materialized", accepted=True)
    return ProcessQueueExtraDecision(
        extra={"extra_unavailable_reason": "non_materializable_process_queue_extra"},
        reason="non_materializable_process_queue_extra",
        accepted=False,
    )


def _process_queue_extra(extra: Mapping[str, object] | None) -> dict[str, object]:
    return _process_queue_extra_decision(extra).extra


def process_queue_record_suppressed(
    where: str,
    exc: BaseException,
    *,
    extra: Mapping[str, object] | None = None,
    fatal: bool = False,
) -> bool:
    """Record process-queue telemetry without caller-owned hooks."""
    stage = _process_queue_token(where)
    recorded = False
    try:
        payload: dict[str, object] = {
            "process_queue_stage": stage,
            "fatal": fatal is True,
        }
        payload.update(_process_queue_extra(extra))
        _runtime_record_suppressed_failure(stage, exc, domain="scheduler", context=payload, fatal=fatal is True)
        recorded = True
    except (RuntimeError, OSError, TypeError, ValueError, KeyError) as telemetry_exc:
        logging.warning(
            "process queue telemetry failure at %s: %s",
            stage,
            scheduler_error_detail(telemetry_exc),
        )
        recorded = False
    return recorded


def record_scheduler_suppressed(
    where: str,
    exc: BaseException,
    *,
    extra: Mapping[str, object] | None = None,
    fatal: bool = False,
) -> bool:
    """Public process-queue telemetry entry used by scheduler submodules."""
    return process_queue_record_suppressed(where, exc, extra=extra, fatal=fatal)


def process_queue_log_error(message: object) -> bool:
    """Best-effort process-queue error logging owned by telemetry."""
    safe_message, safe_message_reason = no_hook_text(message, unsupported_reason="process_queue_message_rejected")
    if safe_message_reason != "" or not safe_message:
        safe_message = "process_queue_message_unavailable"
    logged = False
    try:
        _process_queue_core_log_error(safe_message)
        logged = True
    except (OSError, RuntimeError, TypeError, ValueError) as exc:
        process_queue_record_suppressed(
            "process_queue_log_error_failed",
            exc,
            extra={"message": safe_message[:240]},
        )
        logging.error("%s", safe_message)
        logged = False
    return logged


def processqueue_default_failure_info(stage: object, exc: object=None, **extra: object) -> object:
    payload = {
        "stage": _process_queue_token(stage, default_value="process_queue_failure"),
        "time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    if exc is not None:
        payload.update({"exception_type": no_hook_type_name(exc), "error": scheduler_error_detail(exc)})
    payload.update(_process_queue_extra(extra))
    return payload
