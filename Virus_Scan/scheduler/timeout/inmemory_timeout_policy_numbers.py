"""Numeric timeout policy field readers owned by timeout policy."""
from __future__ import annotations

from typing import Callable, Mapping

from Virus_Scan.scheduler.internal.immutable_output_support import unsupported_scheduler_value_evidence
from Virus_Scan.scheduler.internal.no_hook_diagnostics import scheduler_float
from Virus_Scan.scheduler.timeout.inmemory_timeout_evidence import record_timeout_recovery_failure
from Virus_Scan.scheduler.timeout.inmemory_timeout_record_value_decisions import timeout_record_value_decision
from Virus_Scan.scheduler.timeout.inmemory_timeout_policy_text import timeout_policy_field_text, timeout_policy_reason



def _coerce_scheduler_float(value: object, *, field: str) -> float:
    number, reason = scheduler_float(
        value,
        default=0.0,
        reason=timeout_policy_reason(field, "unsafe_numeric_rejected"),
        non_finite_reason=timeout_policy_reason(field, "non_finite"),
    )
    if reason:
        raise ValueError(reason)
    return number


def safe_record_float(
    *,
    record: Mapping[str, object],
    field: str,
    default: float,
    job_id: object,
    pid: object = None,
    failures: list[Mapping[str, object]],
    record_scheduler_suppressed: Callable[[str, BaseException], object],
    recoverable_exceptions: tuple[type[BaseException], ...],
) -> float:
    """Read a timestamp/age field without letting malformed scheduler state abort timeout ownership."""
    field_text = timeout_policy_field_text(field)
    default_number, _default_reason = scheduler_float(
        default,
        default=0.0,
        reason=field_text + "_default_malformed",
        non_finite_reason=field_text + "_default_malformed",
    )
    raw = timeout_record_value_decision(record, field_text).as_value()
    if raw is None or (type(raw) is str and raw == ""):
        return default_number
    try:
        return _coerce_scheduler_float(raw, field=field_text)
    except (TypeError, ValueError, OverflowError) as value_exc:
        record_timeout_policy_failure(
            failures=failures,
            job_id=job_id,
            record=record,
            reason=field_text + "_malformed",
            action="timeout_record_field_malformed",
            error=value_exc,
            source="inmemory_timeout_sweep." + field_text,
            pid=pid,
            record_scheduler_suppressed=record_scheduler_suppressed,
            recoverable_exceptions=recoverable_exceptions,
        )
        return default_number


def safe_timeout_budget_number(
    *,
    record: Mapping[str, object],
    budget: Mapping[str, object],
    field: str,
    default: float,
    job_id: object,
    pid: object = None,
    failures: list[Mapping[str, object]],
    record_scheduler_suppressed: Callable[[str, BaseException], object],
    recoverable_exceptions: tuple[type[BaseException], ...],
) -> float:
    """Read timeout-budget numeric fields and emit evidence for malformed values."""
    field_text = timeout_policy_field_text(field)
    default_number, _default_reason = scheduler_float(
        default,
        default=0.0,
        reason="timeout_budget_" + field_text + "_default_malformed",
        non_finite_reason="timeout_budget_" + field_text + "_default_malformed",
    )
    raw = timeout_record_value_decision(budget, field_text).as_value()
    if raw is None or (type(raw) is str and raw == ""):
        return default_number
    try:
        return _coerce_scheduler_float(raw, field=field_text)
    except (TypeError, ValueError, OverflowError) as value_exc:
        record_timeout_policy_failure(
            failures=failures,
            job_id=job_id,
            record=record,
            reason="timeout_budget_" + field_text + "_malformed",
            action="timeout_budget_field_malformed",
            error=value_exc,
            source="inmemory_timeout_sweep.timeout_budget." + field_text,
            pid=pid,
            record_scheduler_suppressed=record_scheduler_suppressed,
            recoverable_exceptions=recoverable_exceptions,
        )
        return default_number


def timeout_budget_for_record(record: Mapping[str, object]) -> Mapping[str, object]:
    """Return immutable-compatible timeout budget evidence from a job record."""
    raw_budget = timeout_record_value_decision(record, "timeout_budget").as_value()
    if type(raw_budget) is dict:
        return raw_budget
    if raw_budget is None or (type(raw_budget) is str and raw_budget == ""):
        return {
            "timeout_budget_unavailable": True,
            "timeout_budget_unavailable_reason": "missing_timeout_budget",
            "final_json_must_record": True,
            "checkpoint_must_record": True,
            "replay_must_record": True,
        }
    return {
        "timeout_budget_unavailable": True,
        "timeout_budget_unavailable_reason": "timeout_budget_container_malformed",
        "timeout_budget_failure": unsupported_scheduler_value_evidence(raw_budget, field_name="timeout_budget"),
        "final_json_must_record": True,
        "checkpoint_must_record": True,
        "replay_must_record": True,
    }


def record_timeout_policy_failure(
    *,
    failures: list[Mapping[str, object]],
    job_id: object,
    record: Mapping[str, object],
    reason: str,
    action: str,
    error: BaseException,
    source: str,
    pid: object = None,
    record_scheduler_suppressed: Callable[[str, BaseException], object],
    recoverable_exceptions: tuple[type[BaseException], ...],
) -> None:
    """Record a timeout-policy callback failure as retry/checkpoint/replay evidence."""
    record_timeout_recovery_failure(
        failures=failures,
        job_id=job_id,
        reason=reason,
        pid=pid,
        action=action,
        attempt=timeout_record_value_decision(record, "attempt").as_value(),
        timeout_budget=timeout_budget_for_record(record),
        error=error,
        source=source,
        record_scheduler_suppressed=record_scheduler_suppressed,
        recoverable_exceptions=recoverable_exceptions,
    )


__all__ = (
    "record_timeout_policy_failure",
    "safe_record_float",
    "safe_timeout_budget_number",
    "timeout_budget_for_record",
)
