"""Timeout-owned scalar coercion boundaries for in-memory timeout sweeps.

This module keeps base timeout policy values and returned sweep counters from
aborting the scheduler when malformed runtime state reaches timeout ownership.
Malformed values are represented as immutable timeout evidence instead of hidden
clean success values.
"""
from __future__ import annotations

from typing import Mapping

from Virus_Scan.contracts.no_hook_materialization import no_hook_exact_nonnegative_int
from Virus_Scan.scheduler.internal.no_hook_diagnostics import scheduler_float
from Virus_Scan.scheduler.timeout.inmemory_timeout_evidence import timeout_reporting_failure
from Virus_Scan.scheduler.timeout.inmemory_timeout_policy_callbacks import record_timeout_policy_failure
from Virus_Scan.scheduler.timeout.inmemory_timeout_policy_text import timeout_policy_field_text



def safe_timeout_policy_number(
    *,
    value: object,
    default: float,
    field: str,
    job_id: object,
    record: Mapping[str, object],
    pid: object,
    failures: list[Mapping[str, object]],
    record_scheduler_suppressed: object,
    recoverable_exceptions: tuple[type[BaseException], ...],
) -> float:
    """Coerce a base timeout policy value and emit evidence on malformed state."""
    field_text = timeout_policy_field_text(field)
    default_number, default_reason = scheduler_float(
        default,
        default=0.0,
        reason=field_text + "_default_malformed",
        non_finite_reason=field_text + "_malformed",
    )
    number, reason = scheduler_float(
        value,
        default=default_number,
        reason=field_text + "_malformed",
        non_finite_reason=field_text + "_malformed",
    )
    rejection = reason or default_reason
    if rejection:
        record_timeout_policy_failure(
            failures=failures,
            job_id=job_id,
            record=record,
            reason=rejection,
            action="timeout_policy_value_malformed",
            error=ValueError(rejection),
            source="inmemory_timeout_sweep." + field_text,
            pid=pid,
            record_scheduler_suppressed=record_scheduler_suppressed,
            recoverable_exceptions=recoverable_exceptions,
        )
        return default_number
    return number


def safe_timeout_result_count(
    *,
    value: object,
    field: str,
    reporting_failures: list[Mapping[str, object]],
) -> int:
    """Coerce timeout-sweep result counters without aborting result creation."""
    field_text = timeout_policy_field_text(field)
    count, reason = no_hook_exact_nonnegative_int(
        value,
        default=0,
        reason=field_text + "_malformed",
        non_finite_reason=field_text + "_non_finite",
    )
    if reason:
        reporting_failures.append(
            timeout_reporting_failure(
                job_id="shared_heartbeat",
                reason=reason,
                error=ValueError(reason),
            )
        )
    return count


__all__ = ("safe_timeout_policy_number", "safe_timeout_result_count")
