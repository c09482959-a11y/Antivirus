"""Running timeout budget value coercion and evidence helpers."""
from __future__ import annotations

from typing import Callable, Mapping

from Virus_Scan.contracts.no_hook_materialization import no_hook_type_name
from Virus_Scan.scheduler.internal.immutable_output_support import unsupported_scheduler_value_evidence
from Virus_Scan.scheduler.timeout.inmemory_timeout_evidence import record_timeout_recovery_failure
from Virus_Scan.scheduler.timeout.inmemory_timeout_numeric_policy import safe_timeout_policy_number
from Virus_Scan.scheduler.timeout.inmemory_timeout_policy_callbacks import safe_timeout_budget_number
from Virus_Scan.scheduler.timeout.inmemory_timeout_record_value_decisions import timeout_record_value_decision


def _timeout_budget_unavailable(reason: str, raw_value: object | None = None) -> Mapping[str, object]:
    evidence: dict[str, object] = {
        "timeout_budget_unavailable": True,
        "timeout_budget_unavailable_reason": reason,
        "final_json_must_record": True,
        "checkpoint_must_record": True,
        "replay_must_record": True,
    }
    if raw_value is not None:
        evidence["timeout_budget_failure"] = unsupported_scheduler_value_evidence(
            raw_value,
            field_name="timeout_budget",
        )
    return evidence


def timeout_budget_mapping_for_record(
    *,
    jid: object,
    rec: Mapping[str, object],
    pid: object,
    timeout_retry_evidence: list[Mapping[str, object]],
    record_scheduler_suppressed: Callable[[str, BaseException], object],
    recoverable_exceptions: tuple[type[BaseException], ...],
) -> Mapping[str, object]:
    """Return a scheduler-owned timeout budget mapping or explicit unavailable evidence."""

    raw_budget_info = timeout_record_value_decision(rec, "timeout_budget").as_value()
    if type(raw_budget_info) is dict:
        return raw_budget_info
    if raw_budget_info is None or (type(raw_budget_info) is str and raw_budget_info == ""):
        return _timeout_budget_unavailable("missing_timeout_budget")
    timeout_budget_evidence = _timeout_budget_unavailable(
        "timeout_budget_container_malformed",
        raw_budget_info,
    )
    record_timeout_recovery_failure(
        failures=timeout_retry_evidence,
        job_id=jid,
        reason="timeout_budget_container_malformed",
        pid=pid,
        action="timeout_budget_container_malformed",
        attempt=timeout_record_value_decision(rec, "attempt").as_value(),
        timeout_budget=timeout_budget_evidence,
        error=TypeError("timeout_budget must be an exact dict, got " + no_hook_type_name(raw_budget_info)),
        source="inmemory_timeout_sweep.timeout_budget",
        record_scheduler_suppressed=record_scheduler_suppressed,
        recoverable_exceptions=recoverable_exceptions,
    )
    return timeout_budget_evidence


def combined_running_timeout_budget(
    *,
    policy_value: float,
    policy_field: str,
    budget_field: str,
    jid: object,
    rec: Mapping[str, object],
    pid: object,
    budget_info: Mapping[str, object],
    timeout_retry_evidence: list[Mapping[str, object]],
    record_scheduler_suppressed: Callable[[str, BaseException], object],
    recoverable_exceptions: tuple[type[BaseException], ...],
) -> float:
    """Return the effective timeout budget from policy and per-job budget data."""

    policy_budget = safe_timeout_policy_number(
        value=policy_value,
        default=0.0,
        field=policy_field,
        job_id=jid,
        record=rec,
        pid=pid,
        failures=timeout_retry_evidence,
        record_scheduler_suppressed=record_scheduler_suppressed,
        recoverable_exceptions=recoverable_exceptions,
    )
    record_budget = safe_timeout_budget_number(
        record=rec,
        budget=budget_info,
        field=budget_field,
        default=0.0,
        job_id=jid,
        pid=pid,
        failures=timeout_retry_evidence,
        record_scheduler_suppressed=record_scheduler_suppressed,
        recoverable_exceptions=recoverable_exceptions,
    )
    return max(policy_budget, record_budget)


__all__ = ("combined_running_timeout_budget", "timeout_budget_mapping_for_record")
