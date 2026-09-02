"""Scheduler runtime weighted stage-budget and progress ownership."""
from __future__ import annotations

from Virus_Scan.contracts.no_hook_materialization import no_hook_mapping_items
from Virus_Scan.exception_contracts import RECOVERABLE_RUNTIME_ERRORS
from Virus_Scan.runtime.api import record_suppressed_failure, report_progress
from Virus_Scan.scheduler.internal.no_hook_diagnostics import scheduler_float, scheduler_int, scheduler_text
from Virus_Scan.scheduler.internal.mapping_item_lookup import scheduler_mapping_value
from Virus_Scan.scheduler.runtime.stage_cost import estimate_stage_file_cost, record_stage_cost_observation
from Virus_Scan.scheduler.runtime.stage_budget_tables import record_stage_budget_failure, stage_budget_failure_evidence, stage_class_for_task, stage_table

class SchedulerStageBudgetCancelled(Exception):
    """Raised when cooperative cancellation interrupts stage-budget acquisition."""

from Virus_Scan.scheduler.runtime.stage_budget_lease import (
    SchedulerStageBudgetLease,
    inherit_stage_budget_lease,
    own_stage_budget_lease,
    reset_stage_budget_lease_context,
)

def _record_stage_budget_rejection(stage_name: object, category: object, message: object, *, exception_type: object="") -> object:
    evidence = stage_budget_failure_evidence(stage_name, category, message, exception_type=exception_type)
    record_stage_budget_failure(evidence)
    return evidence

def stage_semaphore_for_name(name: object) -> object:
    sem = None
    try:
        sems = stage_table("stage_semaphores", name)
        if sems is not None:
            cls = stage_class_for_task(name)
            sem = scheduler_mapping_value(sems, cls, default=scheduler_mapping_value(sems, "generic"))
            if sem is None:
                _record_stage_budget_rejection(name, "stage_budget_unavailable", "configured stage semaphore is unavailable")
    except RECOVERABLE_RUNTIME_ERRORS as exc:
        _record_stage_budget_rejection(name, "stage_budget_corrupt", "configured stage semaphore lookup failed", exception_type=type(exc).__name__)
    return sem

def stage_limit_for_name(name: object) -> object:
    limit = 1
    try:
        limits = stage_table("stage_limits", name)
        if limits is not None:
            cls = stage_class_for_task(name)
            configured = scheduler_mapping_value(limits, cls, default=scheduler_mapping_value(limits, "generic"))
            if configured is None:
                _record_stage_budget_rejection(name, "stage_budget_unavailable", "configured stage limit is unavailable")
            else:
                parsed, reason = scheduler_int(configured, default=1, minimum=1, reason="stage_budget_limit_rejected")
                if reason:
                    _record_stage_budget_rejection(name, "stage_budget_corrupt", "configured stage limit is invalid", exception_type=reason)
                limit = parsed
    except RECOVERABLE_RUNTIME_ERRORS as exc:
        evidence = stage_budget_failure_evidence(name, "stage_budget_corrupt", "configured stage limit lookup failed", exception_type=type(exc).__name__)
        record_stage_budget_failure(evidence, exc)
    return limit

def weighted_stage_tokens(path: object=None, stage_name: object=None, cost: object=None) -> object:
    """Return weighted semaphore tokens for toxic stages without changing detection."""
    result = (1, "generic")
    try:
        c = cost if no_hook_mapping_items(cost) is not None else (estimate_stage_file_cost(path) if path is not None else {})
        weight, weight_reason = scheduler_int(scheduler_mapping_value(c, "weight", default=1), default=1, minimum=1, reason="stage_budget_weight_rejected")
        stage_source = stage_name if stage_name is not None else scheduler_mapping_value(c, "stage", default="generic")
        stage_text, stage_text_reason = scheduler_text(
            stage_source,
            replacement_text="generic",
            unsupported_reason="stage_budget_stage_name_rejected",
        )
        stage, stage_reason = ("generic", stage_text_reason) if stage_text_reason or stage_text == "" else (stage_text, "")
        if weight_reason:
            _record_stage_budget_rejection(stage, "stage_budget_corrupt", "configured stage weight is invalid", exception_type=weight_reason)
        if stage_reason:
            _record_stage_budget_rejection("generic", "stage_budget_corrupt", "configured stage name is invalid", exception_type=stage_reason)
        cls = stage_class_for_task(stage.lower())
        tokens = min(weight, stage_limit_for_name(cls)) if cls in {"image", "archive", "dotnet", "raw", "yara"} else 1
        result = (max(1, tokens), cls)
    except RECOVERABLE_RUNTIME_ERRORS as exc:
        _record_stage_budget_rejection(stage_name, "stage_budget_corrupt", "weighted stage token calculation failed", exception_type=type(exc).__name__)
    return result

def _release_partial_budget(acquired: object) -> object:
    for sem in reversed(acquired):
        try:
            sem.release()
        except RECOVERABLE_RUNTIME_ERRORS as exc:
            try:
                record_suppressed_failure("suppressed_exception", exc, domain="runtime")
            except RECOVERABLE_RUNTIME_ERRORS as report_exc:
                _ = report_exc

def acquire_weighted_stage_budget(path: object=None, stage_name: object=None, cost: object=None, cancel_check: object=None, timeout_slice: object=0.25) -> object:
    """Acquire N shared stage tokens with cooperative cancellation."""
    sem_stage = stage_name if stage_name is not None else (scheduler_mapping_value(cost, "stage") if no_hook_mapping_items(cost) is not None else None)
    sem = stage_semaphore_for_name(sem_stage)
    if sem is None:
        evidence = stage_budget_failure_evidence(sem_stage, "stage_budget_unavailable", "weighted stage budget semaphore unavailable")
        record_stage_budget_failure(evidence)
        return SchedulerStageBudgetLease(evidence=(evidence,))
    tokens, cls = weighted_stage_tokens(path=path, stage_name=stage_name, cost=cost)
    inherited_lease = inherit_stage_budget_lease(sem)
    if inherited_lease is not None:
        return inherited_lease
    acquired = SchedulerStageBudgetLease()
    try:
        timeout_value, timeout_reason = scheduler_float(
            timeout_slice,
            default=0.25,
            minimum=0.0,
            reason="stage_budget_timeout_slice_rejected",
        )
        if timeout_reason:
            _record_stage_budget_rejection(
                cls,
                "stage_budget_corrupt",
                "weighted stage budget timeout slice is invalid",
                exception_type=timeout_reason,
            )
        for _ in range(tokens):
            while True:
                if callable(cancel_check) and cancel_check():
                    evidence = stage_budget_failure_evidence(cls, "stage_budget_cancelled", "cancelled while waiting for weighted stage budget")
                    record_stage_budget_failure(evidence)
                    raise SchedulerStageBudgetCancelled("cancelled_while_waiting_for_stage_budget")
                try:
                    ok = sem.acquire(timeout=timeout_value)
                except TypeError:
                    ok = sem.acquire(True, timeout_value)
                if ok:
                    acquired.append(sem)
                    break
        return own_stage_budget_lease(sem, acquired)
    except RECOVERABLE_RUNTIME_ERRORS as exc:
        evidence = stage_budget_failure_evidence(cls, "stage_budget_acquire_failed", "weighted stage budget acquisition failed after partial acquisition", exception_type=type(exc).__name__)
        record_stage_budget_failure(evidence, exc)
        _release_partial_budget(acquired)
        raise

def release_weighted_stage_budget(tokens: object) -> object:
    lease = tokens if type(tokens) is SchedulerStageBudgetLease else None
    _release_partial_budget(list(tokens or []))
    if lease is None or lease.context_token is None:
        return None
    try:
        reset_stage_budget_lease_context(lease)
    except RECOVERABLE_RUNTIME_ERRORS as exc:
        try:
            record_suppressed_failure(
                "scheduler_stage_budget_context_reset_failed",
                exc,
                domain="runtime",
            )
        except RECOVERABLE_RUNTIME_ERRORS as report_exc:
            _ = report_exc
    return None

def stage_progress(stage: object="scan", inc: object=1, bytes_delta: object=0) -> object:
    """Report nested scheduler/scanner progress through the runtime owner."""
    stage_text, stage_reason = scheduler_text(stage, replacement_text="scan", unsupported_reason="stage_progress_stage_rejected")
    increment, increment_reason = scheduler_int(inc, default=1, minimum=1, reason="stage_progress_increment_rejected")
    byte_count, byte_reason = scheduler_int(bytes_delta, default=0, minimum=0, reason="stage_progress_bytes_rejected")
    for category, reason in (("stage_progress_stage_rejected", stage_reason), ("stage_progress_increment_rejected", increment_reason), ("stage_progress_bytes_rejected", byte_reason)):
        if reason:
            try:
                record_suppressed_failure(category, ValueError(reason), domain="runtime")
            except RECOVERABLE_RUNTIME_ERRORS as report_exc:
                _ = report_exc
    try:
        return report_progress(stage_text, increment, byte_count)
    except RECOVERABLE_RUNTIME_ERRORS as exc:
        try:
            record_suppressed_failure("suppressed_exception", exc, domain="runtime")
        except RECOVERABLE_RUNTIME_ERRORS as report_exc:
            _ = report_exc
    return True

__all__ = (
    "SchedulerStageBudgetCancelled",
    "SchedulerStageBudgetLease",
    "acquire_weighted_stage_budget",
    "record_stage_cost_observation",
    "release_weighted_stage_budget",
    "stage_limit_for_name",
    "stage_progress",
    "stage_semaphore_for_name",
    "weighted_stage_tokens",
)
