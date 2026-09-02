"""Queue admission fairness and interleaving policies."""
from __future__ import annotations

from typing import Iterable

from Virus_Scan.exception_contracts import RECOVERABLE_RUNTIME_ERRORS
from Virus_Scan.runtime.api import record_suppressed_failure
from Virus_Scan.runtime.api import adaptive_reprice_cost, apply_repricing_inertia
from Virus_Scan.runtime.api import get_runtime_economics_ledger
from Virus_Scan.scheduler.queue.admission import (
    WorkloadClassificationPlan,
    WorkloadClassifiedTarget,
)
from Virus_Scan.scheduler.internal.no_hook_diagnostics import scheduler_float, scheduler_text


def _buckets_have_items(buckets: dict[str, list[object]], order: tuple[str, ...]) -> bool:
    if not order:
        return False
    return any(buckets[cls] for cls in order)


def _workload_key(value: object) -> str:
    result = "generic"
    if type(value) is str:
        result = str.__str__(value) or result
    elif type(value) is bool:
        result = "True" if value else result
    elif type(value) is int:
        result = int.__str__(value) if value != 0 else result
    elif type(value) is float:
        result = float.__str__(value) if value != 0.0 else result
    elif value is not None:
        text, reason = scheduler_text(value, unsupported_reason="scheduler_workload_key_rejected")
        if reason == "" and text:
            result = text
        else:
            record_suppressed_failure("scheduler_workload_key_rejected", ValueError(reason or "blank_scheduler_workload_key"), domain="scheduler")
    return result


def _nonnegative_float(value: object, *, default: float, reason: str, zero_uses_default: bool = False) -> float:
    if value is None:
        return default
    if type(value) is bool:
        return 1.0 if value else default
    if zero_uses_default and ((type(value) is int and value == 0) or (type(value) is float and value == 0.0)):
        return default
    parsed, parse_reason = scheduler_float(value, default=default, reason=reason)
    if parse_reason:
        record_suppressed_failure(reason, ValueError(parse_reason), domain="scheduler")
        return default
    return max(0.0, parsed)

def interleave_workloads(
    plan: WorkloadClassificationPlan,
    limits: dict[str, int] | None = None,
) -> list[WorkloadClassifiedTarget]:
    """Interleave one already-classified target generation by workload lane."""
    del limits
    if type(plan) is not WorkloadClassificationPlan:
        raise TypeError("workload_classification_plan_required")
    buckets: dict[str, list[WorkloadClassifiedTarget]] = {
        "archive": [], "dotnet": [], "raw": [], "yara": [],
        "image": [], "script": [], "generic": [],
    }
    for target in plan.targets:
        buckets[target.workload].append(target)
    for workload in tuple(buckets):
        priced: list[tuple[float, str, int, WorkloadClassifiedTarget]] = []
        last_cost = None
        for index, target in enumerate(buckets[workload]):
            proposed = adaptive_reprice_cost(target.path)
            smoothed = apply_repricing_inertia(last_cost, proposed)
            last_cost = smoothed
            priced.append((smoothed, target.filesystem_path, index, target))
        priced.sort(key=lambda row: (row[0], row[1], row[2]))
        buckets[workload] = [row[3] for row in priced]
    order = ("image", "generic", "raw", "yara", "script", "dotnet", "archive")
    out: list[WorkloadClassifiedTarget] = []
    while _buckets_have_items(buckets, order):
        progressed = False
        for workload in order:
            if buckets[workload]:
                out.append(buckets[workload].pop(0))
                progressed = True
        if not progressed:
            break
    return out

class QueueDebtLedger:
    """Tracks runtime debt without retaining mutable dictionary state."""
    __slots__ = ("_debt_items", "_wait_items")

    def __init__(self) -> None:
        self._debt_items: tuple[tuple[str, float], ...] = ()
        self._wait_items: tuple[tuple[str, int], ...] = ()

    @staticmethod
    def _read(items: tuple[tuple[str, object], ...], key: str, default: object) -> object:
        for item_key, value in items:
            if item_key == key:
                return value
        return default

    @staticmethod
    def _write(items: tuple[tuple[str, object], ...], key: str, value: object) -> tuple[tuple[str, object], ...]:
        replaced = False
        updated = []
        for item_key, item_value in items:
            if item_key == key:
                updated.append((item_key, value))
                replaced = True
            else:
                updated.append((item_key, item_value))
        if not replaced:
            updated.append((key, value))
        return tuple(updated)

    def charge(self, workload: str, amount: float) -> None:
        key = _workload_key(workload)
        current = _nonnegative_float(self._read(self._debt_items, key, 0.0), default=0.0, reason="scheduler_debt_current_rejected")
        self._debt_items = self._write(self._debt_items, key, current + _nonnegative_float(amount, default=0.0, reason="scheduler_debt_amount_rejected"))

    def age(self, workload: str) -> None:
        key = _workload_key(workload)
        current = int(self._read(self._wait_items, key, 0))
        self._wait_items = self._write(self._wait_items, key, current + 1)

    def priority(self, workload: str, base_cost: float = 1.0) -> float:
        key = _workload_key(workload)
        debt = _nonnegative_float(self._read(self._debt_items, key, 0.0), default=0.0, reason="scheduler_debt_value_rejected")
        aging_credit = min(0.75, int(self._read(self._wait_items, key, 0)) * 0.03)
        base_metric = _nonnegative_float(base_cost, default=1.0, reason="scheduler_priority_base_cost_rejected", zero_uses_default=True)
        return max(0.01, base_metric + debt * 0.10 - aging_credit)


def weighted_fair_interleave(
    targets: Iterable[WorkloadClassifiedTarget],
    *,
    ledger: QueueDebtLedger | None = None,
) -> list[WorkloadClassifiedTarget]:
    """Apply deterministic weighted fairness without reclassifying targets."""
    ledger = ledger or QueueDebtLedger()
    buckets: dict[str, list[tuple[float, str, int, WorkloadClassifiedTarget]]] = {
        "image": [], "generic": [], "raw": [], "yara": [],
        "script": [], "dotnet": [], "archive": [],
    }
    for index, target in enumerate(targets or ()):
        if type(target) is not WorkloadClassifiedTarget:
            raise TypeError("workload_classified_target_required")
        workload = target.workload
        cost = apply_repricing_inertia(None, adaptive_reprice_cost(target.path))
        try:
            get_runtime_economics_ledger().observe("admission_cost", cost)
        except RECOVERABLE_RUNTIME_ERRORS as exc:
            record_suppressed_failure("workload_admission_cost_observe_failed", exc, domain="scheduler")
        buckets[workload].append(
            (ledger.priority(workload, cost), target.filesystem_path, index, target)
        )
    for workload in tuple(buckets):
        buckets[workload].sort(key=lambda row: (row[0], row[1], row[2]))
    out: list[WorkloadClassifiedTarget] = []
    lanes = ("image", "generic", "raw", "yara", "script", "dotnet", "archive")
    while _buckets_have_items(buckets, lanes):
        best = None
        for lane_index, workload in enumerate(lanes):
            if not buckets[workload]:
                continue
            score, filesystem_path, original_index, target = buckets[workload][0]
            candidate = (
                score, lane_index, filesystem_path, original_index, workload, target,
            )
            if best is None or candidate[:4] < best[:4]:
                best = candidate
        if best is None:
            break
        _, _, _, _, workload, target = best
        buckets[workload].pop(0)
        out.append(target)
        admission_cost = max(0.1, adaptive_reprice_cost(target.path) * 0.05)
        ledger.charge(workload, admission_cost)
        try:
            get_runtime_economics_ledger().observe("admission_cost", admission_cost)
        except RECOVERABLE_RUNTIME_ERRORS as exc:
            record_suppressed_failure("workload_admission_cost_observe_failed", exc, domain="scheduler")
        for other in lanes:
            if other != workload and buckets[other]:
                ledger.age(other)
    return out

__all__ = ("QueueDebtLedger", "interleave_workloads", "weighted_fair_interleave")
