"""Runtime debt and fairness accounting for event/replay/governance pressure."""
from __future__ import annotations

from Virus_Scan.contracts.no_hook_materialization import no_hook_exact_owner_field
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Mapping
import time

from Virus_Scan.runtime.governance_inputs import (
    runtime_float,
    runtime_int,
    runtime_text,
)
from Virus_Scan.runtime.immutable_core import freeze_runtime_value


def _runtime_debt_field(prefix: str, field_name: object) -> str:
    if type(field_name) is str:
        return str.__str__(prefix) + "_" + str.__str__(field_name)
    return str.__str__(prefix) + "_field_rejected"


def _runtime_debt_sorted_items(items: dict[str, "WorkloadDebt"]) -> tuple[tuple[str, "WorkloadDebt"], ...]:
    return tuple(sorted(dict.items(items), key=lambda item: item[0]))


def _runtime_debt_oldest_keys(items: dict[str, "WorkloadDebt"], remove_count: int) -> tuple[str, ...]:
    oldest = sorted(dict.items(items), key=lambda item: (item[1].last_seen, item[0]))
    return tuple(item[0] for item in oldest[:remove_count])


@dataclass
class WorkloadDebt:
    workload_id: str
    event_cost: float = 0.0
    replay_cost: float = 0.0
    telemetry_cost: float = 0.0
    extraction_cost: float = 0.0
    stabilization_cost: float = 0.0
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    input_evidence: tuple[Mapping[str, object], ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        if type(self) is not WorkloadDebt:
            exception_message = "workload debt owner rejected"
            raise TypeError(exception_message)
        self.workload_id, issues = runtime_text(
            self.workload_id,
            field_name="runtime_debt_workload_id",
            default="input_rejected",
        )
        evidence = issues
        for field_name in (
            "event_cost",
            "replay_cost",
            "telemetry_cost",
            "extraction_cost",
            "stabilization_cost",
            "first_seen",
            "last_seen",
        ):
            value, issues = runtime_float(
                no_hook_exact_owner_field(self, WorkloadDebt, field_name),
                field_name=_runtime_debt_field("runtime_debt", field_name),
                default=0.0,
                minimum=0.0,
            )
            evidence += issues
            object.__setattr__(self, field_name, value)
        self.input_evidence = evidence

    def total(self) -> float:
        return float(self.event_cost + self.replay_cost + self.telemetry_cost + self.extraction_cost + self.stabilization_cost)

    def aging_boost(self, now: float | None = None) -> float:
        now_value, issues = runtime_float(
            time.time() if now is None else now,
            field_name="runtime_debt_now",
            default=self.last_seen,
            minimum=0.0,
        )
        if issues:
            self.input_evidence += issues
        now = now_value
        wait = max(0.0, now - self.first_seen)
        return min(100.0, wait / 10.0)

    def priority_penalty(self) -> float:
        return max(0.0, self.total() - self.aging_boost())

    def as_dict(self) -> dict[str, object]:
        return {"workload_id": self.workload_id, "total": round(self.total(), 4), "event_cost": round(self.event_cost, 4), "replay_cost": round(self.replay_cost, 4), "telemetry_cost": round(self.telemetry_cost, 4), "extraction_cost": round(self.extraction_cost, 4), "stabilization_cost": round(self.stabilization_cost, 4), "aging_boost": round(self.aging_boost(), 4), "priority_penalty": round(self.priority_penalty(), 4), "input_evidence": list(self.input_evidence)}


class RuntimeDebtLedger:
    def __init__(self, max_records: int = 8192) -> None:
        self.max_records, issues = runtime_int(
            max_records, field_name="runtime_debt_max_records", default=8192
        )
        self.max_records = max(1, self.max_records)
        self._items: dict[str, WorkloadDebt] = {}
        self._input_evidence = issues

    def record(self, workload_id: str, *, event: float = 0.0, replay: float = 0.0, telemetry: float = 0.0, extraction: float = 0.0, stabilization: float = 0.0) -> WorkloadDebt:
        wid, issues = runtime_text(
            workload_id,
            field_name="runtime_debt_record_workload_id",
            default="input_rejected",
        )
        evidence = issues
        costs: dict[str, float] = {}
        for field_name, raw in (
            ("event", event),
            ("replay", replay),
            ("telemetry", telemetry),
            ("extraction", extraction),
            ("stabilization", stabilization),
        ):
            costs[field_name], issues = runtime_float(
                raw,
                field_name=_runtime_debt_field("runtime_debt_record", field_name),
                default=0.0,
                minimum=0.0,
            )
            evidence += issues
        if evidence:
            self._input_evidence += evidence
            return WorkloadDebt(
                wid[:256],
                input_evidence=tuple(freeze_runtime_value(evidence)),
            )
        wid = wid[:256]
        rec = self._items.get(wid)
        if rec is None:
            rec = self._items[wid] = WorkloadDebt(wid)
        rec.event_cost += costs["event"]
        rec.replay_cost += costs["replay"]
        rec.telemetry_cost += costs["telemetry"]
        rec.extraction_cost += costs["extraction"]
        rec.stabilization_cost += costs["stabilization"]
        rec.last_seen = time.time()
        if len(self._items) > self.max_records:
            for k in _runtime_debt_oldest_keys(self._items, len(self._items) - self.max_records):
                self._items.pop(k, None)
        return rec

    def snapshot(self) -> Mapping[str, object]:
        out: dict[str, object] = {k: v.as_dict() for k, v in _runtime_debt_sorted_items(self._items)}
        if self._input_evidence:
            out["__input_evidence__"] = list(self._input_evidence)
        return MappingProxyType(out)

    def hot_workloads(self, threshold: float = 4096.0) -> tuple[str, ...]:
        threshold_value, issues = runtime_float(
            threshold,
            field_name="runtime_debt_hot_threshold",
            default=0.0,
            minimum=0.0,
        )
        if issues:
            self._input_evidence += issues
            return tuple(sorted(self._items))
        return tuple(k for k, v in _runtime_debt_sorted_items(self._items) if v.total() >= threshold_value)


_GLOBAL_DEBT_LEDGER = RuntimeDebtLedger()

def get_runtime_debt_ledger() -> RuntimeDebtLedger:
    return _GLOBAL_DEBT_LEDGER

__all__ = ("RuntimeDebtLedger", "WorkloadDebt", "get_runtime_debt_ledger")
