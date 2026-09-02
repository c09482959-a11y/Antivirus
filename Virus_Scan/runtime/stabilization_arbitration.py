"""Hierarchical stabilization arbitration for governed runtime domains."""
from __future__ import annotations

from Virus_Scan.contracts.no_hook_materialization import no_hook_exact_owner_field
from dataclasses import dataclass, field
from typing import Mapping

from Virus_Scan.runtime.governance_inputs import (
    runtime_bool,
    runtime_float,
    runtime_mapping,
    runtime_sequence,
    runtime_text,
)
from Virus_Scan.runtime.immutable_core import freeze_runtime_value, materialize_runtime_value

from .stability_policy import StabilizationDecision, decide_stabilization
from .topology_stabilization import analyze_topology_pressure
from .runtime_debt import get_runtime_debt_ledger


PLR2004N0_25 = 0.25
PLR2004N0_5 = 0.5


def _runtime_indexed_name(prefix: str, index: int, suffix: str = "") -> str:
    if type(index) is int and type(index) is not bool:
        index_text = int.__str__(index)
    else:
        index_text = "index"
    return prefix + "_" + index_text + suffix


@dataclass(frozen=True)
class ArbitrationResult:
    action: str
    reason: str
    delegated_domains: tuple[str, ...] = field(default_factory=tuple)
    suppress_telemetry: bool = False
    freeze_replay: bool = False
    isolate_workloads: tuple[str, ...] = field(default_factory=tuple)
    reduce_concurrency: bool = False
    details: Mapping[str, object] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if type(self) is not ArbitrationResult:
            exception_message = "arbitration result owner rejected"
            raise TypeError(exception_message)
        evidence: tuple[Mapping[str, object], ...] = ()
        action, issues = runtime_text(
            self.action, field_name="arbitration_action", default="degrade"
        )
        evidence += issues
        reason, issues = runtime_text(
            self.reason,
            field_name="arbitration_reason",
            default="runtime_input_rejected",
        )
        evidence += issues
        domains, issues = runtime_sequence(
            self.delegated_domains, field_name="arbitration_delegated_domains"
        )
        evidence += issues
        workloads, issues = runtime_sequence(
            self.isolate_workloads, field_name="arbitration_isolate_workloads"
        )
        evidence += issues
        delegated_domains = []
        for index, item in enumerate(domains):
            text, issues = runtime_text(
                item,
                field_name=_runtime_indexed_name("arbitration_delegated_domain", index),
                default="input_rejected",
            )
            evidence += issues
            delegated_domains.append(text)
        isolate_workloads = []
        for index, item in enumerate(workloads):
            text, issues = runtime_text(
                item,
                field_name=_runtime_indexed_name("arbitration_isolate_workload", index),
                default=_runtime_indexed_name("input_rejected", index),
            )
            evidence += issues
            isolate_workloads.append(text)
        details, issues = runtime_mapping(
            self.details, field_name="arbitration_details"
        )
        evidence += issues
        for field_name in (
            "suppress_telemetry",
            "freeze_replay",
            "reduce_concurrency",
        ):
            parsed, issues = runtime_bool(
                no_hook_exact_owner_field(self, ArbitrationResult, field_name),
                field_name="arbitration_" + field_name,
            )
            evidence += issues
            object.__setattr__(self, field_name, parsed)
        if evidence:
            action = "degrade"
            reason = "runtime_input_rejected"
            details["input_evidence"] = evidence
        object.__setattr__(self, "action", action)
        object.__setattr__(self, "reason", reason)
        object.__setattr__(self, "delegated_domains", tuple(delegated_domains))
        object.__setattr__(self, "isolate_workloads", tuple(isolate_workloads))
        object.__setattr__(self, "details", freeze_runtime_value(details))

    def as_dict(self) -> dict[str, object]:
        return {"action": self.action, "reason": self.reason, "delegated_domains": list(self.delegated_domains), "suppress_telemetry": self.suppress_telemetry, "freeze_replay": self.freeze_replay, "isolate_workloads": list(self.isolate_workloads), "reduce_concurrency": self.reduce_concurrency, "details": materialize_runtime_value(self.details)}


def arbitrate_stabilization(
    *,
    events: object=(),
    invariant_snapshot: Mapping[str, object] | None = None,
    budgets: Mapping[str, object] | None = None,
    topology: Mapping[str, object] | None = None,
) -> ArbitrationResult:
    topo_report = analyze_topology_pressure(events)
    topology_input = topo_report.as_dict() if topology is None else topology
    base: StabilizationDecision = decide_stabilization(
        invariant_snapshot=invariant_snapshot,
        budgets=budgets,
        topology=topology_input,
    )
    ledger = get_runtime_debt_ledger()
    budget_rows, input_evidence = runtime_mapping(
        budgets, field_name="arbitration_budgets"
    )
    for index, (raw_workload, raw_budget) in enumerate(dict.items(budget_rows)):
        workload, issues = runtime_text(
            raw_workload,
            field_name=_runtime_indexed_name("arbitration_workload", index),
            default=_runtime_indexed_name("input_rejected", index),
        )
        input_evidence += issues
        budget, issues = runtime_mapping(
            raw_budget, field_name=_runtime_indexed_name("arbitration_budget", index)
        )
        input_evidence += issues
        if issues:
            continue
        event_cost, issues = runtime_float(
            dict.get(budget, "cost", 0.0),
            field_name=_runtime_indexed_name("arbitration_budget", index, "_cost"),
            minimum=0.0,
        )
        input_evidence += issues
        suppressed, issues = runtime_float(
            dict.get(budget, "suppressed", 0.0),
            field_name=_runtime_indexed_name("arbitration_budget", index, "_suppressed"),
            minimum=0.0,
        )
        input_evidence += issues
        ledger.record(workload, event=event_cost, telemetry=suppressed * 0.1)
    hot = set(ledger.hot_workloads())
    base_details, issues = runtime_mapping(
        base.details, field_name="arbitration_base_details"
    )
    input_evidence += issues
    base_hot, issues = runtime_sequence(
        dict.get(base_details, "hot_workloads"),
        field_name="arbitration_base_hot_workloads",
    )
    input_evidence += issues
    for index, raw_workload in enumerate(base_hot):
        workload, issues = runtime_text(
            raw_workload,
            field_name=_runtime_indexed_name("arbitration_base_hot_workload", index),
            default=_runtime_indexed_name("input_rejected", index),
        )
        input_evidence += issues
        if not issues:
            hot.add(workload)
    domains: list[str] = []
    if topo_report.pressure >= PLR2004N0_25:
        domains.append('event_topology')
    if any('replay' in a for a in topo_report.actions) or base.freeze_replay:
        domains.append('replay')
    if base.suppress_telemetry:
        domains.append('telemetry')
    if base.reduce_concurrency or hot:
        domains.append('scheduler')
    details = {
        "topology": topo_report.as_dict(),
        "debt": ledger.snapshot(),
        "input_evidence": input_evidence,
    }
    if not domains and base.action == "normal" and not input_evidence:
        return ArbitrationResult("normal", "stable", details=details)
    return ArbitrationResult(
        "degrade",
        "+".join(
            sorted(
                set(
                    [base.reason]
                    + list(topo_report.anomalies)
                    + (["runtime_input_rejected"] if input_evidence else [])
                )
            )
        )
        or "pressure",
        delegated_domains=tuple(sorted(set(domains))),
        suppress_telemetry=base.suppress_telemetry or topo_report.pressure > PLR2004N0_5,
        freeze_replay=base.freeze_replay
        or "freeze_deep_replay" in topo_report.actions,
        isolate_workloads=tuple(sorted(hot))[:32],
        reduce_concurrency=base.reduce_concurrency or bool(hot),
        details=details,
    )

__all__ = ("ArbitrationResult", "arbitrate_stabilization")
