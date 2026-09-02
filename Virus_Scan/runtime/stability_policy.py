"""Authoritative stabilization policies for event-native runtime governance.

The policy layer converts observed pressure into enforced degradation decisions.
It is intentionally deterministic and side-effect-free: RuntimeRoot/event bus own
mutation and emission; this module only returns mandatory runtime actions.
"""
from __future__ import annotations

from Virus_Scan.contracts.no_hook_materialization import no_hook_exact_owner_field
from dataclasses import dataclass, field
from typing import Mapping

from Virus_Scan.runtime.governance_inputs import (
    runtime_bool,
    runtime_float,
    runtime_int,
    runtime_mapping,
    runtime_text,
)
from Virus_Scan.runtime.immutable_core import freeze_runtime_value, materialize_runtime_value


PLR2004N0_45 = 0.45
PLR2004N0_55 = 0.55
PLR2004N128 = 128
PLR2004N2_0 = 2.0
PLR2004N4096_0 = 4096.0
PLR2004N50000 = 50000


def _stabilization_indexed_name(prefix: str, index: int, suffix: str = "") -> str:
    if type(index) is int and type(index) is not bool:
        index_text = int.__str__(index)
    else:
        index_text = "index"
    return prefix + "_" + index_text + suffix


@dataclass(frozen=True)
class StabilizationDecision:
    action: str
    reason: str
    freeze_replay: bool = False
    suppress_telemetry: bool = False
    isolate_workload: bool = False
    reduce_concurrency: bool = False
    throttle_invariants: bool = False
    rollback_stabilization: bool = False
    compress_lineage: bool = False
    details: Mapping[str, object] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if type(self) is not StabilizationDecision:
            exception_message = "stabilization decision owner rejected"
            raise TypeError(exception_message)
        action, action_issues = runtime_text(
            self.action, field_name="stabilization_action", default="degrade"
        )
        reason, reason_issues = runtime_text(
            self.reason,
            field_name="stabilization_reason",
            default="runtime_input_rejected",
        )
        details, detail_issues = runtime_mapping(
            self.details, field_name="stabilization_details"
        )
        issues = action_issues + reason_issues + detail_issues
        if issues:
            details["input_evidence"] = issues
            action = "degrade"
            reason = "runtime_input_rejected"
        object.__setattr__(self, "action", action)
        object.__setattr__(self, "reason", reason)
        for field_name in (
            "freeze_replay",
            "suppress_telemetry",
            "isolate_workload",
            "reduce_concurrency",
            "throttle_invariants",
            "rollback_stabilization",
            "compress_lineage",
        ):
            parsed, bool_issues = runtime_bool(
                no_hook_exact_owner_field(self, StabilizationDecision, field_name),
                field_name="stabilization_" + field_name,
            )
            if bool_issues:
                details.setdefault("input_evidence", ())
                details["input_evidence"] = (
                    tuple(details["input_evidence"]) + bool_issues
                )
                action = "degrade"
                reason = "runtime_input_rejected"
            object.__setattr__(self, field_name, parsed)
        object.__setattr__(self, "action", action)
        object.__setattr__(self, "reason", reason)
        object.__setattr__(self, "details", freeze_runtime_value(details))

    def as_dict(self) -> dict[str, object]:
        return {
            "action": self.action,
            "reason": self.reason,
            "freeze_replay": self.freeze_replay,
            "suppress_telemetry": self.suppress_telemetry,
            "isolate_workload": self.isolate_workload,
            "reduce_concurrency": self.reduce_concurrency,
            "throttle_invariants": self.throttle_invariants,
            "rollback_stabilization": self.rollback_stabilization,
            "compress_lineage": self.compress_lineage,
            "details": materialize_runtime_value(self.details),
        }


def _stabilization_inputs(
    invariant_snapshot: Mapping[str, object] | None,
    budgets: Mapping[str, object] | None,
    topology: Mapping[str, object] | None,
    lineage_pressure: Mapping[str, object] | None,
) -> tuple[
    dict[object, object],
    dict[object, object],
    dict[object, object],
    dict[object, object],
    tuple[Mapping[str, object], ...],
]:
    invariant, invariant_issues = runtime_mapping(
        invariant_snapshot, field_name="stabilization_invariant_snapshot"
    )
    budget_rows, budget_issues = runtime_mapping(
        budgets, field_name="stabilization_budgets"
    )
    topology_state, topology_issues = runtime_mapping(
        topology, field_name="stabilization_topology"
    )
    lineage, lineage_issues = runtime_mapping(
        lineage_pressure, field_name="stabilization_lineage_pressure"
    )
    return (
        invariant,
        budget_rows,
        topology_state,
        lineage,
        invariant_issues + budget_issues + topology_issues + lineage_issues,
    )


def _stabilization_budget_metrics(
    budget_rows: dict[object, object],
) -> tuple[int, float, list[str], tuple[Mapping[str, object], ...]]:
    suppressed_total = 0
    cost_total = 0.0
    hot_workloads: list[str] = []
    input_evidence: tuple[Mapping[str, object], ...] = ()
    for index, (raw_workload, raw_data) in enumerate(dict.items(budget_rows)):
        workload, issues = runtime_text(
            raw_workload,
            field_name=_stabilization_indexed_name("stabilization_workload", index),
            default=_stabilization_indexed_name("input_rejected", index),
        )
        input_evidence += issues
        data, issues = runtime_mapping(
            raw_data, field_name=_stabilization_indexed_name("stabilization_budget", index)
        )
        input_evidence += issues
        if issues:
            continue
        suppressed, issues = runtime_int(
            dict.get(data, "suppressed", 0),
            field_name=_stabilization_indexed_name("stabilization_budget", index, "_suppressed"),
        )
        input_evidence += issues
        cost, issues = runtime_float(
            dict.get(data, "cost", 0.0),
            field_name=_stabilization_indexed_name("stabilization_budget", index, "_cost"),
            minimum=0.0,
        )
        input_evidence += issues
        suppressed_total += suppressed
        cost_total += cost
        if suppressed > PLR2004N128 or cost > PLR2004N4096_0:
            hot_workloads.append(workload)
    return suppressed_total, cost_total, hot_workloads, input_evidence


def _stabilization_pressure_metrics(
    topology_state: dict[object, object],
    lineage: dict[object, object],
) -> tuple[int, float, str, float, float, str, tuple[Mapping[str, object], ...]]:
    event_count, event_issues = runtime_int(
        dict.get(topology_state, "event_count", 0),
        field_name="stabilization_event_count",
    )
    topology_pressure, topology_issues = runtime_float(
        dict.get(topology_state, "pressure", 0.0),
        field_name="stabilization_topology_pressure",
        minimum=0.0,
        maximum=1.0,
    )
    lineage_action, lineage_action_issues = runtime_text(
        dict.get(lineage, "action", "normal"),
        field_name="stabilization_lineage_action",
        default="input_rejected",
    )
    lineage_pressure, lineage_pressure_issues = runtime_float(
        dict.get(lineage, "pressure", 0.0),
        field_name="stabilization_lineage_pressure_value",
        minimum=0.0,
        maximum=1.0,
    )
    causal, causal_issues = runtime_mapping(
        dict.get(topology_state, "causal_forecast"),
        field_name="stabilization_causal_forecast",
    )
    causal_anomaly, anomaly_issues = runtime_float(
        dict.get(causal, "anomaly_probability", 0.0),
        field_name="stabilization_causal_anomaly_probability",
        minimum=0.0,
        maximum=1.0,
    )
    causal_action, action_issues = runtime_text(
        dict.get(causal, "action", "normal"),
        field_name="stabilization_causal_action",
        default="input_rejected",
    )
    return (
        event_count,
        topology_pressure,
        lineage_action,
        lineage_pressure,
        causal_anomaly,
        causal_action,
        event_issues
        + topology_issues
        + lineage_action_issues
        + lineage_pressure_issues
        + causal_issues
        + anomaly_issues
        + action_issues,
    )


def _stabilization_reasons(
    *,
    invariant_failed: bool,
    suppressed_total: int,
    cost_total: float,
    hot_workloads: list[str],
    event_count: int,
    topology_pressure: float,
    lineage_action: str,
    lineage_pressure: float,
    causal_anomaly: float,
    causal_action: str,
    has_input_evidence: bool,
) -> list[str]:
    reasons: list[str] = []
    if invariant_failed:
        reasons.append("runtime_invariant_violation")
    if hot_workloads:
        reasons.append("workload_event_pressure")
    if has_input_evidence:
        reasons.append("runtime_input_rejected")
    if event_count > PLR2004N50000 or topology_pressure >= PLR2004N0_55 or causal_anomaly >= PLR2004N0_45:
        reasons.append("event_stream_pressure")
    if causal_action in {"terminate_replay_branch", "isolate_topology_region"}:
        reasons.append("causal_topology_instability")
    if lineage_action in {"compress_lineage", "throttle_replay"} or lineage_pressure >= PLR2004N0_55:
        reasons.append("replay_lineage_pressure")
    invariant_cost_ratio = cost_total / max(1.0, float(event_count))
    if invariant_cost_ratio > PLR2004N2_0 and suppressed_total > 0:
        reasons.append("invariant_enforcement_amplification")
    if suppressed_total > max(256, event_count // 4):
        reasons.append("stabilization_overcorrection")
    return reasons


def decide_stabilization(
    *,
    invariant_snapshot: Mapping[str, object] | None = None,
    budgets: Mapping[str, object] | None = None,
    topology: Mapping[str, object] | None = None,
    lineage_pressure: Mapping[str, object] | None = None,
) -> StabilizationDecision:
    inv, budget_rows, topology_state, lineage, input_evidence = (
        _stabilization_inputs(
            invariant_snapshot, budgets, topology, lineage_pressure
        )
    )
    invariant_ok, issues = runtime_bool(
        dict.get(inv, "ok", True),
        field_name="stabilization_invariant_ok",
        default=False,
    )
    input_evidence += issues
    suppressed_total, cost_total, hot_workloads, budget_input_evidence = (
        _stabilization_budget_metrics(budget_rows)
    )
    input_evidence += budget_input_evidence
    (
        event_count,
        topo_pressure,
        lineage_action,
        lineage_p,
        causal_anomaly,
        causal_action,
        pressure_input_evidence,
    ) = _stabilization_pressure_metrics(topology_state, lineage)
    input_evidence += pressure_input_evidence
    reasons = _stabilization_reasons(
        invariant_failed=len(inv) > 0 and not invariant_ok,
        suppressed_total=suppressed_total,
        cost_total=cost_total,
        hot_workloads=hot_workloads,
        event_count=event_count,
        topology_pressure=topo_pressure,
        lineage_action=lineage_action,
        lineage_pressure=lineage_p,
        causal_anomaly=causal_anomaly,
        causal_action=causal_action,
        has_input_evidence=len(input_evidence) > 0,
    )
    if not reasons:
        return StabilizationDecision(
            "normal",
            "stable",
            details={
                "suppressed_total": suppressed_total,
                "cost_total": round(cost_total, 4),
            },
        )
    reason = "+".join(sorted(set(reasons)))
    return StabilizationDecision(
        "degrade",
        reason,
        freeze_replay="runtime_invariant_violation" in reasons or "replay_lineage_pressure" in reasons or "causal_topology_instability" in reasons,
        suppress_telemetry=True,
        isolate_workload=len(hot_workloads) > 0 or "event_stream_pressure" in reasons,
        reduce_concurrency="event_stream_pressure" in reasons or len(hot_workloads) > 0,
        throttle_invariants="invariant_enforcement_amplification" in reasons or "event_stream_pressure" in reasons,
        rollback_stabilization="stabilization_overcorrection" in reasons,
        compress_lineage="replay_lineage_pressure" in reasons or "causal_topology_instability" in reasons,
        details={
            "hot_workloads": hot_workloads[:16],
            "suppressed_total": suppressed_total,
            "cost_total": round(cost_total, 4),
            "topology_pressure": topo_pressure,
            "lineage_pressure": lineage_p,
            "causal_anomaly_probability": causal_anomaly,
            "causal_action": causal_action,
            "input_evidence": input_evidence,
        },
    )


__all__ = ("StabilizationDecision", "decide_stabilization")
