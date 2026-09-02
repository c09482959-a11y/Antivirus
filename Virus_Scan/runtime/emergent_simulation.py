"""Stage 40 emergent-behavior simulation and degradation planning.

The simulator is deterministic and snapshot-driven.  It exercises the Window 10
risk classes without creating asynchronous background work or mutable global
state: replay cascades, topology explosions, stabilization recursion, and
governance divergence are modeled as projected pressure curves and mandatory
containment actions.
"""
from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field

from Virus_Scan.contracts.no_hook_materialization import (
    exact_finite_float_or_none,
    materialize_json_no_hook,
    no_hook_mapping_items,
    no_hook_type_name,
)
from Virus_Scan.runtime.immutable_core import freeze_runtime_value, materialize_runtime_value
from Virus_Scan.runtime.governance_inputs import (
    runtime_bool,
    runtime_float,
    runtime_int,
    runtime_sequence,
    runtime_text,
)


EmergentValue = object
EmergentRecord = dict[str, EmergentValue]
EmergentEvidence = Mapping[str, EmergentValue]


@dataclass(frozen=True)
class EmergentScenarioResult:
    name: str
    risk: float
    predicted_failure: bool
    reasons: tuple[str, ...] = field(default_factory=tuple)
    actions: tuple[str, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        if type(self) is not EmergentScenarioResult:
            exception_message = "emergent scenario result owner rejected"
            raise TypeError(exception_message)
        evidence: tuple[EmergentEvidence, ...] = ()
        name, issues = runtime_text(
            self.name, field_name="emergent_scenario_name", default="input_rejected"
        )
        evidence += issues
        risk, issues = runtime_float(
            self.risk,
            field_name="emergent_scenario_risk",
            default=1.0,
            minimum=0.0,
            maximum=1.0,
        )
        evidence += issues
        predicted, issues = runtime_bool(
            self.predicted_failure,
            field_name="emergent_scenario_predicted_failure",
            default=True,
        )
        evidence += issues
        reasons, issues = _emergent_text_sequence(
            self.reasons, "emergent_scenario_reasons"
        )
        evidence += issues
        actions, issues = _emergent_text_sequence(
            self.actions, "emergent_scenario_actions"
        )
        evidence += issues
        if evidence:
            risk = 1.0
            predicted = True
            reasons = tuple(sorted(set((*reasons, 'runtime_input_rejected'))))
        object.__setattr__(self, "name", name)
        object.__setattr__(self, "risk", risk)
        object.__setattr__(self, "predicted_failure", predicted)
        object.__setattr__(self, "reasons", reasons)
        object.__setattr__(self, "actions", actions)

    def as_dict(self) -> EmergentRecord:
        return {
            "name": self.name,
            "risk": round(self.risk, 4),
            "predicted_failure": self.predicted_failure,
            "reasons": list(self.reasons),
            "actions": list(self.actions),
        }


@dataclass(frozen=True)
class EmergentSimulationReport:
    ok: bool
    overall_risk: float
    scenarios: tuple[EmergentScenarioResult, ...]
    graceful_degradation: EmergentEvidence
    immutable_invariants: EmergentEvidence

    def __post_init__(self) -> None:
        if type(self) is not EmergentSimulationReport:
            exception_message = "emergent simulation report owner rejected"
            raise TypeError(exception_message)
        ok, ok_issues = runtime_bool(
            self.ok, field_name="emergent_simulation_ok", default=False
        )
        overall, risk_issues = runtime_float(
            self.overall_risk,
            field_name="emergent_simulation_overall_risk",
            default=1.0,
            minimum=0.0,
            maximum=1.0,
        )
        scenario_rows, scenario_issues = runtime_sequence(
            self.scenarios, field_name="emergent_simulation_scenarios"
        )
        scenarios: list[EmergentScenarioResult] = []
        for row in scenario_rows:
            if type(row) is EmergentScenarioResult:
                scenarios.append(row)
            else:
                scenarios.append(
                    EmergentScenarioResult(
                        "input_rejected",
                        1.0,
                        True,
                        reasons=("runtime_input_rejected",),
                    )
                )
        evidence = ok_issues + risk_issues + scenario_issues
        degradation = freeze_runtime_value(
            {} if self.graceful_degradation is None else self.graceful_degradation
        )
        invariants = freeze_runtime_value(
            {} if self.immutable_invariants is None else self.immutable_invariants
        )
        if evidence:
            ok = False
            overall = 1.0
            degradation = freeze_runtime_value(
                {
                    "required": True,
                    "actions": ("preserve_runtime_input_evidence",),
                    "input_evidence": evidence,
                    "source": degradation,
                }
            )
        object.__setattr__(self, "ok", ok)
        object.__setattr__(self, "overall_risk", overall)
        object.__setattr__(self, "scenarios", tuple(scenarios))
        object.__setattr__(self, "graceful_degradation", degradation)
        object.__setattr__(self, "immutable_invariants", invariants)

    def as_dict(self) -> EmergentRecord:
        return {
            "ok": self.ok,
            "overall_risk": round(self.overall_risk, 4),
            "scenarios": [s.as_dict() for s in self.scenarios],
            "graceful_degradation": materialize_runtime_value(self.graceful_degradation),
            "immutable_invariants": materialize_runtime_value(self.immutable_invariants),
        }


def _failure_record(value: EmergentValue, *, reason: str, field: str = "event") -> EmergentRecord:
    return {
        "seq": 0,
        "domain": "runtime",
        "kind": "unsupported_emergent_value",
        "owner": "runtime",
        "schema_version": 1,
        "parent_seq": None,
        "causal_depth": 0,
        "event_unavailable": True,
        "event_unavailable_reason": reason,
        "event_value_field": field,
        "event_value_type": no_hook_type_name(value),
    }


def _emergent_text(value: EmergentValue, default: str) -> str:
    if type(value) is str:
        return str.__str__(value)
    return default


def _emergent_join(prefix: EmergentValue, suffix: EmergentValue) -> str:
    return _emergent_text(prefix, "emergent") + "_" + _emergent_text(suffix, "field")


def _emergent_indexed_field(field_name: EmergentValue, index: int) -> str:
    index_text = int.__str__(index) if type(index) is int else "0"
    return _emergent_text(field_name, "emergent_field") + "_" + index_text


def _emergent_context(field: EmergentValue) -> str:
    return _emergent_join("emergent", field)


def _emergent_unavailable_reason_field(field_name: EmergentValue) -> str:
    return _emergent_join(field_name, "unavailable_reason")


def _emergent_mapping_items(value: EmergentValue) -> tuple[tuple[EmergentValue, EmergentValue], ...]:
    items = no_hook_mapping_items(value)
    if items is None:
        return ()
    return tuple(items)


def _emergent_mapping_values(value: EmergentValue) -> tuple[EmergentValue, ...]:
    return tuple(item for _key, item in _emergent_mapping_items(value))


def _emergent_text_sequence(
    value: EmergentValue, field_name: str
) -> tuple[tuple[str, ...], tuple[EmergentEvidence, ...]]:
    rows, evidence = runtime_sequence(value, field_name=field_name)
    output: list[str] = []
    for index, row in enumerate(rows):
        text, issues = runtime_text(
            row,
            field_name=_emergent_indexed_field(field_name, index),
            default="input_rejected",
        )
        evidence += issues
        output.append(text)
    return tuple(output), evidence


def _contains_unavailable(value: EmergentValue) -> bool:
    items = _emergent_mapping_items(value)
    if items:
        for key, item in items:
            if type(key) is str and (
                key == "unavailable_reason" or key.endswith(("_unavailable", "_unavailable_reason"))
            ):
                return True
            if _contains_unavailable(item):
                return True
        return False
    if type(value) is tuple:
        return any(_contains_unavailable(item) for item in value)
    if type(value) is list:
        return any(_contains_unavailable(item) for item in list.__iter__(value))
    return False


def _event_sequence(events: EmergentValue) -> tuple[EmergentValue, ...]:
    if events is None:
        return ()
    if type(events) is tuple:
        return events
    if type(events) is list:
        return tuple(list.__iter__(events))
    return (_failure_record(events, reason="non_materializable_emergent_event_sequence", field="events"),)


def _event_dict(ev: EmergentValue) -> EmergentRecord:
    materialized = materialize_json_no_hook(ev, context="emergent_event", max_depth=8)
    if type(materialized) is dict:
        if "unavailable_reason" in materialized and "domain" not in materialized:
            return _failure_record(ev, reason="non_materializable_emergent_event", field="event")
        normalized = {
            key: item
            for key, item in _emergent_mapping_items(materialized)
            if type(key) is str
        }
        for field_name in ("seq", "causal_depth"):
            if field_name not in normalized:
                continue
            parsed, issues = runtime_int(
                dict.get(normalized, field_name),
                field_name=_emergent_join("emergent_event", field_name),
                default=0,
            )
            normalized[field_name] = parsed
            if issues:
                normalized[_emergent_unavailable_reason_field(field_name)] = issues[0]["reason"]
        parent = dict.get(normalized, "parent_seq")
        if parent is not None:
            parsed_parent, issues = runtime_int(
                parent,
                field_name="emergent_event_parent_seq",
                default=0,
            )
            normalized["parent_seq"] = None if issues else parsed_parent
            if issues:
                normalized["parent_seq_unavailable_reason"] = issues[0]["reason"]
        return normalized
    return _failure_record(ev, reason="non_mapping_emergent_event", field="event")


def _mapping_snapshot(value: EmergentValue, *, field_name: str) -> EmergentRecord:
    if value is None:
        return {}
    items = no_hook_mapping_items(value)
    if items is None:
        return {
            field_name + "_unavailable": True,
            field_name + "_unavailable_reason": "non_materializable_emergent_mapping",
            field_name + "_value_type": no_hook_type_name(value),
        }
    materialized = materialize_json_no_hook(value, context=_emergent_context(field_name), max_depth=8)
    if type(materialized) is dict:
        return {
            key: item
            for key, item in _emergent_mapping_items(materialized)
            if type(key) is str
        }
    return {
        field_name + "_unavailable": True,
        field_name + "_unavailable_reason": "emergent_mapping_materialization_failed",
        field_name + "_value_type": no_hook_type_name(value),
    }


def _emergent_int(value: EmergentValue, default: int = 0) -> int:
    metric, _issues = runtime_int(
        value,
        field_name="emergent_integer",
        default=default,
    )
    return metric


def _emergent_float(value: EmergentValue, default: float = 0.0) -> float:
    metric = exact_finite_float_or_none(value)
    return metric if metric is not None else default


_CORRECTIVE_DOMAINS = frozenset(
    {"governance", "telemetry", "scheduler", "replay", "saturation", "semantic"}
)


def _parent_chain_is_acyclic(
    parent_seq: int,
    by_seq: Mapping[int, EmergentRecord],
) -> bool:
    seen: set[int] = set()
    current = parent_seq
    acyclic = True
    while current in by_seq:
        if current in seen:
            acyclic = False
            break
        seen.add(current)
        next_parent = by_seq[current].get("parent_seq")
        if next_parent is None:
            break
        current = _emergent_int(next_parent, 0)
    return acyclic


def _corrective_chain_state(
    parent_seq: EmergentValue | None,
    by_seq: Mapping[int, EmergentRecord],
) -> tuple[int, bool]:
    depth = 1
    acyclic = True
    seen: set[int] = set()
    current_parent = parent_seq
    while current_parent is not None and _emergent_int(current_parent, 0) in by_seq:
        current_seq = _emergent_int(current_parent, 0)
        if current_seq in seen:
            acyclic = False
            break
        seen.add(current_seq)
        parent_event = by_seq[current_seq]
        if parent_event.get("domain") not in _CORRECTIVE_DOMAINS:
            break
        depth += 1
        current_parent = parent_event.get("parent_seq")
    return depth, acyclic


def _event_invariant_state(
    event: EmergentRecord,
    by_seq: Mapping[int, EmergentRecord],
) -> tuple[bool, bool, int, int | None]:
    seq = _emergent_int(event.get("seq"), 0)
    parent = event.get("parent_seq")
    parent_before_child = True
    acyclic = True
    violation: int | None = None
    if parent is not None:
        parent_seq = _emergent_int(parent, 0)
        parent_before_child = parent_seq in by_seq and parent_seq < seq
        acyclic = _parent_chain_is_acyclic(parent_seq, by_seq)
    if event.get("domain") in _CORRECTIVE_DOMAINS:
        depth, chain_acyclic = _corrective_chain_state(parent, by_seq)
        acyclic = acyclic and chain_acyclic
        if depth > 3:
            violation = seq
    return (
        parent_before_child,
        acyclic,
        _emergent_int(event.get("causal_depth"), 0),
        violation,
    )


def immutable_orchestration_invariants(events: Sequence[EmergentValue]) -> EmergentRecord:
    event_list = [_event_dict(ev) for ev in _event_sequence(events)]
    input_rejected = any(_contains_unavailable(event) for event in event_list)
    by_seq = {_emergent_int(ev.get("seq"), 0): ev for ev in event_list}
    parent_before_child = True
    acyclic = True
    max_depth = 0
    corrective_chain_bad: list[int] = []
    for event in event_list:
        event_parent_before_child, event_acyclic, event_depth, violation = (
            _event_invariant_state(event, by_seq)
        )
        parent_before_child = parent_before_child and event_parent_before_child
        acyclic = acyclic and event_acyclic
        max_depth = max(max_depth, event_depth)
        if violation is not None:
            corrective_chain_bad.append(violation)
    ok = all(
        (
            parent_before_child,
            acyclic,
            not corrective_chain_bad,
            not input_rejected,
        )
    )
    return {"ok": ok, "replay_acyclic": acyclic, "parent_before_child": parent_before_child, "max_depth": max_depth, "stabilization_recursion_violations": corrective_chain_bad[:64], "workloads_terminate_assumption": True, "input_rejected": input_rejected}


def _scenario(name: str, risk: float, thresholds: tuple[tuple[float, str], ...], actions: tuple[str, ...]) -> EmergentScenarioResult:
    reasons = tuple(reason for threshold, reason in thresholds if risk >= threshold)
    return EmergentScenarioResult(name=name, risk=min(1.0, max(0.0, risk)), predicted_failure=len(reasons) > 0, reasons=reasons, actions=actions if reasons else ())


def simulate_emergent_behaviors(events: Sequence[EmergentValue], *, topology: EmergentEvidence | None = None, lineage: EmergentEvidence | None = None, budgets: EmergentEvidence | None = None, convergence: EmergentEvidence | None = None) -> EmergentSimulationReport:
    event_list = [_event_dict(ev) for ev in _event_sequence(events)]
    topology = _mapping_snapshot(topology, field_name="topology")
    lineage = _mapping_snapshot(lineage, field_name="lineage")
    budgets = _mapping_snapshot(budgets, field_name="budgets")
    convergence = _mapping_snapshot(convergence, field_name="convergence")
    boundary_rejected = any(
        _contains_unavailable(value)
        for value in (event_list, topology, lineage, budgets, convergence)
    )
    event_count = max(1, len(event_list))
    edge_count = sum(1 for ev in event_list if ev.get("parent_seq") is not None)
    density = edge_count / event_count
    max_depth = max((_emergent_int(ev.get("causal_depth"), 0) for ev in event_list), default=0)
    suppressed = sum(
        _emergent_int(dict.get(b, "suppressed"), 0)
        for b in _emergent_mapping_values(budgets)
        if type(b) is dict
    )
    suppression_ratio = suppressed / max(1, event_count + suppressed)
    topo_pressure = _emergent_float(topology.get("pressure"), 0.0)
    causal_value = topology.get("causal_forecast")
    causal: EmergentRecord = (
        {
            key: item
            for key, item in _emergent_mapping_items(causal_value)
            if type(key) is str
        }
        if type(causal_value) is dict
        else {}
    )
    causal_risk = _emergent_float(causal.get("anomaly_probability"), 0.0)
    lineage_pressure = _emergent_float(lineage.get("pressure"), 0.0)
    violated, violation_issues = runtime_bool(
        dict.get(convergence, "violated", False),
        field_name="emergent_convergence_violated",
        default=False,
    )
    boundary_rejected = boundary_rejected or len(violation_issues) > 0
    convergence_risk = 1.0 if violated or boundary_rejected else 0.0

    scenarios = (
        _scenario("replay_cascade", max(lineage_pressure, max_depth / 64.0, causal_risk), ((0.45, "replay_cascade_possible"), (0.75, "replay_cascade_likely")), ("freeze_replay", "compress_lineage", "isolate_topology_region")),
        _scenario("topology_explosion", max(topo_pressure, density * 0.75 + causal_risk * 0.25), ((0.45, "topology_growth_unstable"), (0.80, "topology_collapse_risk")), ("reduce_concurrency", "isolate_topology_region", "summarize_topology")),
        _scenario("stabilization_recursion", max(suppression_ratio, convergence_risk), ((0.25, "stabilization_feedback_visible"), (0.70, "stabilization_recursion_risk")), ("activate_stabilization_firebreak", "suppress_noncritical_telemetry", "rollback_stabilization")),
        _scenario("governance_divergence", max(convergence_risk, topo_pressure * 0.5 + lineage_pressure * 0.5), ((0.40, "governance_divergence_possible"), (0.75, "governance_divergence_likely")), ("enforce_convergence_latency", "isolate_workload", "recompute_governance_snapshot")),
    )
    overall = max((s.risk for s in scenarios), default=0.0)
    actions = []
    for s in scenarios:
        for action in s.actions:
            if action not in actions:
                actions.append(action)
    degradation = {
        "required": any(s.predicted_failure for s in scenarios) or boundary_rejected,
        "freeze_replay": "freeze_replay" in actions,
        "reduce_concurrency": "reduce_concurrency" in actions,
        "isolate_unstable_topology": "isolate_topology_region" in actions,
        "suppress_noncritical_telemetry": "suppress_noncritical_telemetry" in actions,
        "rollback_stabilization": "rollback_stabilization" in actions,
        "actions": actions,
        "input_rejected": boundary_rejected,
    }
    invariants = immutable_orchestration_invariants(event_list)
    ok = (
        not any(s.predicted_failure and s.risk >= 0.75 for s in scenarios)
        and dict.get(invariants, "ok", False) is True
        and not boundary_rejected
    )
    return EmergentSimulationReport(ok=ok, overall_risk=overall, scenarios=scenarios, graceful_degradation=degradation, immutable_invariants=invariants)


__all__ = ("EmergentScenarioResult", "EmergentSimulationReport", "immutable_orchestration_invariants", "simulate_emergent_behaviors")
