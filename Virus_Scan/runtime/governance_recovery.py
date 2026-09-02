"""Governance convergence verification and deterministic rollback planning."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Mapping

from Virus_Scan.runtime.governance_inputs import (
    runtime_bool,
    runtime_float,
    runtime_int,
    runtime_mapping,
    runtime_sequence,
    runtime_text,
)
from Virus_Scan.runtime.immutable_core import (
    freeze_runtime_value,
    materialize_runtime_value,
)


PLR2004N0_55 = 0.55


def _governance_child_field(parent: str, child: str) -> str:
    if type(parent) is str and type(child) is str:
        return str.__str__(parent) + "_" + str.__str__(child)
    return "governance_field"


def _governance_index_field(parent: str, index: int, suffix: str | None = None) -> str:
    if type(parent) is not str or type(index) is not int or type(index) is bool:
        return "governance_index"
    field_name = str.__str__(parent) + "_" + int.__str__(index)
    if type(suffix) is str and suffix:
        field_name += "_" + str.__str__(suffix)
    return field_name


def _snapshot_mapping(
    snapshot: dict[str, object],
    key: str,
) -> tuple[dict[str, object], tuple[Mapping[str, object], ...]]:
    return runtime_mapping(
        dict.get(snapshot, key), field_name=_governance_child_field("governance", key)
    )


def _normalized_text_sequence(
    value: object, *, field_name: str
) -> tuple[tuple[str, ...], tuple[Mapping[str, object], ...]]:
    rows, evidence = runtime_sequence(value, field_name=field_name)
    out: list[str] = []
    for index, row in enumerate(rows):
        text, issues = runtime_text(
            row,
            field_name=_governance_index_field(field_name, index),
            default="input_rejected",
        )
        evidence += issues
        out.append(text)
    return tuple(out), evidence


@dataclass(frozen=True)
class GovernanceConvergenceReport:
    ok: bool
    drift_domains: tuple[str, ...] = field(default_factory=tuple)
    reasons: tuple[str, ...] = field(default_factory=tuple)
    metrics: Mapping[str, object] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if type(self) is not GovernanceConvergenceReport:
            exception_message = "governance convergence report owner rejected"
            raise TypeError(exception_message)
        evidence: tuple[Mapping[str, object], ...] = ()
        ok, issues = runtime_bool(
            self.ok, field_name="governance_convergence_ok", default=False
        )
        evidence += issues
        domains, issues = _normalized_text_sequence(
            self.drift_domains,
            field_name="governance_convergence_drift_domains",
        )
        evidence += issues
        reasons, issues = _normalized_text_sequence(
            self.reasons, field_name="governance_convergence_reasons"
        )
        evidence += issues
        metrics, issues = runtime_mapping(
            self.metrics, field_name="governance_convergence_metrics"
        )
        evidence += issues
        if evidence:
            ok = False
            domains = tuple(sorted({*domains, 'governance'}))
            reasons = tuple(
                sorted({*reasons, 'runtime_input_rejected'})
            )
            metrics["input_evidence"] = evidence
        object.__setattr__(self, "ok", ok)
        object.__setattr__(self, "drift_domains", domains)
        object.__setattr__(self, "reasons", reasons)
        object.__setattr__(self, "metrics", freeze_runtime_value(metrics))

    def as_dict(self) -> dict[str, object]:
        return {
            "ok": self.ok,
            "drift_domains": list(self.drift_domains),
            "reasons": list(self.reasons),
            "metrics": materialize_runtime_value(self.metrics),
        }


def _convergence_sections(
    snapshot: Mapping[str, object],
) -> tuple[
    dict[str, object],
    dict[str, object],
    dict[str, object],
    dict[str, object],
    dict[str, object],
    dict[str, object],
    tuple[Mapping[str, object], ...],
]:
    snapshot_state, evidence = runtime_mapping(
        snapshot, field_name="governance_snapshot"
    )
    event_budgets, issues = _snapshot_mapping(snapshot_state, "event_budgets")
    evidence += issues
    governance_planes, issues = _snapshot_mapping(snapshot_state, "governance_planes")
    evidence += issues
    stabilization_policy, issues = _snapshot_mapping(snapshot_state, "stabilization_policy")
    evidence += issues
    replay_lineage_pressure, issues = _snapshot_mapping(snapshot_state, "replay_lineage_pressure")
    evidence += issues
    topology_pressure_forecast, issues = _snapshot_mapping(snapshot_state, "topology_pressure_forecast")
    evidence += issues
    convergence_latency, issues = _snapshot_mapping(snapshot_state, "convergence_latency")
    evidence += issues
    return (
        event_budgets,
        governance_planes,
        stabilization_policy,
        replay_lineage_pressure,
        topology_pressure_forecast,
        convergence_latency,
        evidence,
    )


def _replay_policy_drift(
    policy: dict[str, object],
    replay: dict[str, object],
) -> tuple[list[str], set[str], tuple[Mapping[str, object], ...]]:
    reasons: list[str] = []
    domains: set[str] = set()
    freeze_replay, freeze_issues = runtime_bool(
        dict.get(policy, "freeze_replay", False),
        field_name="governance_policy_freeze_replay",
    )
    replay_action, action_issues = runtime_text(
        dict.get(replay, "action", "normal"),
        field_name="governance_replay_action",
        default="input_rejected",
    )
    if freeze_replay and replay_action == "normal":
        reasons.append("policy_replay_freeze_without_replay_pressure")
        domains.add("replay")
    return reasons, domains, freeze_issues + action_issues


def _budget_has_pressure(
    budgets: dict[str, object],
) -> tuple[bool, tuple[Mapping[str, object], ...]]:
    pressure = False
    evidence: tuple[Mapping[str, object], ...] = ()
    for index, raw_budget in enumerate(dict.values(budgets)):
        budget, issues = runtime_mapping(
            raw_budget, field_name=_governance_index_field("governance_budget", index)
        )
        evidence += issues
        suppressed, issues = runtime_int(
            dict.get(budget, "suppressed", 0),
            field_name=_governance_index_field("governance_budget", index, "suppressed"),
        )
        evidence += issues
        if suppressed > 0:
            pressure = True
    return pressure, evidence


def _telemetry_scheduler_drift(
    budgets: dict[str, object],
    planes: dict[str, object],
    policy: dict[str, object],
    topology: dict[str, object],
) -> tuple[
    float,
    list[str],
    set[str],
    tuple[Mapping[str, object], ...],
]:
    reasons: list[str] = []
    domains: set[str] = set()
    suppress_telemetry, suppress_issues = runtime_bool(
        dict.get(policy, "suppress_telemetry", False),
        field_name="governance_policy_suppress_telemetry",
    )
    telemetry_plane, plane_issues = runtime_mapping(
        dict.get(planes, "telemetry"),
        field_name="governance_telemetry_plane",
    )
    telemetry_state, state_issues = runtime_text(
        dict.get(telemetry_plane, "state", "normal"),
        field_name="governance_telemetry_state",
        default="input_rejected",
    )
    topology_pressure, topology_issues = runtime_float(
        dict.get(topology, "pressure", 0.0),
        field_name="governance_topology_pressure",
        minimum=0.0,
        maximum=1.0,
    )
    if suppress_telemetry and telemetry_state == "normal" and topology_pressure < PLR2004N0_55:
        reasons.append("telemetry_suppression_without_plane_pressure")
        domains.add("telemetry")
    reduce_concurrency, concurrency_issues = runtime_bool(
        dict.get(policy, "reduce_concurrency", False),
        field_name="governance_policy_reduce_concurrency",
    )
    budget_pressure, budget_issues = _budget_has_pressure(budgets)
    if reduce_concurrency and not budget_pressure and topology_pressure < PLR2004N0_55:
        reasons.append("scheduler_throttle_without_budget_pressure")
        domains.add("scheduler")
    return (
        topology_pressure,
        reasons,
        domains,
        suppress_issues
        + plane_issues
        + state_issues
        + topology_issues
        + concurrency_issues
        + budget_issues,
    )


def _topology_latency_drift(
    policy: dict[str, object],
    topology: dict[str, object],
    convergence_latency: dict[str, object],
) -> tuple[list[str], set[str], tuple[Mapping[str, object], ...]]:
    reasons: list[str] = []
    domains: set[str] = set()
    topology_action, topology_issues = runtime_text(
        dict.get(topology, "action", "normal"),
        field_name="governance_topology_action",
        default="input_rejected",
    )
    policy_action, policy_issues = runtime_text(
        dict.get(policy, "action", "normal"),
        field_name="governance_policy_action",
        default="input_rejected",
    )
    if topology_action != "normal" and policy_action == "normal":
        reasons.append("topology_forecast_not_reflected_in_policy")
        domains.add("event_topology")
    latency_violated, latency_issues = runtime_bool(
        dict.get(convergence_latency, "violated", False),
        field_name="governance_convergence_latency_violated",
    )
    drift_issues: tuple[Mapping[str, object], ...] = ()
    if latency_violated:
        reasons.append("governance_convergence_latency_exceeded")
        drift_domains, drift_issues = _normalized_text_sequence(
            dict.get(convergence_latency, "drift_domains", ("governance",)),
            field_name="governance_latency_drift_domains",
        )
        domains.update(drift_domains or ("governance",))
    return (
        reasons,
        domains,
        topology_issues + policy_issues + latency_issues + drift_issues,
    )


def verify_governance_convergence(
    snapshot: Mapping[str, object],
) -> GovernanceConvergenceReport:
    (
        budgets,
        planes,
        policy,
        replay,
        topology,
        convergence_latency,
        input_evidence,
    ) = _convergence_sections(snapshot)
    reasons: list[str] = []
    domains: set[str] = set()
    replay_reasons, replay_domains, replay_issues = _replay_policy_drift(
        policy, replay
    )
    reasons.extend(replay_reasons)
    domains.update(replay_domains)
    input_evidence += replay_issues
    topology_pressure, pressure_reasons, pressure_domains, pressure_issues = (
        _telemetry_scheduler_drift(budgets, planes, policy, topology)
    )
    reasons.extend(pressure_reasons)
    domains.update(pressure_domains)
    input_evidence += pressure_issues
    topology_reasons, topology_domains, topology_issues = (
        _topology_latency_drift(policy, topology, convergence_latency)
    )
    reasons.extend(topology_reasons)
    domains.update(topology_domains)
    input_evidence += topology_issues
    replay_pressure, issues = runtime_float(
        dict.get(replay, "pressure", 0.0),
        field_name="governance_replay_pressure",
        minimum=0.0,
        maximum=1.0,
    )
    input_evidence += issues
    if input_evidence:
        reasons.append("runtime_input_rejected")
        domains.add("governance")
    return GovernanceConvergenceReport(
        ok=not reasons,
        drift_domains=tuple(sorted(domains)),
        reasons=tuple(reasons),
        metrics={
            "budget_count": len(budgets),
            "topology_pressure": topology_pressure,
            "replay_pressure": replay_pressure,
            "convergence_latency": convergence_latency,
            "input_evidence": input_evidence,
        },
    )


@dataclass(frozen=True)
class RollbackPlan:
    required: bool
    reason: str = "stable"
    checkpoint_sequence: int = 0
    actions: tuple[str, ...] = field(default_factory=tuple)
    input_evidence: tuple[Mapping[str, object], ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        if type(self) is not RollbackPlan:
            exception_message = "rollback plan owner rejected"
            raise TypeError(exception_message)
        required, required_issues = runtime_bool(
            self.required, field_name="rollback_required", default=True
        )
        reason, reason_issues = runtime_text(
            self.reason,
            field_name="rollback_reason",
            default="runtime_input_rejected",
        )
        sequence, sequence_issues = runtime_int(
            self.checkpoint_sequence,
            field_name="rollback_checkpoint_sequence",
            default=0,
        )
        actions, action_issues = _normalized_text_sequence(
            self.actions, field_name="rollback_actions"
        )
        evidence_rows, evidence_issues = runtime_sequence(
            self.input_evidence, field_name="rollback_input_evidence"
        )
        evidence = (
            required_issues
            + reason_issues
            + sequence_issues
            + action_issues
            + evidence_issues
            + tuple(evidence_rows)
        )
        if evidence:
            required = True
            reason = "runtime_input_rejected"
        object.__setattr__(self, "required", required)
        object.__setattr__(self, "reason", reason)
        object.__setattr__(self, "checkpoint_sequence", sequence)
        object.__setattr__(self, "actions", actions)
        object.__setattr__(
            self, "input_evidence", tuple(freeze_runtime_value(evidence))
        )

    def as_dict(self) -> dict[str, object]:
        return {
            "required": self.required,
            "reason": self.reason,
            "checkpoint_sequence": self.checkpoint_sequence,
            "actions": list(self.actions),
            "input_evidence": materialize_runtime_value(self.input_evidence),
        }


def plan_adaptive_rollback(
    snapshot: Mapping[str, object],
    checkpoint: Mapping[str, object] | None = None,
) -> RollbackPlan:
    snapshot_state, input_evidence = runtime_mapping(
        snapshot, field_name="rollback_snapshot"
    )
    policy, issues = _snapshot_mapping(
        snapshot_state, "stabilization_policy"
    )
    input_evidence += issues
    invariants, issues = _snapshot_mapping(snapshot_state, "event_invariants")
    input_evidence += issues
    convergence = verify_governance_convergence(snapshot).as_dict()
    rollback_requested, issues = runtime_bool(
        dict.get(policy, "rollback_stabilization", False),
        field_name="rollback_policy_requested",
    )
    input_evidence += issues
    convergence_ok, issues = runtime_bool(
        dict.get(convergence, "ok", False),
        field_name="rollback_convergence_ok",
        default=False,
    )
    input_evidence += issues
    invariants_ok, issues = runtime_bool(
        dict.get(invariants, "ok", True),
        field_name="rollback_invariants_ok",
        default=False,
    )
    input_evidence += issues
    required = (
        rollback_requested
        or not convergence_ok
        or not invariants_ok
        or len(input_evidence) > 0
    )
    if not required:
        return RollbackPlan(required=False)
    actions = [
        "restore_event_checkpoint",
        "clear_transient_suppression",
        "recompute_governance_snapshot",
    ]
    freeze_replay, issues = runtime_bool(
        dict.get(policy, "freeze_replay", False),
        field_name="rollback_freeze_replay",
    )
    input_evidence += issues
    if freeze_replay:
        actions.append("keep_replay_frozen_until_convergence")
    raw_reason = dict.get(policy, "reason")
    if raw_reason is None:
        reason = ""
        issues = ()
    else:
        reason, issues = runtime_text(
            raw_reason,
            field_name="rollback_policy_reason",
            default="",
        )
        input_evidence += issues
    if reason == "":
        convergence_reasons, reason_issues = _normalized_text_sequence(
            dict.get(convergence, "reasons"),
            field_name="rollback_convergence_reasons",
        )
        input_evidence += reason_issues
        reason = "+".join(convergence_reasons) or "invariant_failure"
    checkpoint_state, issues = runtime_mapping(
        checkpoint, field_name="rollback_checkpoint"
    )
    input_evidence += issues
    checkpoint_sequence, issues = runtime_int(
        dict.get(checkpoint_state, "sequence", 0),
        field_name="rollback_checkpoint_sequence",
        default=0,
    )
    input_evidence += issues
    return RollbackPlan(
        required=True,
        reason=reason,
        checkpoint_sequence=checkpoint_sequence,
        actions=tuple(actions),
        input_evidence=input_evidence,
    )


__all__ = (
    "GovernanceConvergenceReport",
    "RollbackPlan",
    "plan_adaptive_rollback",
    "verify_governance_convergence",
)
