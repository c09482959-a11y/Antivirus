"""System-level governance invariants and circuit breakers.

This module keeps Stage 25 runtime controls deterministic and observable.  It is
not scanner repair glue: it defines the common rules that replay, telemetry, queues,
and resource economics use to prevent emergent feedback loops.
"""
from __future__ import annotations

from dataclasses import dataclass, field, replace
from typing import Iterable, Mapping
import hashlib
import json
import time
from Virus_Scan.contracts.no_hook_materialization import materialize_json_no_hook, no_hook_exact_owner_field
from Virus_Scan.runtime.governance_inputs import (
    runtime_bool,
    runtime_float,
    runtime_int,
    runtime_sequence,
    runtime_text,
)


def _governance_text(value: object, default: str) -> str:
    if type(value) is str:
        return str.__str__(value)
    return default


def _governance_indexed_field(prefix: str, index: int) -> str:
    index_text = int.__str__(index) if type(index) is int else "0"
    return str.__str__(prefix) + "_" + index_text


def _governance_field(prefix: str, field_name: object) -> str:
    return str.__str__(prefix) + "_" + _governance_text(field_name, "field")


def _governance_metric_text(value: object) -> str:
    if type(value) is int and type(value) is not bool:
        return int.__str__(value)
    if type(value) is float:
        return float.__str__(value)
    return "0"


def _governance_budget_violation(name: str, actual: object, limit: object) -> str:
    return (
        str.__str__(name)
        + ":"
        + _governance_metric_text(actual)
        + ">"
        + _governance_metric_text(limit)
    )


def _append_governance_evidence(
    evidence: tuple[Mapping[str, object], ...],
    issues: tuple[Mapping[str, object], ...],
) -> tuple[Mapping[str, object], ...]:
    if issues == ():
        return evidence
    return evidence + issues


@dataclass(frozen=True)
class GovernanceLimits:
    max_replay_depth: int = 16
    max_lineage_fanout: int = 128
    max_descendants_per_root: int = 5000
    max_telemetry_events_per_workload: int = 256
    max_replay_nodes_per_workload: int = 8192
    max_scheduler_debt: float = 25000.0


@dataclass(frozen=True)
class CircuitBreakerState:
    replay_frozen: bool = False
    telemetry_throttled: bool = False
    workload_isolated: bool = False
    concurrency_reduced: bool = False
    reasons: tuple[str, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        if type(self) is not CircuitBreakerState:
            exception_message = "circuit breaker state owner rejected"
            raise TypeError(exception_message)
        rows, evidence = runtime_sequence(
            self.reasons, field_name="circuit_breaker_reasons"
        )
        reasons: list[str] = []
        for index, row in enumerate(rows):
            reason, issues = runtime_text(
                row,
                field_name=_governance_indexed_field("circuit_breaker_reason", index),
                default="runtime_input_rejected",
            )
            evidence = _append_governance_evidence(evidence, issues)
            reasons.append(reason)
        if evidence:
            reasons.append("runtime_input_rejected")
        object.__setattr__(self, "reasons", tuple(dict.fromkeys(reasons)))
        for field_name in (
            "replay_frozen",
            "telemetry_throttled",
            "workload_isolated",
            "concurrency_reduced",
        ):
            value, issues = runtime_bool(
                no_hook_exact_owner_field(self, type(self), field_name),
                field_name=_governance_field("circuit_breaker", field_name),
                default=True,
            )
            object.__setattr__(self, field_name, value or issues != ())

    def trip(self, reason: str, *, replay: bool = False, telemetry: bool = False,
             isolate: bool = False, reduce_concurrency: bool = False) -> "CircuitBreakerState":
        r, issues = runtime_text(
            reason,
            field_name="circuit_breaker_trip_reason",
            default="runtime_input_rejected",
        )
        replay_value, replay_issues = runtime_bool(
            replay, field_name="circuit_breaker_trip_replay", default=True
        )
        telemetry_value, telemetry_issues = runtime_bool(
            telemetry,
            field_name="circuit_breaker_trip_telemetry",
            default=True,
        )
        isolate_value, isolate_issues = runtime_bool(
            isolate, field_name="circuit_breaker_trip_isolate", default=True
        )
        concurrency_value, concurrency_issues = runtime_bool(
            reduce_concurrency,
            field_name="circuit_breaker_trip_reduce_concurrency",
            default=True,
        )
        if issues or replay_issues or telemetry_issues or isolate_issues or concurrency_issues:
            r = "runtime_input_rejected"
        reasons = self.reasons if r in self.reasons else (*self.reasons, r)
        return replace(
            self,
            replay_frozen=self.replay_frozen or replay_value,
            telemetry_throttled=self.telemetry_throttled or telemetry_value,
            workload_isolated=self.workload_isolated or isolate_value,
            concurrency_reduced=self.concurrency_reduced or concurrency_value,
            reasons=reasons,
        )


@dataclass(frozen=True)
class RuntimeInvariantReport:
    ok: bool
    violations: tuple[str, ...] = field(default_factory=tuple)
    circuit_breaker: CircuitBreakerState = field(default_factory=CircuitBreakerState)
    checked_at: float = field(default_factory=time.time)

    def __post_init__(self) -> None:
        if type(self) is not RuntimeInvariantReport:
            exception_message = "runtime invariant report owner rejected"
            raise TypeError(exception_message)
        rows, evidence = runtime_sequence(
            self.violations, field_name="runtime_invariant_violations"
        )
        violations: list[str] = []
        for index, row in enumerate(rows):
            violation, issues = runtime_text(
                row,
                field_name=_governance_indexed_field("runtime_invariant_violation", index),
                default="runtime_input_rejected",
            )
            evidence = _append_governance_evidence(evidence, issues)
            violations.append(violation)
        ok, issues = runtime_bool(
            self.ok, field_name="runtime_invariant_ok", default=False
        )
        evidence = _append_governance_evidence(evidence, issues)
        checked_at, issues = runtime_float(
            self.checked_at,
            field_name="runtime_invariant_checked_at",
            default=0.0,
            minimum=0.0,
        )
        evidence = _append_governance_evidence(evidence, issues)
        if evidence:
            ok = False
            violations.append("runtime_input_rejected")
        object.__setattr__(self, "ok", ok)
        object.__setattr__(self, "violations", tuple(dict.fromkeys(violations)))
        object.__setattr__(self, "checked_at", checked_at)

    def as_dict(self) -> dict[str, object]:
        return {
            "ok": self.ok,
            "violations": list(self.violations),
            "circuit_breaker": {
                "replay_frozen": self.circuit_breaker.replay_frozen,
                "telemetry_throttled": self.circuit_breaker.telemetry_throttled,
                "workload_isolated": self.circuit_breaker.workload_isolated,
                "concurrency_reduced": self.circuit_breaker.concurrency_reduced,
                "reasons": list(self.circuit_breaker.reasons),
            },
            "checked_at": self.checked_at,
        }


def stable_digest(value: object) -> str:
    payload = json.dumps(
        materialize_json_no_hook(value, context="governance_digest"),
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )
    return hashlib.sha256(payload.encode("utf-8", errors="replace")).hexdigest()


def assert_acyclic_edges(edges: Iterable[tuple[str, str]]) -> list[str]:
    """Return cycle violations for parent->child lineage edges."""
    graph: dict[str, list[str]] = {}
    rows, input_evidence = runtime_sequence(
        edges, field_name="governance_lineage_edges"
    )
    for index, row in enumerate(rows):
        edge_field = _governance_indexed_field("governance_lineage_edge", index)
        edge, issues = runtime_sequence(
            row, field_name=edge_field
        )
        input_evidence = _append_governance_evidence(input_evidence, issues)
        if len(edge) != 2:
            input_evidence += (
                {
                    "runtime_input_rejected": True,
                    "field_name": edge_field,
                    "reason": "lineage_edge_pair_rejected",
                },
            )
            continue
        p, issues = runtime_text(
            edge[0],
            field_name=_governance_indexed_field("governance_lineage_parent", index),
            default="input_rejected",
        )
        input_evidence = _append_governance_evidence(input_evidence, issues)
        c, issues = runtime_text(
            edge[1],
            field_name=_governance_indexed_field("governance_lineage_child", index),
            default="input_rejected",
        )
        input_evidence = _append_governance_evidence(input_evidence, issues)
        if p and c:
            graph.setdefault(p, []).append(c)
    violations: list[str] = (
        ["runtime_input_rejected:lineage_edges"] if input_evidence else []
    )
    temp: set[str] = set()
    perm: set[str] = set()

    def visit(n: str, stack: list[str]) -> None:
        if n in perm:
            return
        if n in temp:
            violations.append("lineage_cycle:" + "->".join([*stack, n]))
            return
        temp.add(n)
        for nxt in sorted(graph.get(n, [])):
            visit(nxt, [*stack, n])
        temp.discard(n)
        perm.add(n)

    for node in sorted(graph):
        visit(node, [])
    return violations


def evaluate_runtime_invariants(*, replay_nodes: int = 0, replay_depth: int = 0,
                                lineage_fanout: int = 0, descendants: int = 0,
                                telemetry_events: int = 0, scheduler_debt: float = 0.0,
                                limits: GovernanceLimits | None = None) -> RuntimeInvariantReport:
    limit_input_rejected = limits is not None and type(limits) is not GovernanceLimits
    limits = limits if type(limits) is GovernanceLimits else GovernanceLimits()
    violations: list[str] = []
    cb = CircuitBreakerState()
    evidence: tuple[Mapping[str, object], ...] = (
        (
            {
                "runtime_input_rejected": True,
                "field_name": "governance_limits",
                "reason": "governance_limits_rejected",
            },
        )
        if limit_input_rejected
        else ()
    )
    metrics: dict[str, float | int] = {}
    for field_name, value in (
        ("replay_nodes", replay_nodes),
        ("replay_depth", replay_depth),
        ("lineage_fanout", lineage_fanout),
        ("descendants", descendants),
        ("telemetry_events", telemetry_events),
    ):
        parsed, issues = runtime_int(
            value, field_name=_governance_field("runtime_invariant", field_name), default=0
        )
        evidence = _append_governance_evidence(evidence, issues)
        metrics[field_name] = parsed
    scheduler_metric, issues = runtime_float(
        scheduler_debt,
        field_name="runtime_invariant_scheduler_debt",
        default=0.0,
        minimum=0.0,
    )
    evidence = _append_governance_evidence(evidence, issues)
    metrics["scheduler_debt"] = scheduler_metric
    limit_values: dict[str, float | int] = {}
    for field_name in (
        "max_replay_depth",
        "max_lineage_fanout",
        "max_descendants_per_root",
        "max_telemetry_events_per_workload",
        "max_replay_nodes_per_workload",
    ):
        parsed, issues = runtime_int(
            no_hook_exact_owner_field(limits, GovernanceLimits, field_name),
            field_name=_governance_field("governance_limit", field_name),
            default=0,
        )
        evidence = _append_governance_evidence(evidence, issues)
        limit_values[field_name] = parsed
    debt_limit, issues = runtime_float(
        no_hook_exact_owner_field(limits, GovernanceLimits, "max_scheduler_debt"),
        field_name="governance_limit_max_scheduler_debt",
        default=0.0,
        minimum=0.0,
    )
    evidence = _append_governance_evidence(evidence, issues)
    limit_values["max_scheduler_debt"] = debt_limit
    if evidence:
        violations.append("runtime_input_rejected")
        cb = cb.trip(
            "runtime_input_rejected",
            replay=True,
            telemetry=True,
            isolate=True,
            reduce_concurrency=True,
        )
    if metrics["replay_depth"] > limit_values["max_replay_depth"]:
        violations.append(_governance_budget_violation("replay_depth_exceeded", metrics["replay_depth"], limit_values["max_replay_depth"]))
        cb = cb.trip("replay_depth_exceeded", replay=True, isolate=True)
    if metrics["lineage_fanout"] > limit_values["max_lineage_fanout"]:
        violations.append(_governance_budget_violation("lineage_fanout_exceeded", metrics["lineage_fanout"], limit_values["max_lineage_fanout"]))
        cb = cb.trip("lineage_fanout_exceeded", replay=True, isolate=True)
    if metrics["descendants"] > limit_values["max_descendants_per_root"]:
        violations.append(_governance_budget_violation("descendant_budget_exceeded", metrics["descendants"], limit_values["max_descendants_per_root"]))
        cb = cb.trip("descendant_budget_exceeded", isolate=True, reduce_concurrency=True)
    if metrics["telemetry_events"] > limit_values["max_telemetry_events_per_workload"]:
        violations.append(_governance_budget_violation("telemetry_budget_exceeded", metrics["telemetry_events"], limit_values["max_telemetry_events_per_workload"]))
        cb = cb.trip("telemetry_budget_exceeded", telemetry=True)
    if metrics["replay_nodes"] > limit_values["max_replay_nodes_per_workload"]:
        violations.append(_governance_budget_violation("replay_node_budget_exceeded", metrics["replay_nodes"], limit_values["max_replay_nodes_per_workload"]))
        cb = cb.trip("replay_node_budget_exceeded", replay=True, isolate=True)
    if metrics["scheduler_debt"] > limit_values["max_scheduler_debt"]:
        violations.append(_governance_budget_violation("scheduler_debt_exceeded", metrics["scheduler_debt"], limit_values["max_scheduler_debt"]))
        cb = cb.trip("scheduler_debt_exceeded", reduce_concurrency=True)
    return RuntimeInvariantReport(ok=not violations, violations=tuple(violations), circuit_breaker=cb)


__all__ = (
    "CircuitBreakerState",
    "GovernanceLimits",
    "RuntimeInvariantReport",
    "assert_acyclic_edges",
    "evaluate_runtime_invariants",
    "stable_digest",
)
