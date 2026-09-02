"""Proactive event-topology anomaly prevention."""
from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Iterable, Mapping

from Virus_Scan.runtime.governance_inputs import (
    runtime_bool,
    runtime_float,
    runtime_int,
    runtime_object_state,
    runtime_sequence,
    runtime_text,
)
from Virus_Scan.runtime.immutable_core import freeze_runtime_value, materialize_runtime_value


def _topology_indexed_name(prefix: str, index: int) -> str:
    if type(index) is int and type(index) is not bool:
        return prefix + "_" + int.__str__(index)
    return prefix + "_index"


@dataclass(frozen=True)
class TopologyStabilizationReport:
    ok: bool
    pressure: float
    anomalies: tuple[str, ...] = field(default_factory=tuple)
    actions: tuple[str, ...] = field(default_factory=tuple)
    metrics: Mapping[str, object] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if type(self) is not TopologyStabilizationReport:
            exception_message = "topology stabilization report owner rejected"
            raise TypeError(exception_message)
        ok, ok_issues = runtime_bool(
            self.ok, field_name="topology_ok", default=False
        )
        anomalies, anomaly_issues = runtime_sequence(
            self.anomalies, field_name="topology_anomalies"
        )
        actions, action_issues = runtime_sequence(
            self.actions, field_name="topology_actions"
        )
        anomaly_text = tuple(
            runtime_text(item, field_name="topology_anomaly", default="input_rejected")[0]
            for item in anomalies
        )
        action_text = tuple(
            runtime_text(item, field_name="topology_action", default="input_rejected")[0]
            for item in actions
        )
        pressure, pressure_issues = runtime_float(
            self.pressure,
            field_name="topology_pressure",
            minimum=0.0,
            maximum=1.0,
        )
        metrics = freeze_runtime_value({} if self.metrics is None else self.metrics)
        if ok_issues or anomaly_issues or action_issues or pressure_issues:
            metrics = freeze_runtime_value(
                {
                    "metrics": metrics,
                    "input_evidence": (
                        ok_issues
                        + anomaly_issues
                        + action_issues
                        + pressure_issues
                    ),
                }
            )
            ok = False
        object.__setattr__(self, "ok", ok)
        object.__setattr__(self, "anomalies", anomaly_text)
        object.__setattr__(self, "actions", action_text)
        object.__setattr__(self, "pressure", pressure)
        object.__setattr__(self, "metrics", metrics)

    def as_dict(self) -> dict[str, object]:
        return {
            "ok": self.ok,
            "pressure": round(self.pressure, 4),
            "anomalies": list(self.anomalies),
            "actions": list(self.actions),
            "metrics": materialize_runtime_value(self.metrics),
        }


def _topology_limits(
    fanout_limit: object,
    depth_limit: object,
    burst_limit: object,
) -> tuple[int, int, int, tuple[Mapping[str, object], ...]]:
    fanout, fanout_issues = runtime_int(
        fanout_limit, field_name="topology_fanout_limit", default=128
    )
    depth, depth_issues = runtime_int(
        depth_limit, field_name="topology_depth_limit", default=48
    )
    burst, burst_issues = runtime_int(
        burst_limit, field_name="topology_burst_limit", default=512
    )
    return fanout, depth, burst, fanout_issues + depth_issues + burst_issues


def _topology_event_metrics(
    event_items: tuple[object, ...],
) -> tuple[
    dict[int, int],
    Counter[str],
    Counter[str],
    int,
    int,
    tuple[Mapping[str, object], ...],
]:
    children: dict[int, int] = defaultdict(int)
    domains: Counter[str] = Counter()
    kinds: Counter[str] = Counter()
    max_depth = 0
    suppressed = 0
    row_issues: tuple[Mapping[str, object], ...] = ()
    for index, event in enumerate(event_items):
        state, issues = runtime_object_state(
            event, field_name=_topology_indexed_name("topology_event", index)
        )
        row_issues += issues
        if issues:
            continue
        parent = dict.get(state, "parent_seq")
        if parent is not None:
            parent_id, issues = runtime_int(
                parent, field_name="topology_parent_seq"
            )
            row_issues += issues
            if not issues:
                children[parent_id] += 1
        domain, issues = runtime_text(
            dict.get(state, "domain", "runtime"),
            field_name="topology_domain",
            default="runtime",
        )
        row_issues += issues
        kind, issues = runtime_text(
            dict.get(state, "kind", "event"),
            field_name="topology_kind",
            default="event",
        )
        row_issues += issues
        event_depth, issues = runtime_int(
            dict.get(state, "causal_depth", 0),
            field_name="topology_causal_depth",
        )
        row_issues += issues
        event_suppressed, issues = runtime_int(
            dict.get(state, "suppressed_count", 0),
            field_name="topology_suppressed_count",
        )
        row_issues += issues
        domains[domain] += 1
        kinds[domain + ":" + kind] += 1
        max_depth = max(max_depth, event_depth)
        suppressed += event_suppressed
    return children, domains, kinds, max_depth, suppressed, row_issues


def _topology_actions(
    *,
    event_count: int,
    max_fanout: int,
    max_depth: int,
    suppressed: int,
    hot_kind: tuple[str, int],
    fanout_limit: int,
    depth_limit: int,
    burst_limit: int,
    has_input_issues: bool,
) -> tuple[list[str], list[str], float]:
    anomalies: list[str] = []
    actions: list[str] = []
    pressure = 0.0
    if has_input_issues:
        anomalies.append("topology_input_rejected")
        actions.append("preserve_topology_input_evidence")
        pressure += 0.25
    if max_fanout > fanout_limit:
        anomalies.append("fanout:" + int.__str__(max_fanout) + ">" + int.__str__(fanout_limit))
        actions.append("isolate_fanout_parent")
        pressure += 0.35
    if max_depth > depth_limit:
        anomalies.append("depth:" + int.__str__(max_depth) + ">" + int.__str__(depth_limit))
        actions.append("freeze_deep_replay")
        pressure += 0.25
    if hot_kind[1] > burst_limit:
        anomalies.append("burst:" + hot_kind[0] + "=" + int.__str__(hot_kind[1]) + ">" + int.__str__(burst_limit))
        actions.append("suppress_event_burst")
        pressure += 0.25
    if suppressed > max(1024, event_count * 2):
        anomalies.append("suppression:" + int.__str__(suppressed))
        actions.append("preserve_suppression_trace")
        pressure += 0.15
    return anomalies, actions, pressure


def analyze_topology_pressure(
    events: Iterable[object],
    *,
    fanout_limit: int = 128,
    depth_limit: int = 48,
    burst_limit: int = 512,
) -> TopologyStabilizationReport:
    event_items, event_issues = runtime_sequence(events, field_name="topology_events")
    fanout, depth, burst, limit_issues = _topology_limits(
        fanout_limit, depth_limit, burst_limit
    )
    input_evidence = event_issues + limit_issues
    children, domains, kinds, max_depth, suppressed, row_issues = (
        _topology_event_metrics(event_items)
    )
    child_counts = tuple(dict.values(children))
    max_fanout = max(child_counts) if child_counts else 0
    hot_kind = kinds.most_common(1)[0] if kinds else ("", 0)
    anomalies, actions, pressure = _topology_actions(
        event_count=len(event_items),
        max_fanout=max_fanout,
        max_depth=max_depth,
        suppressed=suppressed,
        hot_kind=hot_kind,
        fanout_limit=fanout,
        depth_limit=depth,
        burst_limit=burst,
        has_input_issues=len(input_evidence + row_issues) > 0,
    )
    return TopologyStabilizationReport(
        ok=not anomalies,
        pressure=min(1.0, pressure),
        anomalies=tuple(anomalies),
        actions=tuple(sorted(set(actions))),
        metrics={
            "event_count": len(event_items),
            "max_fanout": max_fanout,
            "max_depth": max_depth,
            "suppressed": suppressed,
            "top_domains": domains.most_common(8),
            "top_kinds": kinds.most_common(8),
            "input_evidence": input_evidence + row_issues,
        },
    )


__all__ = ("TopologyStabilizationReport", "analyze_topology_pressure")
