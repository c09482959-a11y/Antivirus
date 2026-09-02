"""Causal event stream query/projection support owners.

These helpers keep EventBus focused on mutation/append authority while preserving
owned no-hook materialization, deterministic replay, and topology projection
semantics for read-only runtime views.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any

from .causal_event_stream_support import (
    _causal_budget_suppressed_values,
    _causal_counter_items,
    _causal_counter_values,
    _causal_dependency_edge,
    _causal_domain_edge,
    _causal_event_cost,
    _causal_event_node,
    _causal_event_row_without_timestamp,
    _causal_event_type_key,
    _causal_int,
    _causal_max_counter_value,
    _causal_payload_key_names,
    _causal_positive_counter_keys,
    _causal_sorted_counter,
)
from .causal_text import causal_text
from .governance_inputs import runtime_int

_DEFAULT_WORKLOAD_MAX_DEPTH = 64


def compressed_replay_for_bus(bus: Any, *, max_payload_keys: int = 8) -> tuple[dict[str, object], ...]:
    """Return deterministic compressed replay lineage records for an EventBus."""
    payload_key_limit, issues = runtime_int(
        max_payload_keys,
        field_name="compressed_replay_max_payload_keys",
        default=8,
    )
    if issues:
        raise ValueError("compressed replay payload-key limit rejected")
    with bus._lock:
        out: list[dict[str, object]] = []
        for ev in bus.snapshot():
            keys = sorted(
                causal_text(k, empty="causal_text_empty")
                for k in _causal_payload_key_names(ev.payload)
            )[:payload_key_limit]
            out.append({
                "seq": ev.seq,
                "parent_seq": ev.parent_seq,
                "lineage_id": ev.lineage_id,
                "domain": ev.domain,
                "kind": ev.kind,
                "generation": ev.generation,
                "schema_version": ev.schema_version,
                "workload_id": ev.workload_id,
                "cost": round(ev.cost, 4),
                "suppressed_count": ev.suppressed_count,
                "causal_depth": ev.causal_depth,
                "causal_digest": ev.causal_digest,
                "payload_keys": keys,
            })
        return tuple(out)


def compressed_causal_trace_for_bus(
    bus: Any, *, max_events: int = 512, checkpoint_stride: int = 64
) -> dict[str, object]:
    """Return a saturation-safe causal trace summary for an EventBus."""
    limit, limit_issues = runtime_int(
        max_events,
        field_name="compressed_causal_trace_max_events",
        default=512,
    )
    stride, stride_issues = runtime_int(
        checkpoint_stride,
        field_name="compressed_causal_trace_checkpoint_stride",
        default=64,
    )
    if limit_issues or stride_issues:
        raise ValueError("compressed causal trace limit rejected")
    with bus._lock:
        limit = max(1, limit)
        stride = max(1, stride)
        events = bus.snapshot()[-limit:]
        lineage: dict[str, dict[str, object]] = {}
        domain_edges: dict[str, int] = {}
        propagation_deltas: list[dict[str, object]] = []
        checkpoints: list[dict[str, object]] = []
        by_seq = dict(bus._by_seq)
        prev_domain = None
        for index, ev in enumerate(events, 1):
            rec = lineage.setdefault(
                ev.lineage_id,
                {
                    "events": 0,
                    "domains": set(),
                    "max_depth": 0,
                    "first_seq": ev.seq,
                    "last_seq": ev.seq,
                    "suppressed": 0,
                },
            )
            rec["events"] += 1
            rec["domains"].add(ev.domain)
            rec["max_depth"] = max(_causal_int(rec["max_depth"], 0), _causal_int(ev.causal_depth, 0))
            rec["first_seq"] = min(int(rec["first_seq"]), ev.seq)
            rec["last_seq"] = max(int(rec["last_seq"]), ev.seq)
            rec["suppressed"] += _causal_int(ev.suppressed_count, 0)
            if ev.parent_seq is not None and ev.parent_seq in by_seq:
                parent = by_seq[ev.parent_seq]
                edge = _causal_domain_edge(parent, ev)
                domain_edges[edge] = domain_edges.get(edge, 0) + 1
            if prev_domain is not None and prev_domain != ev.domain:
                propagation_deltas.append({
                    "seq": ev.seq,
                    "from": prev_domain,
                    "to": ev.domain,
                    "lineage_id": ev.lineage_id,
                    "depth": ev.causal_depth,
                })
            prev_domain = ev.domain
            if index == 1 or index % stride == 0 or index == len(events):
                checkpoints.append({
                    "seq": ev.seq,
                    "lineage_id": ev.lineage_id,
                    "causal_digest": ev.causal_digest,
                    "event_count": index,
                    "edge_count": sum(_causal_counter_values(domain_edges)),
                    "lineage_count": len(lineage),
                })
        lineage_summary = []
        for lid, rec in sorted(dict.items(lineage), key=lambda kv: (-_causal_int(kv[1]["events"], 0), kv[0]))[:64]:
            lineage_summary.append({
                "lineage_id": lid,
                "events": int(rec["events"]),
                "domains": sorted(rec["domains"]),
                "max_depth": int(rec["max_depth"]),
                "first_seq": int(rec["first_seq"]),
                "last_seq": int(rec["last_seq"]),
                "suppressed": int(rec["suppressed"]),
            })
        raw_nodes = len(events)
        raw_edges = sum(1 for ev in events if ev.parent_seq is not None and ev.parent_seq in by_seq)
        compressed_units = len(lineage_summary) + len(domain_edges) + len(checkpoints) + min(128, len(propagation_deltas))
        compression_ratio = max(0.0, round(1.0 - (compressed_units / max(1.0, float(raw_nodes + raw_edges))), 4)) if (raw_nodes + raw_edges) else 0.0
        return {
            "event_count": raw_nodes,
            "raw_edge_count": raw_edges,
            "lineage_aggregation": tuple(lineage_summary),
            "topology_deltas": dict(sorted(_causal_counter_items(domain_edges), key=lambda kv: (-kv[1], kv[0]))[:64]),
            "propagation_delta_reconstruction": tuple(propagation_deltas[-128:]),
            "replay_checkpoint_summarization": tuple(checkpoints),
            "causal_reconstruction_snapshots": tuple(checkpoints[-8:]),
            "compression_ratio": compression_ratio,
            "digest": hashlib.sha256(
                json.dumps(
                    (lineage_summary, sorted(_causal_counter_items(domain_edges)), checkpoints),
                    sort_keys=True,
                    separators=(",", ":"),
                    allow_nan=False,
                ).encode("utf-8", "replace")
            ).hexdigest(),
        }


def telemetry_resource_budget_for_bus(bus: Any) -> dict[str, object]:
    """Budget observability so tracing cannot destabilize runtime orchestration."""
    with bus._lock:
        events = bus.snapshot()
        total = max(1, len(events))
        telemetry_events = [ev for ev in events if ev.domain == "telemetry"]
        governance_events = [ev for ev in events if ev.domain == "governance"]
        trace_density = len(telemetry_events) / total
        reconstruction_overhead = min(
            1.0,
            (len(events) + sum(1 for ev in events if ev.parent_seq is not None))
            / max(1.0, float(bus._max_events)),
        )
        replay_trace_cost = sum(_causal_event_cost(ev.cost) for ev in events if ev.domain in {"replay", "telemetry"})
        topology_visualization_pressure = min(
            1.0,
            (len(bus._children) + sum(_causal_counter_values(bus._children)))
            / max(1.0, float(bus._max_events)),
        )
        governance_snapshot_generation_expense = min(
            1.0,
            (len(governance_events) + len(bus._budgets) + len(bus._lineage_counts)) / 2048.0,
        )
        observability_amplification = min(
            1.0,
            trace_density
            + reconstruction_overhead * 0.35
            + topology_visualization_pressure * 0.25
            + governance_snapshot_generation_expense * 0.25,
        )
        preserve = [
            "contract_violation",
            "event_loop_detected",
            "lineage_hard_ceiling",
            "lineage_descendant_hard_ceiling",
            "telemetry_isolation_domain",
        ]
        throttle = (
            observability_amplification >= 0.55
            or trace_density >= 0.25
            or governance_snapshot_generation_expense >= 0.50
        )
        return {
            "observability_amplification": round(observability_amplification, 4),
            "trace_density": round(trace_density, 4),
            "reconstruction_overhead": round(reconstruction_overhead, 4),
            "replay_trace_cost": round(replay_trace_cost, 4),
            "topology_visualization_pressure": round(topology_visualization_pressure, 4),
            "governance_snapshot_generation_expense": round(governance_snapshot_generation_expense, 4),
            "dynamic_throttle_noncritical_tracing": bool(throttle),
            "preserve_integrity_critical_telemetry": True,
            "action": "throttle_noncritical_tracing" if throttle else "normal",
            "integrity_reasons_preserved": preserve,
        }


def replay_lineage_pressure_for_bus(bus: Any) -> dict[str, object]:
    """Forecast replay-lineage pressure before saturation collapses topology."""
    with bus._lock:
        lineages = dict(bus._lineage_counts)
        event_count = len(bus._events)
        unique = max(1, len(lineages))
        max_lineage = _causal_max_counter_value(lineages)
        avg = event_count / unique
        deep = sum(1 for ev in bus._events if ev.causal_depth > 16)
        fanout = _causal_max_counter_value(bus._children)
        pressure = min(
            1.0,
            (max_lineage / max(1, bus._max_events_per_workload))
            + (deep / max(1, event_count))
            + (fanout / max(1, bus._max_fanout_per_parent)),
        )
        return {
            "event_count": event_count,
            "lineage_count": len(lineages),
            "max_lineage_events": max_lineage,
            "avg_events_per_lineage": round(avg, 4),
            "deep_events": deep,
            "max_parent_fanout": fanout,
            "pressure": round(pressure, 4),
            "pruned_events": sum(_causal_counter_values(bus._lineage_pruned)),
            "hard_lineage_ceiling": bus._max_lineage_events,
            "hard_lineage_domain_ceiling": bus._max_lineages,
            "hard_descendant_ceiling": bus._max_descendants_per_lineage,
            "action": "throttle_replay" if pressure >= 0.85 else ("compress_lineage" if pressure >= 0.55 else "normal"),
        }


def deterministic_checkpoint_for_bus(bus: Any) -> dict[str, object]:
    """Persistable deterministic checkpoint for all event-stream mutations."""
    with bus._lock:
        bus._checkpoint_generation += 1
        checkpoint = {
            "checkpoint_generation": bus._checkpoint_generation,
            "sequence": bus._seq,
            "events": tuple(_causal_event_row_without_timestamp(ev) for ev in bus.snapshot()),
            "compressed_replay": bus.compressed_replay(),
            "budgets": bus.budget_snapshot(),
            "dependencies": bus.dependency_snapshot(),
            "invariants": bus.invariant_snapshot(),
            "lineage_pressure": bus.replay_lineage_pressure(),
            "replay_digest": bus.replay_digest(),
            "config_input_evidence": bus._config_input_evidence,
            "checkpoint_restore_evidence": bus._checkpoint_restore_evidence,
        }
        bus._last_checkpoint = checkpoint
        return checkpoint


def causal_topology_forecast_for_bus(bus: Any) -> dict[str, object]:
    """Causal forecast based on ancestry growth rather than only pressure totals."""
    with bus._lock:
        events = bus.snapshot()
        if not events:
            return {
                "event_count": 0,
                "predicted_growth": 0.0,
                "branching_factor": 0.0,
                "lineage_instability": 0.0,
                "anomaly_probability": 0.0,
                "confidence": 0.0,
                "action": "normal",
            }
        child_counts = dict(bus._children)
        parents = list(_causal_positive_counter_keys(child_counts))
        branching = sum(_causal_counter_values(child_counts)) / max(1, len(parents))
        recent = events[-min(len(events), 256):]
        recent_edges = sum(1 for ev in recent if ev.parent_seq is not None)
        recent_deep = sum(1 for ev in recent if ev.causal_depth >= 8)
        lineage_counts = list(_causal_counter_values(bus._lineage_counts))
        max_lineage = max(lineage_counts, default=0)
        lineage_instability = max_lineage / max(1, len(events))
        growth = (recent_edges / max(1, len(recent))) * (1.0 + min(4.0, branching) / 4.0)
        anomaly = min(
            1.0,
            (growth * 0.40)
            + (recent_deep / max(1, len(recent)) * 0.25)
            + (lineage_instability * 0.25)
            + (_causal_max_counter_value(child_counts) / max(1, bus._max_fanout_per_parent) * 0.10),
        )
        confidence = min(1.0, 0.15 + len(events) / 4096.0 + len(parents) / max(1, len(events)) * 0.35)
        action = (
            "terminate_replay_branch"
            if anomaly >= 0.90
            else ("isolate_topology_region" if anomaly >= 0.70 else ("preemptive_throttle" if anomaly >= 0.45 else "normal"))
        )
        return {
            "event_count": len(events),
            "predicted_growth": round(growth, 4),
            "branching_factor": round(branching, 4),
            "lineage_instability": round(lineage_instability, 4),
            "recent_deep_ratio": round(recent_deep / max(1, len(recent)), 4),
            "anomaly_probability": round(anomaly, 4),
            "confidence": round(confidence, 4),
            "action": action,
        }


def topology_pressure_forecast_for_bus(bus: Any) -> dict[str, object]:
    """Predict topology instability from density, fanout, suppression, and depth."""
    with bus._lock:
        events = len(bus._events)
        edges = sum(1 for ev in bus._events if ev.parent_seq is not None)
        max_fanout = _causal_max_counter_value(bus._children)
        max_depth = max((ev.causal_depth for ev in bus._events), default=0)
        suppressed = sum(_causal_budget_suppressed_values(bus._budgets))
        density = edges / max(1, events)
        suppression_ratio = suppressed / max(1, events + suppressed)
        fanout_ratio = max_fanout / max(1, bus._max_fanout_per_parent)
        depth_ratio = max_depth / max(1.0, float(_DEFAULT_WORKLOAD_MAX_DEPTH))
        causal = bus.causal_topology_forecast()
        causal_probability = float(causal.get("anomaly_probability", 0.0) or 0.0)
        pressure = min(
            1.0,
            (density * 0.15)
            + (fanout_ratio * 0.25)
            + (depth_ratio * 0.20)
            + (suppression_ratio * 0.15)
            + (causal_probability * 0.25),
        )
        confidence = min(
            1.0,
            0.20
            + (events / 2048.0)
            + (edges / max(1, events)) * 0.20
            + float(causal.get("confidence", 0.0) or 0.0) * 0.30,
        )
        anomalies = []
        if fanout_ratio >= 0.75:
            anomalies.append("fanout_collapse_risk")
        if depth_ratio >= 0.75:
            anomalies.append("deep_replay_cascade_risk")
        if suppression_ratio >= 0.25:
            anomalies.append("suppression_visibility_gap")
        if density >= 0.90 and events > 128:
            anomalies.append("dense_topology_coupling")
        if causal_probability >= 0.70:
            anomalies.append("causal_topology_instability")
        return {
            "event_count": events,
            "edge_count": edges,
            "density": round(density, 4),
            "max_fanout": max_fanout,
            "max_depth": max_depth,
            "suppressed": suppressed,
            "suppression_ratio": round(suppression_ratio, 4),
            "pressure": round(pressure, 4),
            "confidence": round(confidence, 4),
            "anomalies": anomalies,
            "causal_forecast": causal,
            "action": "isolate_topology_region"
            if (pressure >= 0.85 or causal.get("action") == "terminate_replay_branch")
            else ("preemptive_throttle" if pressure >= 0.55 else "normal"),
        }


def budget_snapshot_for_bus(bus: Any) -> dict[str, object]:
    with bus._lock:
        return {wid: budget.snapshot() for wid, budget in sorted(dict.items(bus._budgets))}


def dependency_snapshot_for_bus(bus: Any) -> dict[str, object]:
    with bus._lock:
        producers: dict[str, int] = {}
        edges: dict[str, int] = {}
        by_seq = dict(bus._by_seq)
        for ev in bus._events:
            producer_key = _causal_event_type_key(ev.domain, ev.kind)
            producers[producer_key] = producers.get(producer_key, 0) + 1
            if ev.parent_seq and ev.parent_seq in by_seq:
                parent = by_seq[ev.parent_seq]
                edge = _causal_dependency_edge(parent, ev)
                edges[edge] = edges.get(edge, 0) + 1
        return {
            "event_types": _causal_sorted_counter(producers),
            "edges": _causal_sorted_counter(edges),
            "event_count": len(bus._events),
            "sequence": bus._seq,
            "contract_violations": bus._contract_violations,
            "suppressed_reasons": _causal_sorted_counter(bus._suppressed_reasons),
        }


def invariant_snapshot_for_bus(bus: Any) -> dict[str, object]:
    with bus._lock:
        seqs = [ev.seq for ev in bus._events]
        monotonic = seqs == sorted(seqs) and len(seqs) == len(set(seqs))
        parent_valid = all(
            ev.parent_seq is None or (ev.parent_seq in bus._by_seq and ev.parent_seq < ev.seq)
            for ev in bus._events
        )
        too_deep = [ev.seq for ev in bus._events if ev.causal_depth > bus._budget(ev.workload_id).max_depth]
        fanout_bad = [
            parent
            for parent, count in _causal_counter_items(bus._children)
            if count > bus._max_fanout_per_parent
        ]
        return {
            "monotonic_sequence": monotonic,
            "parent_before_child": parent_valid,
            "too_deep": too_deep[:16],
            "fanout_bad": fanout_bad[:16],
            "suppressed_reasons": _causal_sorted_counter(bus._suppressed_reasons),
            "ok": bool(monotonic and parent_valid and not too_deep and not fanout_bad),
        }


def replay_digest_for_bus(bus: Any) -> str:
    """Stable digest over canonical replay records; timestamp-independent."""
    with bus._lock:
        raw = json.dumps(bus.canonical_replay(), sort_keys=True, separators=(",", ":"), allow_nan=False).encode(
            "utf-8", "replace"
        )
        return hashlib.sha256(raw).hexdigest()


def causal_trace_visualization_for_bus(bus: Any, *, max_events: int = 2048) -> dict[str, object]:
    """Return a compact graph-friendly causal trace across runtime domains."""
    limit, issues = runtime_int(
        max_events,
        field_name="causal_trace_visualization_max_events",
        default=2048,
    )
    if issues:
        raise ValueError("causal trace visualization limit rejected")
    with bus._lock:
        events = bus.snapshot()[-max(1, limit):]
        nodes = [_causal_event_node(ev) for ev in events]
        edges = [
            {"source": ev.parent_seq, "target": ev.seq}
            for ev in events
            if ev.parent_seq is not None and ev.parent_seq in bus._by_seq
        ]
        return {
            "nodes": nodes,
            "edges": edges,
            "digest": bus.replay_digest(),
            "event_count": len(nodes),
            "edge_count": len(edges),
        }
