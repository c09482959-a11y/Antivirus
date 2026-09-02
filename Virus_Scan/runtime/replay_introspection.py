"""Replay/event introspection and integrity validation for Stage 33."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping

from .causal_event_stream import CausalEvent, get_global_event_bus
from .governance_inputs import (
    runtime_bool,
    runtime_input_rejection,
    runtime_int,
    runtime_sequence,
)
from .immutable_core import freeze_runtime_value, materialize_runtime_value
from Virus_Scan.contracts.no_hook_materialization import no_hook_exact_owner_field, no_hook_mapping_items


def _replay_text(value: object) -> str:
    if type(value) is str:
        return str.__str__(value)
    if type(value) is int:
        return int.__str__(value)
    return "value"


def _replay_field(prefix: str, value: object) -> str:
    return str.__str__(prefix) + _replay_text(value)


def _replay_duplicate_count(values: dict[str, int]) -> int:
    items = no_hook_mapping_items(values)
    if items is None:
        return 0
    return sum(1 for _, value in items if value > 1)


@dataclass(frozen=True)
class ReplayIntegrityReport:
    ok: bool
    event_count: int
    cycle_count: int
    orphan_count: int
    max_depth: int
    duplicate_lineages: int
    input_evidence: tuple[Mapping[str, object], ...] = ()

    def __post_init__(self) -> None:
        if type(self) is not ReplayIntegrityReport:
            exception_message = "replay integrity report owner rejected"
            raise TypeError(exception_message)
        evidence: tuple[Mapping[str, object], ...] = ()
        ok, issues = runtime_bool(
            self.ok, field_name="replay_integrity_ok", default=False
        )
        evidence += issues
        for field_name in (
            "event_count",
            "cycle_count",
            "orphan_count",
            "max_depth",
            "duplicate_lineages",
        ):
            value, issues = runtime_int(
                no_hook_exact_owner_field(self, ReplayIntegrityReport, field_name),
                field_name=_replay_field("replay_integrity_", field_name),
                default=0,
            )
            evidence += issues
            object.__setattr__(self, field_name, value)
        evidence_rows, issues = runtime_sequence(
            self.input_evidence, field_name="replay_integrity_input_evidence"
        )
        evidence += issues + tuple(evidence_rows)
        if evidence:
            ok = False
        object.__setattr__(self, "ok", ok)
        object.__setattr__(
            self, "input_evidence", tuple(freeze_runtime_value(evidence))
        )

    def as_dict(self) -> dict[str, object]:
        result = {
            "ok": self.ok,
            "event_count": self.event_count,
            "cycle_count": self.cycle_count,
            "orphan_count": self.orphan_count,
            "max_depth": self.max_depth,
            "duplicate_lineages": self.duplicate_lineages,
        }
        if self.input_evidence:
            result["input_evidence"] = materialize_runtime_value(
                self.input_evidence
            )
        return result


def _replay_events(
    events: object,
) -> tuple[tuple[CausalEvent, ...], tuple[Mapping[str, object], ...]]:
    if events is None:
        return get_global_event_bus().snapshot(), ()
    rows, evidence = runtime_sequence(
        events, field_name="replay_introspection_events"
    )
    accepted: list[CausalEvent] = []
    for index, event in enumerate(rows):
        if type(event) is CausalEvent:
            accepted.append(event)
        else:
            evidence += (
                runtime_input_rejection(
                    _replay_field("replay_introspection_event_", index),
                    event,
                    "replay_event_rejected",
                ),
            )
    return tuple(accepted), evidence


def build_replay_graph(events: tuple[CausalEvent, ...] | None = None) -> dict[str, object]:
    events, input_evidence = _replay_events(events)
    nodes = []
    edges = []
    by_seq = {ev.seq: ev for ev in events}
    for ev in events:
        nodes.append({"seq": ev.seq, "domain": ev.domain, "kind": ev.kind, "lineage_id": ev.lineage_id, "workload_id": ev.workload_id, "depth": ev.causal_depth})
        if ev.parent_seq is not None and ev.parent_seq in by_seq:
            edges.append({"from": ev.parent_seq, "to": ev.seq})
    result = {
        "nodes": nodes,
        "edges": edges,
        "node_count": len(nodes),
        "edge_count": len(edges),
    }
    if input_evidence:
        result["input_evidence"] = materialize_runtime_value(input_evidence)
    return result


def validate_replay_integrity(events: tuple[CausalEvent, ...] | None = None) -> ReplayIntegrityReport:
    events, input_evidence = _replay_events(events)
    by_seq = {ev.seq: ev for ev in events}
    cycles = 0
    orphans = 0
    max_depth = 0
    lineage_counts: dict[str, int] = {}
    for ev in events:
        lineage_counts[ev.lineage_id] = lineage_counts.get(ev.lineage_id, 0) + 1
        seen: set[int] = set()
        cur: int | None = ev.seq
        depth = 0
        while cur is not None:
            if cur in seen:
                cycles += 1
                break
            seen.add(cur)
            parent_event = by_seq.get(cur)
            parent = parent_event.parent_seq if parent_event is not None else None
            if parent is not None and parent not in by_seq:
                orphans += 1
                break
            cur = parent
            depth += 1
        max_depth = max(max_depth, depth)
    duplicate_lineages = _replay_duplicate_count(lineage_counts)
    return ReplayIntegrityReport(
        cycles == 0 and orphans == 0 and not input_evidence,
        len(events),
        cycles,
        orphans,
        max_depth,
        duplicate_lineages,
        input_evidence,
    )


def why_event(seq: int) -> Mapping[str, object]:
    sequence, input_evidence = runtime_int(
        seq, field_name="replay_why_event_sequence", default=0
    )
    if input_evidence:
        return {
            "found": False,
            "seq": sequence,
            "input_evidence": materialize_runtime_value(input_evidence),
        }
    events = get_global_event_bus().snapshot()
    by_seq = {ev.seq: ev for ev in events}
    ev = by_seq.get(sequence)
    if ev is None:
        return {"found": False, "seq": sequence}
    ancestry: list[dict[str, object]] = []
    cur: CausalEvent | None = ev
    while cur is not None:
        ancestry.append({"seq": cur.seq, "domain": cur.domain, "kind": cur.kind, "lineage_id": cur.lineage_id, "payload": materialize_runtime_value(cur.payload)})
        parent = by_seq.get(cur.parent_seq) if cur.parent_seq is not None else None
        cur = parent
    return {"found": True, "seq": sequence, "event": ev.as_dict(), "ancestry": ancestry}


__all__ = ("ReplayIntegrityReport", "build_replay_graph", "validate_replay_integrity", "why_event")
