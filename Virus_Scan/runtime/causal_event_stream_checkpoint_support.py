"""Checkpoint restore support for the causal event stream owner."""
from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import Any

from .causal_event_stream_support import _causal_checkpoint_event_field
from .governance_inputs import (
    runtime_input_rejection,
    runtime_int,
    runtime_mapping,
    runtime_sequence,
)
from .immutable_core import freeze_runtime_value, materialize_runtime_value


def restore_checkpoint_for_bus(
    bus: Any,
    checkpoint: Mapping[str, object],
    *,
    event_factory: Callable[..., object],
) -> None:
    """Restore deterministic stream state from a checkpoint mapping."""
    checkpoint_state, checkpoint_issues = runtime_mapping(
        checkpoint, field_name="causal_checkpoint"
    )
    event_rows, event_issues = runtime_sequence(
        dict.get(checkpoint_state, "events"),
        field_name="causal_checkpoint_events",
    )
    top_level_evidence = checkpoint_issues + event_issues
    if top_level_evidence:
        with bus._lock:
            bus._checkpoint_restore_evidence = top_level_evidence
            bus._last_checkpoint = materialize_runtime_value(
                freeze_runtime_value(
                    {
                        "checkpoint_restore_rejected": True,
                        "input_evidence": top_level_evidence,
                    }
                )
            )
        return
    parsed_events, restore_evidence = _parse_checkpoint_events(
        event_rows, event_factory=event_factory
    )
    if event_rows and not parsed_events:
        _record_checkpoint_rejection(
            bus,
            checkpoint_state,
            restore_evidence,
            reason="causal_checkpoint_all_event_rows_rejected",
        )
        return
    _commit_checkpoint_restore(bus, checkpoint_state, parsed_events, restore_evidence)


def _parse_checkpoint_events(
    event_rows: tuple[object, ...],
    *,
    event_factory: Callable[..., object],
) -> tuple[list[object], tuple[Mapping[str, object], ...]]:
    parsed_events: list[object] = []
    evidence: tuple[Mapping[str, object], ...] = ()
    seen_sequences: set[int] = set()
    for index, raw_item in enumerate(event_rows):
        event, issues = _parse_checkpoint_event(raw_item, index, event_factory=event_factory)
        evidence += issues
        if event is None:
            continue
        if event.seq in seen_sequences:
            evidence += (
                runtime_input_rejection(
                    _causal_checkpoint_event_field(index, "_seq"),
                    event.seq,
                    "causal_checkpoint_duplicate_sequence",
                ),
            )
            continue
        seen_sequences.add(event.seq)
        parsed_events.append(event)
    parsed_events.sort(key=lambda event: event.seq)
    return parsed_events, evidence


def _parse_checkpoint_event(
    raw_item: object,
    index: int,
    *,
    event_factory: Callable[..., object],
) -> tuple[object | None, tuple[Mapping[str, object], ...]]:
    item, evidence = runtime_mapping(
        raw_item, field_name=_causal_checkpoint_event_field(index)
    )
    if evidence:
        return None, evidence
    seq, issues = runtime_int(
        dict.get(item, "seq", 0),
        field_name=_causal_checkpoint_event_field(index, "_seq"),
        default=0,
    )
    evidence += issues
    if issues or seq <= 0:
        if not issues:
            evidence += (
                runtime_input_rejection(
                    _causal_checkpoint_event_field(index, "_seq"),
                    seq,
                    "causal_checkpoint_sequence_must_be_positive",
                ),
            )
        return None, evidence
    parent_value = dict.get(item, "parent_seq")
    parent_seq = None
    if parent_value is not None:
        parent_seq, issues = runtime_int(
            parent_value,
            field_name=_causal_checkpoint_event_field(index, "_parent_seq"),
            default=0,
        )
        evidence += issues
        if issues:
            parent_seq = None
    return (
        event_factory(
            seq=seq,
            lineage_id=dict.get(item, "lineage_id", ""),
            domain=dict.get(item, "domain", "runtime"),
            kind=dict.get(item, "kind", "event"),
            payload=dict.get(item, "payload", {}),
            generation=dict.get(item, "generation", 0),
            parent_seq=parent_seq,
            workload_id=dict.get(item, "workload_id", "global"),
            event_key=dict.get(item, "event_key", ""),
            suppressed_count=dict.get(item, "suppressed_count", 0),
            cost=dict.get(item, "cost", 0.0),
            severity=dict.get(item, "severity", "operational"),
            schema_version=dict.get(item, "schema_version", 1),
            owner=dict.get(item, "owner", "runtime"),
            propagation=dict.get(item, "propagation", "append_only"),
            causal_depth=dict.get(item, "causal_depth", 0),
            causal_path=dict.get(item, "causal_path", ()),
            causal_digest=dict.get(item, "causal_digest", ""),
        ),
        evidence,
    )


def _record_checkpoint_rejection(
    bus: Any,
    checkpoint_state: Mapping[str, object],
    evidence: tuple[Mapping[str, object], ...],
    *,
    reason: str,
) -> None:
    rejection = (
        runtime_input_rejection(
            "causal_checkpoint_events", checkpoint_state, reason
        ),
    )
    combined = evidence + rejection
    with bus._lock:
        bus._checkpoint_restore_evidence = combined
        bus._last_checkpoint = materialize_runtime_value(
            freeze_runtime_value(
                {
                    "checkpoint_restore_rejected": True,
                    "checkpoint": checkpoint_state,
                    "input_evidence": combined,
                }
            )
        )


def _commit_checkpoint_restore(
    bus: Any,
    checkpoint_state: Mapping[str, object],
    parsed_events: list[object],
    restore_evidence: tuple[Mapping[str, object], ...],
) -> None:
    with bus._lock:
        bus.reset()
        for event in parsed_events:
            bus._fact_store.append(event, event.parent_seq, event.causal_depth)
            bus._events = bus._fact_store.events
            bus._by_seq = bus._fact_store.by_seq
            bus._parent = bus._fact_store.parent
            bus._depth = bus._fact_store.depth
            bus._children = bus._fact_store.children
            lineage = event.lineage_id
            bus._lineage_counts[lineage] = bus._lineage_counts.get(lineage, 0) + 1
            bus._seq = max(bus._seq, event.seq)
        bus._checkpoint_restore_evidence = restore_evidence
        bus._last_checkpoint = materialize_runtime_value(
            freeze_runtime_value(
                {
                    "checkpoint": checkpoint_state,
                    "input_evidence": restore_evidence,
                }
            )
        )
        bus._lineage_descendants = {}
        for event in bus._events:
            if event.parent_seq is not None:
                lineage = event.lineage_id
                bus._lineage_descendants[lineage] = bus._lineage_descendants.get(lineage, 0) + 1
