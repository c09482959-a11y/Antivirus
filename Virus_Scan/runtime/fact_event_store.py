"""Append-only fact event store.

Stores factual causal events without owning admission, budgets, topology, replay
snapshots, or governance policy.
"""
from __future__ import annotations
from typing import Tuple

from Virus_Scan.contracts.no_hook_materialization import (
    no_hook_plain_instance_dict,
)
from Virus_Scan.runtime.governance_inputs import runtime_int

class FactEventStore:
    def __init__(self, max_events: int = 65536) -> None:
        self.max_events, self.input_evidence = runtime_int(
            max_events, field_name="fact_event_store_max_events", default=65536
        )
        self.max_events = max(1, self.max_events)
        self.events: list[object] = []
        self.by_seq: dict[int, object] = {}
        self.parent: dict[int, int | None] = {}
        self.depth: dict[int, int] = {}
        self.children: dict[int, int] = {}

    def append(self, ev: object, parent_seq: int | None, depth: int) -> object:
        event_state = no_hook_plain_instance_dict(ev)
        if event_state is None:
            exception_message = "fact event rejected"
            raise ValueError(exception_message)
        seq, seq_issues = runtime_int(
            dict.get(event_state, "seq"),
            field_name="fact_event_seq",
            default=0,
        )
        depth_value, depth_issues = runtime_int(
            depth, field_name="fact_event_depth", default=0
        )
        if seq_issues or depth_issues or seq <= 0:
            exception_message = "fact event sequence or depth rejected"
            raise ValueError(exception_message)
        parent = None
        if parent_seq is not None:
            parent, parent_issues = runtime_int(
                parent_seq, field_name="fact_event_parent_seq", default=0
            )
            if parent_issues:
                exception_message = "fact event parent rejected"
                raise ValueError(exception_message)
        self.events.append(ev)
        self.by_seq[seq] = ev
        self.parent[seq] = parent
        self.depth[seq] = depth_value
        if parent is not None:
            self.children[parent] = self.children.get(parent, 0) + 1
        return self.prune()

    def prune(self) -> object:
        if len(self.events) <= self.max_events:
            return []
        drop = len(self.events) - self.max_events
        old = self.events[:drop]
        for item in old:
            self.parent.pop(item.seq, None)
            self.depth.pop(item.seq, None)
            self.children.pop(item.seq, None)
            self.by_seq.pop(item.seq, None)
        del self.events[:drop]
        return old

    def snapshot(self) -> Tuple[object, ...]:
        return tuple(sorted(self.events, key=lambda ev: (ev.seq, ev.domain, ev.kind, ev.event_key)))
