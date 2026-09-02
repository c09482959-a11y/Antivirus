from __future__ import annotations

import json
from collections.abc import Mapping

from Virus_Scan.models import graph


class HostileIterable:
    def __bool__(self):
        raise RuntimeError("iterable truthiness unavailable")

    def __iter__(self):
        raise RuntimeError("iteration unavailable")


class HostileEntity(Mapping):
    def __iter__(self):
        return iter(("id", "kind"))

    def __len__(self):
        return 2

    def __getitem__(self, key):
        raise RuntimeError("entity item unavailable")

    def get(self, key, default=None):
        raise RuntimeError("entity get unavailable")


class HostileEventTimes(Mapping):
    def __iter__(self):
        raise RuntimeError("event times iteration unavailable")

    def __len__(self):
        raise RuntimeError("event times length unavailable")

    def __getitem__(self, key):
        raise RuntimeError("event times item unavailable")

    def items(self):
        raise RuntimeError("event times items unavailable")


class HostileText:
    def __str__(self):
        raise RuntimeError("text unavailable")


def test_stage1422_transition_edges_emit_degraded_evidence_for_hostile_entities() -> None:
    edges = graph.infer_causal_transition_edges(
        tags=("execution",),
        entities=HostileIterable(),
        event_times={"a": 1.0},
    )

    assert edges == (
        {
            "src": "graph_input_unavailable",
            "dst": "graph_input_unavailable",
            "src_kind": "graph_input_unavailable",
            "dst_kind": "graph_input_unavailable",
            "relation": "unavailable_transition",
            "confidence": 0.0,
            "degraded": True,
            "relation_unavailable_reason": "unreadable_graph_transition_entities",
            "final_json_must_record": True,
            "replay_record_required": True,
        },
    )
    json.dumps(edges, sort_keys=True)


def test_stage1422_transition_edges_record_hostile_event_time_mapping() -> None:
    edges = graph.infer_causal_transition_edges(
        tags=("execution", "credential_access"),
        entities=(
            {"kind": "file", "id": "sample.exe"},
            {"kind": "behavior_tag", "id": "credential_access"},
        ),
        event_times=HostileEventTimes(),
    )

    assert len(edges) == 1
    edge = edges[0]
    assert edge["degraded"] is True
    assert edge["relation_unavailable_reason"] == "unreadable_graph_event_times"
    assert edge["final_json_must_record"] is True
    assert edge["replay_record_required"] is True
    json.dumps(edges, sort_keys=True)


def test_stage1422_transition_edges_record_hostile_entity_fields_and_tags() -> None:
    edges = graph.infer_causal_transition_edges(
        tags=HostileIterable(),
        entities=(HostileEntity(), {"kind": HostileText(), "id": "right"}),
        event_times={"right": 2.0},
    )

    assert len(edges) == 1
    edge = edges[0]
    assert edge["degraded"] is True
    assert edge["relation_unavailable_reason"] in {
        "unreadable_graph_transition_tags",
        "unreadable_graph_transition_entity",
    }
    assert edge["final_json_must_record"] is True
    assert edge["replay_record_required"] is True
    json.dumps(edges, sort_keys=True)
