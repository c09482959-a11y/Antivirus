"""Stage 1412: graph causal lineage reports hostile public inputs as evidence."""

from __future__ import annotations

from collections.abc import Mapping
import json

from Virus_Scan.models import graph


class HostilePath:
    def __str__(self):
        raise RuntimeError("path string unavailable")

    def __repr__(self):
        raise RuntimeError("path repr unavailable")


class HostileIterable:
    def __iter__(self):
        raise RuntimeError("iteration unavailable")

    def __repr__(self):
        raise RuntimeError("iterable repr unavailable")


class HostileMetadata(Mapping):
    def __iter__(self):
        raise RuntimeError("metadata iteration unavailable")

    def __len__(self):
        raise RuntimeError("metadata length unavailable")

    def __getitem__(self, key):
        raise RuntimeError("metadata item unavailable")

    def get(self, key, default=None):
        raise RuntimeError("metadata get unavailable")

    def keys(self):
        raise RuntimeError("metadata keys unavailable")


def test_stage1412_infer_behavioral_entities_degrades_hostile_inputs() -> None:
    entities = graph.infer_behavioral_entities(
        path=HostilePath(),
        tags=HostileIterable(),
        metadata=HostileMetadata(),
    )

    unavailable = [entity for entity in entities if entity["kind"] == "graph_input_unavailable"]
    reasons = {entity["unavailable_reason"] for entity in unavailable}
    assert "unreadable_graph_path" in reasons
    assert "unreadable_graph_tags" in reasons
    assert "unreadable_graph_metadata" in reasons
    assert all(entity["final_json_must_record"] is True for entity in unavailable)
    json.dumps(entities, sort_keys=True)


def test_stage1412_causal_entity_lineage_overlay_records_degraded_graph_evidence() -> None:
    evidence = graph.causal_entity_lineage_overlay(
        path=HostilePath(),
        tags=HostileIterable(),
        metadata=HostileMetadata(),
        event_times=HostileIterable(),
    )

    assert evidence["ready"] is False
    assert evidence["degraded"] is True
    assert evidence["final_json_must_record"] is True
    assert evidence["replay_record_required"] is True
    assert evidence["graph_unavailable_reason"] in {
        "unreadable_graph_path",
        "unreadable_graph_tags",
        "unreadable_graph_metadata",
    }
    assert any(entity["kind"] == "graph_input_unavailable" for entity in evidence["entities"])
    json.dumps(evidence, sort_keys=True)


class HostileIterator:
    def __iter__(self):
        return self

    def __next__(self):
        raise RuntimeError("next unavailable")


def test_stage1412_causal_entity_lineage_overlay_records_degraded_iterator_failures() -> None:
    evidence = graph.causal_entity_lineage_overlay(tags=HostileIterator())

    assert evidence["ready"] is False
    assert evidence["degraded"] is True
    assert evidence["final_json_must_record"] is True
    assert evidence["replay_record_required"] is True
    assert any(entity["kind"] == "graph_input_unavailable" for entity in evidence["entities"])
    json.dumps(evidence, sort_keys=True)
