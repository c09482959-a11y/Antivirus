from __future__ import annotations

from Virus_Scan.models import graph as graph_model
from Virus_Scan.models.api import adaptive_signals, graph_contracts


class HostileGraphNode:
    def __bool__(self):  # pragma: no cover - validates public wrapper catches implementation path
        raise RuntimeError("graph node truthiness unavailable")

    def __str__(self):  # pragma: no cover - validates logging/path text cannot leak
        raise RuntimeError("graph node text unavailable")


def test_stage1420_graph_relationship_public_contract_catches_hostile_node_path() -> None:
    evidence = graph_contracts.compute_graph_relationship_layer(
        HostileGraphNode(),
        tags=("execution", "credential_access"),
    )

    assert evidence["graph_relationship_ready"] is False
    assert evidence["degraded"] is True
    assert evidence["unavailable_reason"] in {"graph_relationship_public_call_failed", "graph_relationship_layer_failed"}
    assert evidence["final_json_must_record"] is True
    assert evidence["replay_record_required"] is True


def test_stage1420_adaptive_graph_relationship_contract_catches_hostile_node_path() -> None:
    evidence = adaptive_signals.compute_graph_relationship_layer(
        HostileGraphNode(),
        tags=("execution", "credential_access"),
    )

    assert evidence["graph_relationship_ready"] is False
    assert evidence["degraded"] is True
    assert evidence["unavailable_reason"] in {"graph_relationship_public_call_failed", "graph_relationship_layer_failed"}
    assert evidence["final_json_must_record"] is True
    assert evidence["replay_record_required"] is True


def test_stage1420_graph_temporal_link_public_contract_catches_hostile_stage_path() -> None:
    evidence = graph_contracts.link_temporal_to_graph(
        "node:stage1420",
        HostileGraphNode(),
        ("execution", "credential_access"),
        "runtime",
    )

    assert evidence["linked"] is False
    assert evidence["degraded"] is True
    assert evidence["unavailable_reason"] == "graph_temporal_link_public_call_failed"
    assert evidence["final_json_must_record"] is True
    assert evidence["replay_record_required"] is True


def test_stage1420_graph_relationship_core_uses_safe_log_text_for_hostile_node() -> None:
    evidence = graph_model.compute_graph_relationship_layer(
        HostileGraphNode(),
        tags=("execution", "credential_access"),
    )

    assert evidence["graph_relationship_ready"] is False
    assert evidence["graph_unavailable_reason"] == "graph_relationship_layer_failed"
