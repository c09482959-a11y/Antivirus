from __future__ import annotations

from dataclasses import FrozenInstanceError

import pytest

from Virus_Scan.models.replay_introspection import ReplayNode, compress_replay_nodes
from Virus_Scan.runtime.causal_event_stream import CausalEvent
from Virus_Scan.runtime.governance_invariants import CircuitBreakerState, RuntimeInvariantReport, evaluate_runtime_invariants
from Virus_Scan.runtime.mutation_coordinator import RuntimeEvent
from Virus_Scan.runtime.provenance_graph import ProvenanceGraphEvent


def test_replay_node_is_immutable_and_compression_uses_replacement() -> None:
    node = ReplayNode("child", "root", ["network", "loader"], 0.4, "scanner", "evidence")
    assert node.tags == ("network", "loader")
    with pytest.raises(FrozenInstanceError):
        node.influence = 1.0  # type: ignore[misc]
    with pytest.raises(AttributeError):
        node.tags.append("mutated")  # type: ignore[attr-defined]

    merged = compress_replay_nodes([
        ReplayNode("child", "root", ["loader"], 0.1, "scanner", "first"),
        ReplayNode("child", "root", ["network"], 0.8, "", "second"),
    ])
    assert len(merged) == 1
    assert merged[0].tags == ("loader", "network")
    assert merged[0].influence == 0.8
    assert merged[0].origin == "scanner"
    assert merged[0].rationale == "first"


def test_causal_event_payload_recursively_detaches_from_caller_mutation() -> None:
    source = {"nested": {"items": ["a"]}}
    event = CausalEvent(1, "lineage", "runtime", "kind", source)
    source["nested"]["items"].append("mutated")

    assert event.as_dict()["payload"] == {"nested": {"items": ["a"]}}
    with pytest.raises(TypeError):
        event.payload["new"] = "blocked"  # type: ignore[index]
    with pytest.raises(TypeError):
        event.payload["nested"]["items"] += ("blocked",)  # type: ignore[index,operator]


def test_runtime_event_payload_is_deeply_immutable_but_materializes_for_callers() -> None:
    source = {"metadata": {"tags": ["one"]}}
    event = RuntimeEvent("runtime", "snapshot", source)
    source["metadata"]["tags"].append("mutated")

    assert event.as_dict()["payload"] == {"metadata": {"tags": ["one"]}}
    with pytest.raises(TypeError):
        event.payload["metadata"]["tags"] += ("two",)  # type: ignore[index,operator]


def test_provenance_graph_event_payload_is_deeply_immutable() -> None:
    source = {"context": {"paths": ["a"]}}
    event = ProvenanceGraphEvent.build(event_type="scan", subsystem="runtime", payload=source, parent_ids=["root"])
    source["context"]["paths"].append("mutated")

    assert event.canonical()["payload"] == {"context": {"paths": ["a"]}}
    with pytest.raises(TypeError):
        event.payload["context"]["paths"] += ("b",)  # type: ignore[index,operator]


def test_governance_invariant_report_and_circuit_breaker_are_immutable_outputs() -> None:
    report = evaluate_runtime_invariants(replay_depth=99, telemetry_events=999)
    assert isinstance(report.violations, tuple)
    assert isinstance(report.circuit_breaker.reasons, tuple)
    assert report.as_dict()["circuit_breaker"]["reasons"] == ["replay_depth_exceeded", "telemetry_budget_exceeded"]

    with pytest.raises(FrozenInstanceError):
        report.ok = True  # type: ignore[misc]
    with pytest.raises(FrozenInstanceError):
        report.circuit_breaker.replay_frozen = False  # type: ignore[misc]

    cb = CircuitBreakerState().trip("a").trip("a").trip("b", telemetry=True)
    assert cb.reasons == ("a", "b")
    assert cb.telemetry_throttled is True

from Virus_Scan.runtime.mutation_coordinator import RuntimeRoot


def test_runtime_domain_state_detaches_caller_mutation_and_snapshot_is_deeply_immutable() -> None:
    root = RuntimeRoot()
    source = {"items": ["original"]}
    returned = root.mutate("runtime", "root.phase3", source, kind="event")
    source["items"].append("caller-mutated")

    assert returned == {"items": ["original"]}
    assert root.domain("runtime").get("root.phase3") == {"items": ["original"]}

    snapshot = root.domain("runtime").snapshot()
    assert snapshot["root.phase3"]["items"] == ("original",)
    with pytest.raises(TypeError):
        snapshot["root.phase3"]["items"] += ("blocked",)  # type: ignore[index,operator]
    assert root.domain("runtime").get("root.phase3") == {"items": ["original"]}
