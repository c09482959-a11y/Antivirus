from __future__ import annotations
from Virus_Scan.detection.chains.execution.anchors import evaluate_chain_evidence
from Virus_Scan.tests.support.canonical_chain_fixtures import physical_tag_evidence
from Virus_Scan.tests.support.static_inventory import read_python_file


import ast
from pathlib import Path

from Virus_Scan.detection.correlation.graph.temporal_graph import compute_stage_timeline_layer


def test_stage1146_stage_timeline_layer_invokes_temporal_validation_boundary() -> None:
    source = read_python_file(Path("Virus_Scan/detection/correlation/graph/temporal_graph.py"))
    tree = ast.parse(source)
    function = next(node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef) and node.name == "compute_stage_timeline_layer")
    calls = {getattr(node.func, "id", getattr(node.func, "attr", "")) for node in ast.walk(function) if isinstance(node, ast.Call)}

    assert "detection_temporal_validation" in calls
    assert "compute_temporal_validation" not in calls
    assert "temporal_validation = {'score': 0.0, 'hits': []}" not in source


def test_stage1146_stage_timeline_layer_publishes_temporal_validation_hits_deterministically() -> None:
    tag_evidence = physical_tag_evidence(("certutil_exec", "network_download"))
    ordered_events = [
        {"time": 1, "stage": "asset", "tag": "certutil_exec"},
        {"time": 2, "stage": "runtime", "tag": "network_download"},
    ]
    result = compute_stage_timeline_layer(
        "stage1146-script.py",
        tag_evidence,
        chain_evidence=evaluate_chain_evidence(
            tags=tag_evidence, ordered_events=ordered_events,
        ),
        curr_stage="runtime",
        prev_stage="asset",
        ordered_events=ordered_events,
        behavior_flow=["certutil_exec", "network_download"],
    )

    temporal_validation = result["temporal_validation"]
    assert temporal_validation["ready"] is True
    assert temporal_validation["score"] == 0.81
    assert temporal_validation["evidence_strength"] == 0.045
    assert temporal_validation["phase_progression_evidence"]["strength"] == 0.3
    assert temporal_validation["chain_score_contribution"] == 0.0
    assert "execution.certutil_download" in temporal_validation["chain_identities"]
    assert "ordered_certutil_download" not in result["hits"]
    assert "temporal_phase_policy" in result["hits"]
    events = temporal_validation["events"]
    assert [event["behavior_id"] for event in events] == [
        "certutil_exec", "network_download",
    ]
    assert [event["stage"] for event in events] == ["asset", "runtime"]
    assert [event["timestamp_kind"] for event in events] == [
        "observed", "observed",
    ]
    assert [event["timestamp_value"] for event in events] == [1.0, 2.0]
    assert all(event["schema_version"] == "temporal_event_v5" for event in events)
    assert all("tag" not in event and "order" not in event and "phase" not in event for event in events)
    assert all(
        ["materializer", "canonical_temporal_event_v5"] in event["provenance"]
        for event in events
    )
