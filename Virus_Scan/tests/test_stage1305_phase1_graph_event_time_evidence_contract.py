import json
import math

from Virus_Scan.models import graph


def _lineage_with_event_time(value):
    return graph.causal_entity_lineage_overlay(
        path="sample.exe",
        tags=("powershell_exec", "credential_dump_attempt"),
        metadata={"engine": "unity"},
        event_times={"sample.exe": value, ".exe": 1.0},
    )


def test_stage1305_graph_lineage_records_non_numeric_event_time_evidence_without_crash():
    evidence = _lineage_with_event_time("not-a-time")

    assert evidence["ready"] is True
    assert evidence["directed_edges_present"] is True
    assert evidence["event_time_unavailable_reason"] == "non_numeric_event_time"
    assert evidence["invalid_event_time_count"] >= 1
    assert any(
        edge.get("relation_unavailable_reason") == "non_numeric_event_time"
        for edge in evidence["transition_edges"]
    )
    json.dumps(evidence, allow_nan=False)


def test_stage1305_graph_lineage_records_non_finite_event_time_evidence_without_nan_json():
    evidence = _lineage_with_event_time(math.nan)

    assert evidence["ready"] is True
    assert evidence["event_time_unavailable_reason"] == "non_finite_event_time"
    assert evidence["invalid_event_time_count"] >= 1
    raw = json.dumps(evidence, allow_nan=False)
    assert "NaN" not in raw and "Infinity" not in raw
