from __future__ import annotations
from Virus_Scan.detection.chains.execution.anchors import evaluate_chain_evidence
from Virus_Scan.tests.support.canonical_chain_fixtures import physical_tag_evidence

from Virus_Scan.detection.correlation.graph.temporal_graph import (
    _materialize_temporal_validation,
    compute_stage_timeline_layer,
    infer_causal_transition_edges,
)


class HostileTemporalGraphValue:
    touched = 0

    def __bool__(self):
        type(self).touched += 1
        raise RuntimeError("bool hook must not run")

    def __str__(self):
        type(self).touched += 1
        raise RuntimeError("str hook must not run")

    def __repr__(self):
        type(self).touched += 1
        raise RuntimeError("repr hook must not run")

    def __iter__(self):
        type(self).touched += 1
        raise RuntimeError("iter hook must not run")

    @property
    def entity_type(self):
        type(self).touched += 1
        raise RuntimeError("property hook must not run")


class HostileTemporalValidationOutput:
    touched = 0

    def get(self, key, default=None):
        type(self).touched += 1
        raise RuntimeError("mapping hook must not run")

    def __iter__(self):
        type(self).touched += 1
        raise RuntimeError("iter hook must not run")

    def __str__(self):
        type(self).touched += 1
        raise RuntimeError("str hook must not run")


def test_stage1650_stage_timeline_rejects_hostile_public_inputs_without_hooks() -> None:
    HostileTemporalGraphValue.touched = 0
    hostile = HostileTemporalGraphValue()

    result = compute_stage_timeline_layer(
        hostile,
        tags=[hostile, "network_download"],
        chain_evidence=evaluate_chain_evidence(
            tags=physical_tag_evidence(("network_download",)),
        ),
        curr_stage=hostile,
        prev_stage=hostile,
        ordered_events=hostile,
        behavior_flow=[hostile, "network_download"],
    )

    assert HostileTemporalGraphValue.touched == 0
    assert result["degraded"] is True
    assert result["json_record_required"] is True
    assert any(
        record.get("stage_name") == "stage_timeline_layer_node_boundary"
        for record in result["failure_evidence"]
    )
    assert all("HostileTemporalGraphValue" not in hit for hit in result["hits"])


def test_stage1650_temporal_validation_projection_rejects_mapping_like_output_without_hooks() -> None:
    HostileTemporalValidationOutput.touched = 0
    hostile_output = HostileTemporalValidationOutput()

    result = _materialize_temporal_validation(hostile_output)

    assert HostileTemporalValidationOutput.touched == 0
    assert result["ready"] is False
    assert result["degraded"] is True
    assert result["unavailable_reason"] == "invalid_temporal_validation_output"


def test_stage1650_causal_transition_edges_reject_hostile_tags_and_entities_without_hooks() -> None:
    HostileTemporalGraphValue.touched = 0
    hostile = HostileTemporalGraphValue()

    edges = infer_causal_transition_edges(
        path=hostile,
        tags=["network_download", hostile, "encoded_payload"],
        entities=[
            {"entity_type": "file", "entity_id": "file-root"},
            {"entity_type": hostile, "entity_id": "payload"},
            hostile,
        ],
    )

    assert HostileTemporalGraphValue.touched == 0
    assert edges == []
