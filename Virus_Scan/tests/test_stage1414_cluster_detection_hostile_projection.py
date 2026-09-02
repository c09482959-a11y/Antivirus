from Virus_Scan.tests.support.profile_learning import accepted_learning_decision
from Virus_Scan.tests.support.clustering_v2 import raw_cluster_vector
from Virus_Scan.tests.support.canonical_chain_fixtures import physical_tag_evidence
from Virus_Scan.detection.correlation.multi_signal.model_projections import (
    detection_cluster_projection,
    detection_temporal_history_timeline,
    detection_temporal_snapshot,
)
from Virus_Scan.models import clustering


class _HostileText:
    def __str__(self):
        raise RuntimeError("hostile text")

    def __repr__(self):
        raise RuntimeError("hostile repr")


class _HostileIterable:
    def __iter__(self):
        raise RuntimeError("hostile iterator")


def test_stage1414_direct_cluster_assignment_degrades_hostile_public_inputs() -> None:
    result = clustering.assign_cluster_with_context_tags(
        _HostileText(),
        [0.25, 0.75],
        tags=[_HostileText()],
        engine_context={_HostileText(): 1.0},
     learning_decision=accepted_learning_decision(target_names=("clustering",)))

    assert isinstance(result, dict)
    assert result["ready"] is False
    assert result["degraded"] is True
    assert result["final_json_must_record"] is True
    assert result["replay_record_required"] is True
    assert result["cluster_unavailable_reason"]


def test_stage1414_detection_cluster_projection_handles_hostile_inputs_without_model_state() -> None:
    projection = detection_cluster_projection(
        _HostileText(),
        physical_tag_evidence(("process_injection",)),
        engine_context={_HostileText(): 1.0},
    )

    assert projection == "other_noext_malicious_detection_projection"


def test_stage1414_detection_temporal_projection_detaches_hostile_event_inputs() -> None:
    snapshot = detection_temporal_snapshot("node", ordered_events=[{"tag": _HostileText()}, {"tag": "network_download"}])
    timeline = detection_temporal_history_timeline("node", ordered_events=[{"tag": _HostileText(), "stage": _HostileText()}])

    assert snapshot["ready"] is True
    assert snapshot["flow"] == ["network_download"]
    assert timeline == [{"time": 0, "stage": "current", "tags": []}]


def test_stage1414_direct_cluster_assignment_degrades_hostile_iterators() -> None:
    result = clustering.assign_cluster_with_context_tags(
        "node.bin",
        raw_cluster_vector(),
        tags=_HostileIterable(),
        engine_context={"unity": 1.0},
     learning_decision=accepted_learning_decision(target_names=("clustering",)))

    assert isinstance(result, dict)
    assert result["cluster_unavailable_reason"] == "cluster_tag_input_unavailable"

from Virus_Scan.detection.correlation.multi_signal.model_projections import (
    detection_behavior_bucket_validation,
    detection_feature_vector,
)
from Virus_Scan.detection.chains.execution.anchors import evaluate_chain_evidence


def test_stage1414_detection_behavior_bucket_validation_detaches_hostile_inputs() -> None:
    result = detection_behavior_bucket_validation(
        _HostileText(),
        _HostileText(),
        physical_tag_evidence(("process_injection",)),
        strings_blob=_HostileText(),
        ordered_events=_HostileIterable(),
    )

    assert any(record["tag"] == "process_injection" for record in result["records"])
    assert "filetype_validation" in result


def test_stage1414_detection_feature_vector_detaches_hostile_model_inputs() -> None:
    vector = detection_feature_vector(
        _HostileText(),
        physical_tag_evidence(("process_injection",)),
        evaluate_chain_evidence(tags=physical_tag_evidence(("process_injection",))),
        {_HostileText(): 1.0, "risk": 0.5},
        {_HostileText(): 1.0, "belief": 0.25},
        {_HostileText(): 1.0, "pair_anomaly": 0.25},
        {_HostileText(): 1.0, "unity": 1.0},
        file_path=_HostileText(),
        strings_blob=_HostileText(),
        ordered_events=_HostileIterable(),
    )

    assert isinstance(vector, list)
    assert vector
    assert all(0.0 <= value <= 1.0 for value in vector)
