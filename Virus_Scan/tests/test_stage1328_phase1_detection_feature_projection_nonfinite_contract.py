import json
import math

from Virus_Scan.detection.correlation.multi_signal import model_projections
from Virus_Scan.tests.support.canonical_chain_fixtures import physical_tag_evidence
from Virus_Scan.detection.chains.execution.anchors import evaluate_chain_evidence


def test_stage1328_detection_feature_vector_rejects_nonfinite_model_inputs_as_unavailable():
    vector = model_projections.detection_feature_vector(
        "sample.png",
        tags=["benign_asset"],
        chain_evidence=evaluate_chain_evidence(tags=physical_tag_evidence(("benign_asset",))),
        graph_features={"risk": float("nan"), "anomaly": float("inf")},
        temporal_features={"belief": float("inf")},
        markov_features={"transition": float("nan"), "rarity": float("inf"), "pair_anomaly": "not-a-number"},
        engine_context={"unity": float("inf"), "renpy": float("nan"), "unknown": "not-a-number"},
        risk=float("inf"),
        file_path="sample.png",
    )

    assert len(vector) == len(model_projections.VECTOR_FEATURE_NAMES)
    assert all(math.isfinite(value) for value in vector)
    assert vector[model_projections.VECTOR_FEATURE_NAMES.index("risk_scaled")] == 0.0
    json.dumps({"vector": vector}, allow_nan=False, sort_keys=True)


def test_stage1328_detection_cluster_projection_ignores_nonfinite_engine_context_for_dominance():
    label = model_projections.detection_cluster_projection(
        "payload.rpy",
        tags=physical_tag_evidence(("pickle_dangerous_global", "pickle_reduce_opcode")),
        engine_context={"unity": float("inf"), "renpy": 0.6},
    )

    assert label == "renpy_rpy_malicious_detection_projection"
    json.dumps({"label": label}, allow_nan=False, sort_keys=True)


def test_stage1328_detection_cluster_projection_falls_back_when_all_engine_weights_are_corrupt():
    label = model_projections.detection_cluster_projection(
        "payload.rpy",
        tags=physical_tag_evidence(("pickle_dangerous_global", "pickle_reduce_opcode")),
        engine_context={"unity": float("inf"), "renpy": float("nan"), "rpgm": "bad"},
    )

    assert label == "other_rpy_malicious_detection_projection"
    json.dumps({"label": label}, allow_nan=False, sort_keys=True)
