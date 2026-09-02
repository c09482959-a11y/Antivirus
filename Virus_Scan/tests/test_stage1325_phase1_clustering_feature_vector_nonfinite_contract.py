from __future__ import annotations

import json
import math

from Virus_Scan.models.clustering import build_feature_vector
from Virus_Scan.runtime.cluster_state import RuntimeClusterState, configure_runtime_cluster_state


def _bind_cluster_state() -> None:
    configure_runtime_cluster_state(RuntimeClusterState())


def test_stage1325_clustering_feature_vector_rejects_nonfinite_model_inputs() -> None:
    _bind_cluster_state()

    vector = build_feature_vector(
        "sample.bin",
        tags=["process_exec"],
        graph_features={"risk": math.nan, "anomaly": math.inf},
        temporal_features={"belief": -math.inf},
        markov_features={"transition": math.nan, "rarity": math.inf, "pair_anomaly": -math.inf},
        engine_context={"unity": math.nan, "renpy": math.inf, "rpgm": -math.inf, "media": "not-a-number", "unknown": math.nan},
    )

    assert len(vector) == 17
    assert all(isinstance(value, float) for value in vector)
    assert all(math.isfinite(value) for value in vector)
    assert vector[5:16] == [0.0] * 11
    json.dumps({"feature_vector": vector}, allow_nan=False)


def test_stage1325_clustering_feature_vector_preserves_valid_finite_model_inputs() -> None:
    _bind_cluster_state()

    vector = build_feature_vector(
        "sample.bin",
        tags=["process_exec", "network_exfiltration"],
        graph_features={"risk": 0.25, "anomaly": 0.5},
        temporal_features={"belief": 0.75},
        markov_features={"transition": 0.4, "rarity": 0.3, "pair_anomaly": 0.2},
        engine_context={"unity": 0.9, "renpy": 0.05, "rpgm": 0.0, "media": 0.0, "unknown": 0.05},
    )

    assert vector[3:9] == [0.25, 0.5, 0.75, 0.4, 0.3, 0.2]
    assert vector[9:14] == [0.9, 0.05, 0.0, 0.0, 0.05]
    json.dumps({"feature_vector": vector}, allow_nan=False)
