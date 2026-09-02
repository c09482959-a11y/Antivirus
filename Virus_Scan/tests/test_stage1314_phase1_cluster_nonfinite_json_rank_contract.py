from __future__ import annotations

import math

from Virus_Scan.models import clustering
from Virus_Scan.models.clustering.microcluster import microcluster_with_fields
from Virus_Scan.tests.support.clustering_v2 import seed_canonical_microcluster
from Virus_Scan.runtime.cluster_state import (
    RuntimeClusterState,
    configure_runtime_cluster_state,
    runtime_cluster_state_to_json,
)


def _assert_no_nonfinite(value):
    if isinstance(value, float):
        assert math.isfinite(value)
    elif isinstance(value, dict):
        for child in value.values():
            _assert_no_nonfinite(child)
    elif isinstance(value, (list, tuple)):
        for child in value:
            _assert_no_nonfinite(child)


def test_stage1314_runtime_cluster_json_sanitizes_nonfinite_model_values() -> None:
    state = RuntimeClusterState()
    state.cluster_signatures["cluster-corrupt"] = [1.0, float("nan"), float("inf"), float("-inf")]
    state.cluster_metadata["cluster-corrupt"] = {
        "confidence": float("inf"),
        "malicious_ratio": float("nan"),
        "samples": float("inf"),
        "last_updated": float("inf"),
        "centroid_vector": [float("nan"), 2.0],
        "scores": [float("nan"), float("inf"), 0.25],
        "nested": {"score": float("nan"), "kept": "value"},
    }
    configure_runtime_cluster_state(state)

    snapshot = runtime_cluster_state_to_json()

    assert "cluster_signatures" not in snapshot
    metadata = snapshot["microclusters"]["cluster-corrupt"]
    assert metadata["confidence"] == 0.0
    assert metadata["malicious_ratio"] == 0.0
    assert metadata["samples"] == 0.0
    assert metadata["last_updated"] == 0.0
    assert metadata["centroid_vector"] == [0.0, 2.0]
    assert metadata["scores"] == [0.0, 0.0, 0.25]
    assert metadata["nested"] == {"score": 0.0, "kept": "value"}
    _assert_no_nonfinite(snapshot)


def test_stage1314_cluster_retention_rank_does_not_promote_nonfinite_last_updated() -> None:
    state = RuntimeClusterState()
    configure_runtime_cluster_state(state)
    seed_canonical_microcluster(
        state, "fresh-valid", members=("valid.node",), kind="mixed",
        confidence=0.5, malicious_ratio=0.0, updated_ordinal=10,
    )
    corrupt = seed_canonical_microcluster(
        state, "corrupt-time", members=("corrupt.node",), kind="mixed",
        confidence=0.5, malicious_ratio=0.0, updated_ordinal=1,
    )
    state.cluster_metadata["corrupt-time"] = microcluster_with_fields(
        corrupt, updated_ordinal=float("inf"), last_updated=float("inf"),
    )

    clustering.prune_cluster_state_for_retention(
        max_cluster_members=10,
        max_cluster_count=1,
        max_node_cluster_map=10,
    )

    assert set(state.cluster_metadata) == {"fresh-valid"}
    assert state.node_cluster_map == {"valid.node": "fresh-valid"}
