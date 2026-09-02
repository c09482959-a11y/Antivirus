from __future__ import annotations


from Virus_Scan.models.api.clustering_contracts import load_cluster_runtime_model_record
from Virus_Scan.models.clustering.anomaly import cluster_anomaly_boost_evidence
from Virus_Scan.models.clustering.feature_registry import ASSIGNMENT_FEATURE_COUNT
from Virus_Scan.tests.support.clustering_v2 import canonical_cluster_state_payload, seed_canonical_microcluster
from Virus_Scan.runtime.cluster_state import (
    RuntimeClusterState,
    configure_runtime_cluster_state,
    runtime_cluster_state_to_json,
)
from Virus_Scan.runtime.graph_state import graph_vector_node_key, reset_graph_state


class _HostileBoolVector(list):
    def __bool__(self) -> bool:  # pragma: no cover - failure path assertion
        raise AssertionError("clustering code must not truth-test caller-owned vectors")


class _HostileBoolDict(dict):
    def __bool__(self) -> bool:  # pragma: no cover - failure path assertion
        raise AssertionError("clustering code must not truth-test caller-owned mappings")



def _bind_cluster_state() -> RuntimeClusterState:
    state = RuntimeClusterState()
    configure_runtime_cluster_state(state)
    return state


def test_stage1484_cluster_anomaly_uses_vector_snapshots_without_truthiness() -> None:
    reset_graph_state()
    try:
        state = _bind_cluster_state()
        node = "stage1484_payload.exe"
        node_key = graph_vector_node_key(node)
        cid = "stage1484_cluster"
        snapshot = seed_canonical_microcluster(
            state, cid, members=(node_key, "stage1484-peer.exe"), kind="malicious",
            confidence=0.75, malicious_ratio=1.0, trusted_sample_count=3,
            influence_enabled=True,
        )
        centroid = list(snapshot["centroid_vector"])
        state.cluster_signatures[cid] = _HostileBoolVector(centroid)
        altered = list(centroid)
        altered[0] = -altered[0] if altered[0] != 0.0 else 1.0
        state.node_feature_vectors[node_key] = _HostileBoolVector(altered)

        evidence = cluster_anomaly_boost_evidence(node)

        assert evidence["cluster_anomaly_boost"] == 0.0
        assert evidence["cluster_anomaly_ready"] is False
        assert evidence["cluster_unavailable_reason"] == "cluster_vector_unavailable"
    finally:
        reset_graph_state()


def test_stage1484_runtime_cluster_json_uses_explicit_missing_checks() -> None:
    state = _bind_cluster_state()
    cid = "stage1484-json-cluster"
    state.cluster_signatures[cid] = _HostileBoolVector([1.0, 2.0])
    state.cluster_metadata[cid] = _HostileBoolDict(
        {
            "confidence": 0.25,
            "malicious_ratio": 0.5,
            "samples": 3,
            "last_updated": 4.0,
            "centroid_vector": _HostileBoolVector([1.0, 2.0]),
        }
    )

    snapshot = runtime_cluster_state_to_json()

    assert "cluster_signatures" not in snapshot
    assert snapshot["microclusters"][cid]["centroid_vector"] == [1.0, 2.0]



def test_stage1484_cluster_current_record_loader_preserves_exact_owned_values() -> None:
    state = _bind_cluster_state()
    payload = canonical_cluster_state_payload(
        "stage1484-loaded", members=("stage1484-node",), kind="mixed",
        tags=("stage1484_tag",), trusted_sample_count=3,
    )
    assert load_cluster_runtime_model_record(payload) is True
    assert len(state.cluster_signatures["stage1484-loaded"]) == ASSIGNMENT_FEATURE_COUNT
    assert len(state.node_feature_vectors["stage1484-node"]) == ASSIGNMENT_FEATURE_COUNT
