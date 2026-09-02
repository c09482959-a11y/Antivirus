"""Stage 1371 clustering current-schema nested-shape validation."""
from __future__ import annotations

from Virus_Scan.models.api.clustering_contracts import load_cluster_runtime_model_record
from Virus_Scan.runtime.cluster_state import RuntimeClusterState, configure_runtime_cluster_state
from Virus_Scan.tests.support.clustering_v2 import canonical_cluster_state_payload, seed_canonical_microcluster


def _seed_state() -> RuntimeClusterState:
    state = RuntimeClusterState()
    configure_runtime_cluster_state(state)
    seed_canonical_microcluster(state, "cluster-a", members=("node-a",), kind="mixed", trusted_sample_count=3)
    return state


def _valid_payload() -> dict[str, object]:
    return canonical_cluster_state_payload(
        "cluster-b", members=("node-b",), kind="benign", tags=("tag-b",),
        chains=("chain-b",), behaviors=("behavior-b",), trusted_sample_count=3,
    )


def _assert_original_state_preserved(state: RuntimeClusterState) -> None:
    assert state.node_cluster_map == {"node-a": "cluster-a"}
    assert set(state.cluster_signatures) == {"cluster-a"}
    assert state.cluster_metadata["cluster-a"]["members"] == frozenset({"node-a"})
    assert state.mixed_clusters["cluster-a"] == {"node-a"}


def test_stage1371_cluster_loader_rejects_scalar_metadata_members_without_clearing_state() -> None:
    state = _seed_state(); payload = _valid_payload(); payload["microclusters"]["cluster-b"]["members"] = 5
    assert load_cluster_runtime_model_record(payload) is False
    _assert_original_state_preserved(state)


def test_stage1371_cluster_loader_rejects_scalar_signature_metadata_without_clearing_state() -> None:
    state = _seed_state(); payload = _valid_payload(); payload["microclusters"]["cluster-b"]["tag_signature"] = "not-a-sequence"
    assert load_cluster_runtime_model_record(payload) is False
    _assert_original_state_preserved(state)


def test_stage1371_cluster_loader_rejects_malformed_metadata_centroid_without_clearing_state() -> None:
    state = _seed_state(); payload = _valid_payload(); payload["microclusters"]["cluster-b"]["centroid_vector"] = "abc"
    assert load_cluster_runtime_model_record(payload) is False
    _assert_original_state_preserved(state)


def test_stage1371_cluster_loader_accepts_valid_nested_metadata() -> None:
    state = _seed_state()
    assert load_cluster_runtime_model_record(_valid_payload()) is True
    assert state.node_cluster_map == {"node-b": "cluster-b"}
    assert state.cluster_metadata["cluster-b"]["members"] == frozenset({"node-b"})
    assert state.cluster_metadata["cluster-b"]["tag_signature"] == frozenset({"tag-b"})
    assert state.benign_clusters["cluster-b"] == {"node-b"}


def test_stage1371_cluster_loader_rejects_nonnumeric_signature_vector_without_clearing_state() -> None:
    state = _seed_state(); payload = _valid_payload(); payload["microclusters"]["cluster-b"]["centroid_vector"][0] = "not-a-number"
    assert load_cluster_runtime_model_record(payload) is False
    _assert_original_state_preserved(state)


def test_stage1371_cluster_loader_rejects_nonnumeric_node_vector_without_clearing_state() -> None:
    state = _seed_state(); payload = _valid_payload(); payload["node_feature_vectors"]["node-b"][0] = "not-a-number"
    assert load_cluster_runtime_model_record(payload) is False
    _assert_original_state_preserved(state)


def test_stage1371_cluster_loader_rejects_nonfinite_vectors_without_clearing_state() -> None:
    state = _seed_state(); payload = _valid_payload(); payload["node_feature_vectors"]["node-b"][0] = float("inf")
    assert load_cluster_runtime_model_record(payload) is False
    _assert_original_state_preserved(state)
