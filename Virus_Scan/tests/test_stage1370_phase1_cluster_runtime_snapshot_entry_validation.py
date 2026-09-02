"""Stage 1370 Phase 1 current-schema cluster record entry validation."""
from __future__ import annotations

from Virus_Scan.models.api.clustering_contracts import load_cluster_runtime_model_record
from Virus_Scan.models.clustering.feature_registry import ASSIGNMENT_FEATURE_COUNT
from Virus_Scan.runtime.cluster_state import RuntimeClusterState, configure_runtime_cluster_state
from Virus_Scan.tests.support.clustering_v2 import canonical_cluster_state_payload, seed_canonical_microcluster


def _bound_seed_state() -> RuntimeClusterState:
    state = RuntimeClusterState()
    configure_runtime_cluster_state(state)
    seed_canonical_microcluster(state, "cluster-a", members=("node-a",), kind="mixed")
    return state


def test_stage1370_cluster_loader_rejects_malformed_entries_without_clearing_state() -> None:
    state = _bound_seed_state()
    payload = canonical_cluster_state_payload("cluster-b", members=("node-b",), kind="benign")
    payload["microclusters"]["cluster-b"] = "not-metadata"

    assert load_cluster_runtime_model_record(payload) is False
    assert state.node_cluster_map == {"node-a": "cluster-a"}
    assert "cluster-a" in state.cluster_signatures
    assert state.cluster_metadata["cluster-a"]["members"] == frozenset(("node-a",))


def test_stage1370_cluster_loader_accepts_valid_entries_after_identity_validation() -> None:
    state = _bound_seed_state()
    payload = canonical_cluster_state_payload("cluster-b", members=("node-b",), kind="benign")

    assert load_cluster_runtime_model_record(payload) is True
    assert state.node_cluster_map == {"node-b": "cluster-b"}
    assert len(state.cluster_signatures["cluster-b"]) == ASSIGNMENT_FEATURE_COUNT
    assert state.benign_clusters["cluster-b"] == {"node-b"}
