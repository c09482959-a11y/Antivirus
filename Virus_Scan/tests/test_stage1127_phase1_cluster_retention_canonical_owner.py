from __future__ import annotations

from Virus_Scan.models import clustering, retention
from Virus_Scan.runtime.cluster_state import RuntimeClusterState, configure_runtime_cluster_state
from Virus_Scan.tests.support.clustering_v2 import seed_canonical_microcluster


def test_cluster_retention_has_single_canonical_model_owner():
    assert hasattr(clustering, "prune_cluster_state_for_retention")
    assert "prune_cluster_state_for_retention" not in retention.__all__
    assert not hasattr(retention, "prune_cluster_state_for_retention")


def test_cluster_retention_canonical_owner_prunes_with_bound_runtime_state():
    state = RuntimeClusterState()
    configure_runtime_cluster_state(state)
    seed_canonical_microcluster(
        state, "c1", members=("n1", "n2"), kind="malicious", confidence=0.8,
        malicious_ratio=1.0, trusted_sample_count=3, updated_ordinal=20,
    )
    seed_canonical_microcluster(
        state, "c2", members=("n3",), kind="benign", confidence=0.3,
        malicious_ratio=0.0, trusted_sample_count=3, updated_ordinal=10,
    )

    returned = clustering.prune_cluster_state_for_retention(
        max_cluster_members=1,
        max_cluster_count=1,
        max_node_cluster_map=2,
    )

    assert returned is None
    assert set(state.cluster_metadata) == {"c1"}
    assert len(state.malicious_clusters["c1"]) == 1
    assert set(state.node_cluster_map.values()) <= {"c1"}
