from __future__ import annotations

from Virus_Scan.models import clustering
from Virus_Scan.runtime.cluster_state import RuntimeClusterState, cluster_state, configure_runtime_cluster_state


def _retained_nodes_after_prune(order: tuple[str, ...]) -> tuple[str, ...]:
    configure_runtime_cluster_state(RuntimeClusterState())
    for idx, node in enumerate(order):
        cluster_state().node_feature_vectors[node] = [float(idx + 1)]
    clustering.prune_node_feature_vectors(max_items=2)
    return tuple(sorted(cluster_state().node_feature_vectors.keys()))


def test_stage1393_node_feature_vector_retention_is_input_order_deterministic() -> None:
    first = _retained_nodes_after_prune(("node-c", "node-a", "node-b"))
    second = _retained_nodes_after_prune(("node-b", "node-c", "node-a"))

    assert first == second
    assert first == ("node-a", "node-b")


def test_stage1393_store_node_vector_returns_detached_sanitized_copy() -> None:
    configure_runtime_cluster_state(RuntimeClusterState())

    returned = clustering.store_node_vector("node-a", [1.0, "2", float("nan")])

    assert returned == []
    assert "node-a" not in cluster_state().node_feature_vectors
