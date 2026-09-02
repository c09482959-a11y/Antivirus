from __future__ import annotations

from Virus_Scan.models.graph import (
    propagate_cluster_influence,
    reinforce_cluster_with_graph,
    reinforce_graph_with_cluster,
)
from Virus_Scan.runtime.cluster_state import RuntimeClusterState, configure_runtime_cluster_state
from Virus_Scan.runtime.graph_state import graph_node_snapshot, graph_vector_node_key, reset_graph_state, update_graph_node_owned


def _bind_cluster_state() -> RuntimeClusterState:
    state = RuntimeClusterState()
    configure_runtime_cluster_state(state)
    return state


def _seed_runtime_cluster(state: RuntimeClusterState, node: str) -> tuple[str, str, set[str]]:
    node_key = graph_vector_node_key(node)
    cid = "stage1336_benign_runtime_cluster"
    peers = {node_key, "stage1336_peer_a.asset", "stage1336_peer_b.asset"}
    state.node_cluster_map[node_key] = cid
    state.benign_clusters[cid].update(peers)
    state.cluster_metadata[cid] = {
        "kind": "benign",
        "members": set(peers),
        "benign_ratio": 1.0,
        "confidence": 0.75,
        "samples": len(peers),
    }
    return node_key, cid, peers


def test_stage1336_graph_reinforcement_reads_runtime_cluster_state() -> None:
    reset_graph_state()
    try:
        state = _bind_cluster_state()
        node = "stage1336_graph_cluster.exe"
        _node_key, cid, peers = _seed_runtime_cluster(state, node)
        update_graph_node_owned(node, risk=20.0, tags={"benign_asset"})

        result = reinforce_graph_with_cluster(node)

        assert result["reinforced"] is True
        assert result["cluster"] == cid
        assert result["confidence"] > 0.0
        snapshot = graph_node_snapshot(node)
        assert snapshot is not None
        assert f"cluster:{cid}" in snapshot["edges"]
        assert len(peers) >= 3
    finally:
        reset_graph_state()


def test_stage1336_graph_cluster_feedback_reads_runtime_cluster_state() -> None:
    reset_graph_state()
    try:
        state = _bind_cluster_state()
        node = "stage1336_graph_feedback.exe"
        _node_key, cid, _peers = _seed_runtime_cluster(state, node)
        update_graph_node_owned(node, risk=30.0, tags={"benign_asset"})

        result = reinforce_cluster_with_graph(node)

        assert result["reinforced"] is True
        assert result["cluster"] == cid
        cluster_snapshot = graph_node_snapshot(f"cluster:{cid}")
        assert cluster_snapshot is not None
        assert node in cluster_snapshot["edges"]
    finally:
        reset_graph_state()


def test_stage1336_cluster_influence_uses_runtime_members_not_static_config() -> None:
    reset_graph_state()
    try:
        state = _bind_cluster_state()
        node = "stage1336_graph_influence.exe"
        _node_key, cid, peers = _seed_runtime_cluster(state, node)
        update_graph_node_owned(node, risk=10.0, tags={"benign_asset"})

        propagate_cluster_influence(node, tags={"benign_asset"})

        snapshot = graph_node_snapshot(node)
        assert snapshot is not None
        assert f"cluster:{cid}" in snapshot["edges"]
        peer_edges = [edge for edge in snapshot["edges"] if str(edge).startswith("cluster_peer:")]
        assert peer_edges
        assert len(peers) >= 3
    finally:
        reset_graph_state()
