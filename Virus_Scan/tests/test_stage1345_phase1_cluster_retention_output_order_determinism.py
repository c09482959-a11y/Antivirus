from __future__ import annotations

from Virus_Scan.models import clustering
from Virus_Scan.tests.support.clustering_v2 import seed_canonical_microcluster
from Virus_Scan.runtime.cluster_state import RuntimeClusterState, configure_runtime_cluster_state
from Virus_Scan.runtime.graph_state import reset_graph_state, update_graph_node_owned


def _bind_cluster_state() -> RuntimeClusterState:
    state = RuntimeClusterState()
    configure_runtime_cluster_state(state)
    return state


def _seed_node(node: str, *, last_seen: float = 10.0) -> None:
    update_graph_node_owned(node, risk=1.0, tags=set(), last_seen=last_seen)


def test_stage1345_explain_cluster_sample_nodes_are_sorted() -> None:
    reset_graph_state()
    state = _bind_cluster_state()
    cid = "stage1345_explain_cluster"
    query = "stage1345_query.exe"
    members = {
        query,
        "stage1345_zeta.exe",
        "stage1345_alpha.exe",
        "stage1345_mu.exe",
        "stage1345_beta.exe",
    }
    for node in members:
        _seed_node(node)
        state.node_cluster_map[node] = cid
    state.malicious_clusters[cid].update(members)
    state.cluster_metadata[cid] = {
        "kind": "malicious",
        "members": set(members),
        "confidence": 0.8,
        "malicious_ratio": 1.0,
        "last_updated": 10.0,
    }
    state.cluster_signatures[cid] = [1.0]

    explanation = clustering.explain_cluster(query)

    assert explanation["sample_nodes"] == tuple(sorted(members)[:10])


def test_stage1345_cluster_member_retention_uses_key_tiebreak_for_equal_age() -> None:
    reset_graph_state()
    state = _bind_cluster_state()
    cid = "stage1345_member_tie_cluster"
    members = ["stage1345_c.exe", "stage1345_a.exe", "stage1345_b.exe"]
    for node in members:
        _seed_node(node, last_seen=25.0)
    seed_canonical_microcluster(
        state, cid, members=members, kind="mixed", confidence=0.5,
        malicious_ratio=0.5, updated_ordinal=25,
    )

    clustering.prune_cluster_state_for_retention(
        max_cluster_members=2,
        max_cluster_count=10,
        max_node_cluster_map=10,
    )

    assert state.cluster_metadata[cid]["members"] == {"stage1345_a.exe", "stage1345_b.exe"}
    assert set(state.node_cluster_map) == {"stage1345_a.exe", "stage1345_b.exe"}


def test_stage1345_node_cluster_map_retention_does_not_preserve_insertion_order_ties() -> None:
    reset_graph_state()
    state = _bind_cluster_state()
    cid = "stage1345_node_map_tie_cluster"
    members = ["stage1345_x.exe", "stage1345_y.exe", "stage1345_z.exe"]
    for node in members:
        _seed_node(node, last_seen=50.0)
    seed_canonical_microcluster(
        state, cid, members=members, kind="benign", confidence=0.4,
        malicious_ratio=0.0, updated_ordinal=50,
    )

    clustering.prune_cluster_state_for_retention(
        max_cluster_members=10,
        max_cluster_count=10,
        max_node_cluster_map=2,
    )

    assert set(state.node_cluster_map) == {"stage1345_x.exe", "stage1345_y.exe"}
    assert state.cluster_metadata[cid]["members"] == {"stage1345_x.exe", "stage1345_y.exe"}
