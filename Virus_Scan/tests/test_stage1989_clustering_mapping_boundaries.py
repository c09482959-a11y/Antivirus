from __future__ import annotations

from pathlib import Path

from Virus_Scan.models import clustering
from Virus_Scan.models.api.clustering_contracts import load_cluster_runtime_model_record
from Virus_Scan.tests.support.clustering_v2 import canonical_cluster_state_payload, seed_canonical_microcluster
from Virus_Scan.runtime.cluster_state import RuntimeClusterState, configure_runtime_cluster_state
from Virus_Scan.runtime.graph_state import reset_graph_state, update_graph_node_owned


def test_stage1989_cluster_retention_and_risk_use_owned_mapping_boundaries() -> None:
    reset_graph_state()
    try:
        state = RuntimeClusterState()
        configure_runtime_cluster_state(state)
        seed_canonical_microcluster(
            state, "stage1989-c1",
            members=("stage1989-node-a", "stage1989-node-b"),
            kind="malicious", tags=("process_injection",),
            malicious_ratio=0.8, confidence=0.7, trusted_sample_count=3,
            updated_ordinal=10, influence_enabled=True,
        )
        update_graph_node_owned("stage1989-node-a", risk=80.0, tags={"process_injection"}, metadata={"last_seen": 10.0})
        update_graph_node_owned("stage1989-node-b", risk=50.0, tags={"network_exfiltration"}, metadata={"last_seen": 9.0})

        clustering.prune_cluster_state_for_retention(
            max_cluster_members=2,
            max_cluster_count=4,
            max_node_cluster_map=4,
        )
        evidence = clustering.cluster_risk_score_evidence("stage1989-node-a")

        assert set(state.node_cluster_map.values()) == {"stage1989-c1"}
        assert state.cluster_tag_signatures["stage1989-c1"] == {"process_injection"}
        assert evidence["ready"] is True
        assert evidence["degraded"] is False
        assert evidence["risk"] > 0.0
    finally:
        reset_graph_state()


def test_stage1989_cluster_current_record_load_uses_owned_mapping_items() -> None:
    state = RuntimeClusterState()
    configure_runtime_cluster_state(state)
    payload = canonical_cluster_state_payload(
        "stage1989-c2", members=("stage1989-node-c",), kind="benign",
        tags=("image_asset",), malicious_ratio=0.0, trusted_sample_count=3,
    )
    assert load_cluster_runtime_model_record(payload) is True
    assert state.node_cluster_map == {"stage1989-node-c": "stage1989-c2"}
    assert state.benign_clusters == {"stage1989-c2": {"stage1989-node-c"}}
    assert state.cluster_tag_signatures["stage1989-c2"] == {"image_asset"}


def test_stage1989_clustering_sources_do_not_reintroduce_mapping_hook_patterns() -> None:
    root = Path(__file__).resolve().parents[2]
    forbidden_by_file = {
        "Virus_Scan/models/clustering/retention.py": (
            "node_cluster_map().items()",
            "node_cluster_map().keys()",
            "list(node_cluster_map().items())",
            "list(node_cluster_map().keys())",
            ".metadata.get('last_seen'",
        ),
        "Virus_Scan/models/clustering/risk.py": (
            "weighted_graph += w * safe_clamp(edge_score + node_risk + tag_risk)",
            "graph_component = safe_clamp(weighted_graph / max(1e-06, total_weight))",
            "meta.get('malicious_ratio'",
            "meta.get('confidence'",
            "cluster_risk_score_evidence(node).get('risk'",
        ),
        "Virus_Scan/models/clustering/snapshots.py": (
            "signatures.items()",
            "metadata.items()",
            "node_map.items()",
            "node_vectors.items()",
            "list(cluster_metadata().items())",
            "log_error(f'runtime cluster state load",
            "f'non_mapping_cluster_state_",
            "f'invalidcluster_metadata_",
        ),
    }
    for relative_path, patterns in forbidden_by_file.items():
        source = (root / relative_path).read_text(encoding="utf-8")
        for pattern in patterns:
            assert pattern not in source, f"{relative_path} still contains {pattern}"
