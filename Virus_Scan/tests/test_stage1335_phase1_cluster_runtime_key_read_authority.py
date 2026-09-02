from __future__ import annotations
from Virus_Scan.tests.support.attack_mapping_contract_fixtures import unavailable_attack_mapping_fixture
from Virus_Scan.detection.chains.execution.anchors import evaluate_chain_evidence

from Virus_Scan.detection.scoring.adaptive.model_score import build_probability_features
from Virus_Scan.models import clustering
from Virus_Scan.tests.support.clustering_v2 import seed_canonical_microcluster
from Virus_Scan.runtime.cluster_state import RuntimeClusterState, configure_runtime_cluster_state
from Virus_Scan.runtime.graph_state import graph_vector_node_key, reset_graph_state, update_graph_node_owned


from Virus_Scan.tests.support.canonical_chain_fixtures import physical_tag_evidence
def _bind_cluster_state() -> RuntimeClusterState:
    state = RuntimeClusterState()
    configure_runtime_cluster_state(state)
    return state


def _seed_cluster(state: RuntimeClusterState, raw_node: str) -> tuple[str, str]:
    node_key = graph_vector_node_key(raw_node)
    peers = ("stage1335_peer.exe", "stage1335_peer_2.exe")
    cid = "stage1335_malicious_cluster"
    snapshot = seed_canonical_microcluster(
        state, cid, members=(node_key, *peers), kind="malicious",
        tags=("process_injection", "network_exfiltration"), confidence=0.8,
        malicious_ratio=1.0, trusted_sample_count=3, influence_enabled=True,
    )
    altered = list(snapshot["centroid_vector"])
    altered[3] = 0.0 if altered[3] > 0.0 else 1.0
    state.node_feature_vectors[node_key] = altered
    update_graph_node_owned(node_key, risk=80.0, tags={"process_injection"})
    update_graph_node_owned(peers[0], risk=60.0, tags={"network_exfiltration"})
    update_graph_node_owned(peers[1], risk=55.0, tags={"process_injection"})
    return node_key, cid


def test_stage1335_cluster_read_apis_use_canonical_runtime_key() -> None:
    reset_graph_state()
    try:
        state = _bind_cluster_state()
        raw_node = "  stage1335_sample.exe  "
        _node_key, cid = _seed_cluster(state, raw_node)

        risk = clustering.cluster_risk_score(raw_node)
        anomaly = clustering.cluster_anomaly_boost(raw_node)
        explanation = clustering.explain_cluster(raw_node)
        quality = clustering.context_cluster_quality(raw_node, physical_tag_evidence(("process_injection",)))

        assert risk > 0.0
        assert anomaly > 0.0
        assert explanation["cluster"] == cid
        assert quality["eligible"] is True
        assert quality["cluster_id"] == cid
    finally:
        reset_graph_state()


def test_stage1335_adaptive_probability_cluster_feature_uses_canonical_runtime_key() -> None:
    reset_graph_state()
    try:
        state = _bind_cluster_state()
        raw_node = "  stage1335_probability_sample.exe  "
        _node_key, _cid = _seed_cluster(state, raw_node)

        features = build_probability_features(
            attack_mapping_result=unavailable_attack_mapping_fixture(),
        chain_evidence=evaluate_chain_evidence(),
            tags=physical_tag_evidence(("process_injection", "network_exfiltration")),
            yara_hits=[],
            node=raw_node,
            prev_stage="binary",
            curr_stage="runtime",
            ordered_events=["process_injection", "network_exfiltration"],
        )

        assert features["p_cluster"] > 0.0
        assert features["p_cluster_unavailable_reason"] is None
    finally:
        reset_graph_state()
