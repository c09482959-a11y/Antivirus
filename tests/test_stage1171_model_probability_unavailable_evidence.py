from Virus_Scan.tests.support.attack_mapping_contract_fixtures import unavailable_attack_mapping_fixture
from Virus_Scan.detection.chains.execution.anchors import evaluate_chain_evidence
from Virus_Scan.detection.scoring.adaptive.model_score import build_probability_features


def test_stage1171_probability_features_explain_missing_model_nodes():
    features = build_probability_features(
        attack_mapping_result=unavailable_attack_mapping_fixture(),
        chain_evidence=evaluate_chain_evidence(),
        tags=["contextual_identity"],
        yara_hits=[],
        node=None,
        prev_stage="unknown",
        curr_stage="unknown",
        ordered_events=[],
    )

    assert features["p_temporal"] == 0.0
    assert features["p_temporal_unavailable_reason"] == "temporal_node_not_provided"
    assert features["p_cluster"] == 0.0
    assert features["p_cluster_unavailable_reason"] == "cluster_node_not_provided"
    assert features["p_graph"] == 0.0
    assert features["p_graph_unavailable_reason"] == "graph_node_not_provided"
