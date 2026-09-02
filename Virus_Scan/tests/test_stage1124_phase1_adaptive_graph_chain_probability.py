from Virus_Scan.tests.support.attack_mapping_contract_fixtures import unavailable_attack_mapping_fixture
from Virus_Scan.detection.chains.execution.anchors import evaluate_chain_evidence
from Virus_Scan.detection.tags.heuristics.normalization_runtime import normalize_tag_evidence
from Virus_Scan.detection.scoring.adaptive.model_score import build_probability_features
from Virus_Scan.models.graph import incremental_graph_update
from Virus_Scan.runtime.graph_state import reset_graph_state


from Virus_Scan.tests.support.canonical_chain_fixtures import physical_tag_evidence
def test_adaptive_probability_features_consume_graph_relationship_layer():
    reset_graph_state()
    try:
        node = "stage1124_graph_chain_sample.exe"
        tags = ["process_exec", "cmd_exec", "network_download"]
        incremental_graph_update(node, tag_evidence=physical_tag_evidence(tuple(tags)))

        features = build_probability_features(
            attack_mapping_result=unavailable_attack_mapping_fixture(),
        chain_evidence=evaluate_chain_evidence(),
            tags=physical_tag_evidence(tuple(tags)),
            yara_hits=["SuspiciousGraphFixture"],
            node=node,
            prev_stage="binary",
            curr_stage="runtime",
            ordered_events=tags,
        )

        assert 0.0 < features["p_graph_chain"] <= 1.0
        assert features["p_attention"] == features["p_graph_chain"]
        assert features["p_cluster_unavailable_reason"] in {"runtime_cluster_state_not_configured", "cluster_not_assigned"}
    finally:
        reset_graph_state()


def test_adaptive_graph_chain_probability_stays_zero_without_graph_evidence():
    reset_graph_state()
    features = build_probability_features(
        attack_mapping_result=unavailable_attack_mapping_fixture(),
        chain_evidence=evaluate_chain_evidence(),
        tags=physical_tag_evidence(("process_exec",)),
        yara_hits=[],
        node=None,
        prev_stage="binary",
        curr_stage="runtime",
        ordered_events=["process_exec"],
    )

    assert features["p_graph_chain"] == 0.0
    assert features["p_attention"] == 0.0
