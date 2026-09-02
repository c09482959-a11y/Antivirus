from Virus_Scan.tests.support.attack_mapping_contract_fixtures import unavailable_attack_mapping_fixture
from Virus_Scan.detection.chains.execution.anchors import evaluate_chain_evidence
from Virus_Scan.detection.tags.heuristics.normalization_runtime import normalize_tag_evidence
from Virus_Scan.detection.scoring.adaptive.model_score import build_probability_features
from Virus_Scan.models.graph import compute_graph_relationship_layer, get_graph_features, incremental_graph_update
from Virus_Scan.runtime.graph_state import reset_graph_state


from Virus_Scan.tests.support.canonical_chain_fixtures import physical_tag_evidence
def test_graph_features_report_unavailable_node_instead_of_bare_clean_zero():
    reset_graph_state()
    features = get_graph_features("stage1142_missing_graph_node.exe")

    assert features["risk"] == 0.0
    assert features["base_risk"] == 0.0
    assert features["anomaly"] == 0.0
    assert features["graph_features_ready"] is False
    assert features["graph_unavailable_reason"] == "graph_node_unavailable"


def test_graph_relationship_layer_carries_unavailable_evidence_for_missing_node():
    reset_graph_state()
    layer = compute_graph_relationship_layer(
        "stage1142_missing_graph_node.exe",
        tags=physical_tag_evidence(("cmd_exec",)),
    )

    assert layer["score"] == 0.0
    assert layer["graph_relationship_ready"] is False
    assert layer["graph_unavailable_reason"] == "graph_node_unavailable"
    assert layer["graph_features"]["graph_features_ready"] is False


def test_adaptive_probability_features_publish_graph_unavailable_reason():
    reset_graph_state()
    features = build_probability_features(
        attack_mapping_result=unavailable_attack_mapping_fixture(),
        chain_evidence=evaluate_chain_evidence(),
        tags=physical_tag_evidence(("cmd_exec",)),
        yara_hits=[],
        node="stage1142_missing_graph_node.exe",
        prev_stage="binary",
        curr_stage="runtime",
        ordered_events=["cmd_exec"],
    )

    assert features["p_graph"] == 0.0
    assert features["p_graph_chain"] == 0.0
    assert features["p_attention"] == 0.0
    assert features["p_graph_unavailable_reason"] == "graph_node_unavailable"


def test_graph_relationship_layer_ready_when_graph_state_exists():
    reset_graph_state()
    try:
        node = "stage1142_ready_graph_node.exe"
        tags = ["process_exec", "network_download", "cmd_exec"]
        incremental_graph_update(node, tag_evidence=physical_tag_evidence(tuple(tags)))

        layer = compute_graph_relationship_layer(node, tags=physical_tag_evidence(tuple(tags)))
        features = build_probability_features(
            attack_mapping_result=unavailable_attack_mapping_fixture(),
        chain_evidence=evaluate_chain_evidence(),
            tags=physical_tag_evidence(tuple(tags)),
            yara_hits=["GraphReadyFixture"],
            node=node,
            prev_stage="binary",
            curr_stage="runtime",
            ordered_events=tags,
        )

        assert layer["graph_relationship_ready"] is True
        assert layer["graph_unavailable_reason"] is None
        assert layer["graph_features"]["graph_features_ready"] is True
        assert features["p_graph_unavailable_reason"] is None
        assert 0.0 < features["p_graph_chain"] <= 1.0
    finally:
        reset_graph_state()
