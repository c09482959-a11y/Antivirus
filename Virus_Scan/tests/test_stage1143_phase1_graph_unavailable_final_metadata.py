from Virus_Scan.tests.support.adaptive_chain_fixtures import adaptive_chain_evidence_fixture
from Virus_Scan.tests.support.attack_mapping_contract_fixtures import unavailable_attack_mapping_fixture
from Virus_Scan.detection.tags.heuristics.normalization_runtime import normalize_tag_evidence
from Virus_Scan.detection.scoring.adaptive.model_score import calibrated_log_odds_score_100
from Virus_Scan.models.graph import incremental_graph_update
from Virus_Scan.runtime.graph_state import reset_graph_state


from Virus_Scan.tests.support.canonical_chain_fixtures import physical_tag_evidence
def test_log_odds_metadata_preserves_graph_unavailable_reason_for_missing_node():
    reset_graph_state()
    try:
        _score, meta = calibrated_log_odds_score_100(
            20.0,
            attack_mapping_result=unavailable_attack_mapping_fixture(),
            chain_evidence=adaptive_chain_evidence_fixture(tags=physical_tag_evidence(("cmd_exec",)), api_calls=None, ordered_events=["cmd_exec"]),
            tags=physical_tag_evidence(("cmd_exec",)),
            yara_hits=[],
            node="stage1143_missing_graph_node.exe",
            prev_stage="binary",
            curr_stage="runtime",
            ordered_events=["cmd_exec"],
        )

        features = meta["feature_probabilities"]
        assert features["graph"] == 0.0
        assert features["graph_chain"] == 0.0
        assert features["attention"] == 0.0
        assert features["graph_unavailable_reason"] == "graph_node_unavailable"
    finally:
        reset_graph_state()


def test_log_odds_metadata_clears_graph_unavailable_reason_when_graph_ready():
    reset_graph_state()
    try:
        node = "stage1143_ready_graph_node.exe"
        tags = ["process_exec", "network_download", "cmd_exec"]
        incremental_graph_update(node, tag_evidence=physical_tag_evidence(tuple(tags)))

        _score, meta = calibrated_log_odds_score_100(
            35.0,
            attack_mapping_result=unavailable_attack_mapping_fixture(),
            chain_evidence=adaptive_chain_evidence_fixture(tags=physical_tag_evidence(tuple(tags)), api_calls=None, ordered_events=tags),
            tags=physical_tag_evidence(tuple(tags)),
            yara_hits=["Stage1143GraphRule"],
            node=node,
            prev_stage="binary",
            curr_stage="runtime",
            ordered_events=tags,
        )

        features = meta["feature_probabilities"]
        assert features["graph_unavailable_reason"] is None
        assert 0.0 < features["graph_chain"] <= 1.0
        assert features["attention"] == features["graph_chain"]
    finally:
        reset_graph_state()
