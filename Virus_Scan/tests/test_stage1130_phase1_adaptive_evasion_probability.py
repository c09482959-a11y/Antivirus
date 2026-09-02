from Virus_Scan.tests.support.adaptive_chain_fixtures import adaptive_chain_evidence_fixture
from Virus_Scan.tests.support.attack_mapping_contract_fixtures import unavailable_attack_mapping_fixture
from Virus_Scan.detection.chains.execution.anchors import evaluate_chain_evidence
from Virus_Scan.detection.tags.heuristics.normalization_runtime import normalize_tag_evidence
from pathlib import Path

from Virus_Scan.detection.scoring.adaptive import evidence_projection
from Virus_Scan.detection.scoring.adaptive.model_score import build_probability_features


from Virus_Scan.tests.support.canonical_chain_fixtures import physical_tag_evidence
def test_stage1130_adaptive_evasion_probability_uses_detection_evidence():
    features = build_probability_features(
        attack_mapping_result=unavailable_attack_mapping_fixture(),
        chain_evidence=evaluate_chain_evidence(),
        tags=physical_tag_evidence(("defense_evasion", "amsi_bypass_attempt", "packed_or_obfuscated", "process_exec")),
        yara_hits=[],
        node={"path": "stage1130_evasion_sample.exe"},
        prev_stage="binary",
        curr_stage="runtime",
        ordered_events=["defense_evasion", "process_exec"],
    )

    assert 0.0 < features["p_evasion"] <= 1.0


def test_stage1130_adaptive_evasion_probability_is_not_dead_zero_stub():
    source = Path(evidence_projection.__file__).read_text(encoding="utf-8")

    assert "p_evasion = 0.0\n    except" not in source
    assert "detect_evasion_signals" in source

from Virus_Scan.detection.scoring.adaptive.model_score import calibrated_log_odds_score_100
from Virus_Scan.models.graph import incremental_graph_update
from Virus_Scan.runtime.graph_state import reset_graph_state


def test_stage1130_log_odds_metadata_records_graph_chain_and_cluster_unavailability():
    reset_graph_state()
    try:
        node = "stage1130_graph_chain_meta.exe"
        tags = ["process_exec", "cmd_exec", "network_download"]
        incremental_graph_update(node, tag_evidence=physical_tag_evidence(tuple(tags)))

        _score, meta = calibrated_log_odds_score_100(
            35.0,
            attack_mapping_result=unavailable_attack_mapping_fixture(),
            chain_evidence=adaptive_chain_evidence_fixture(tags=physical_tag_evidence(tuple(tags)), api_calls=None, ordered_events=tags),
            tags=physical_tag_evidence(tuple(tags)),
            yara_hits=["Stage1130GraphRule"],
            node=node,
            prev_stage="binary",
            curr_stage="runtime",
            ordered_events=tags,
        )

        features = meta["feature_probabilities"]
        assert 0.0 < features["graph_chain"] <= 1.0
        assert features["attention"] == features["graph_chain"]
        assert features["cluster_unavailable_reason"] in {
            "runtime_cluster_state_not_configured",
            "cluster_not_assigned",
            None,
        }
    finally:
        reset_graph_state()
