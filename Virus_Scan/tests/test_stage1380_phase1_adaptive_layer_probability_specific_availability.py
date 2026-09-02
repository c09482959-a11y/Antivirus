"""Stage 1380 Phase 1 adaptive layer-probability specific availability keys."""
from __future__ import annotations
from Virus_Scan.tests.support.adaptive_chain_fixtures import adaptive_chain_evidence_fixture
from Virus_Scan.tests.support.attack_mapping_contract_fixtures import unavailable_attack_mapping_fixture

from Virus_Scan.detection.scoring.adaptive.model_score import calibrated_log_odds_score_100


def test_stage1380_quick_static_specific_unavailable_reason_blocks_probability() -> None:
    unavailable_score, unavailable_meta = calibrated_log_odds_score_100(
        0.0,
        attack_mapping_result=unavailable_attack_mapping_fixture(),
        chain_evidence=adaptive_chain_evidence_fixture(tags=[], api_calls=None, ordered_events=None),
        tags=[],
        yara_hits=[],
        node=None,
        layers={"quick": {"score": 100.0, "quick_static_unavailable_reason": "quick_snapshot_missing"}},
    )
    clean_score, clean_meta = calibrated_log_odds_score_100(
        0.0,
        attack_mapping_result=unavailable_attack_mapping_fixture(),
        chain_evidence=adaptive_chain_evidence_fixture(tags=[], api_calls=None, ordered_events=None),
        tags=[],
        yara_hits=[],
        node=None,
        layers={"quick": {"score": 100.0}},
    )

    assert unavailable_meta["static_probability"] < clean_meta["static_probability"]
    assert unavailable_score < clean_score
    assert unavailable_meta["layer_probability_unavailable_reasons"] == {
        "quick_static": "quick_snapshot_missing"
    }


def test_stage1380_stage_timeline_specific_unavailable_reason_blocks_probability() -> None:
    unavailable_score, unavailable_meta = calibrated_log_odds_score_100(
        0.0,
        attack_mapping_result=unavailable_attack_mapping_fixture(),
        chain_evidence=adaptive_chain_evidence_fixture(tags=[], api_calls=None, ordered_events=None),
        tags=[],
        yara_hits=[],
        node=None,
        layers={"stage": {"score": 100.0, "stage_timeline_unavailable_reason": "timeline_snapshot_missing"}},
    )
    clean_score, clean_meta = calibrated_log_odds_score_100(
        0.0,
        attack_mapping_result=unavailable_attack_mapping_fixture(),
        chain_evidence=adaptive_chain_evidence_fixture(tags=[], api_calls=None, ordered_events=None),
        tags=[],
        yara_hits=[],
        node=None,
        layers={"stage": {"score": 100.0}},
    )

    assert unavailable_meta["model_probability"] <= clean_meta["model_probability"]
    assert unavailable_score <= clean_score
    assert unavailable_meta["layer_probability_unavailable_reasons"] == {
        "stage_timeline": "timeline_snapshot_missing"
    }
