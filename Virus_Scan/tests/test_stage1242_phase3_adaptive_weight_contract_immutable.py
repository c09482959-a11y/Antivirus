from __future__ import annotations
from Virus_Scan.tests.support.adaptive_chain_fixtures import adaptive_chain_evidence_fixture
from Virus_Scan.tests.support.attack_mapping_contract_fixtures import unavailable_attack_mapping_fixture

from collections.abc import Mapping

import pytest

from Virus_Scan.detection.scoring.adaptive.model_score import (
    ADAPTIVE_LEARNED_MODEL_STATIC_VERSION,
    adaptive_learned_model_weight_from_confidence,
    calibrated_log_odds_score_100,
)
from Virus_Scan.models.contracts.model_feature_bundle import materialize_model_feature_bundle


def test_stage1242_adaptive_weight_record_is_immutable_feature_bundle() -> None:
    weights = adaptive_learned_model_weight_from_confidence(
        0.25,
        concrete_count=0,
        profile_files_seen=0,
        static_anchor_score=50.0,
    )

    assert isinstance(weights, Mapping)
    assert not isinstance(weights, dict)
    assert weights["model_version"] == ADAPTIVE_LEARNED_MODEL_STATIC_VERSION
    assert weights["version"] == ADAPTIVE_LEARNED_MODEL_STATIC_VERSION
    assert weights["caps_applied"] == (
        "no_concrete_static_anchors",
        "static_anchor_overrides_weak_model",
    )
    with pytest.raises(TypeError):
        weights["learned_model_weight"] = 1.0


def test_stage1242_adaptive_weight_record_materializes_deterministically() -> None:
    weights = adaptive_learned_model_weight_from_confidence(
        0.8,
        concrete_count=1,
        profile_files_seen=1,
        static_anchor_score=20.0,
    )

    first = materialize_model_feature_bundle(weights)
    second = materialize_model_feature_bundle(weights)

    assert first == second
    assert tuple(first) == tuple(sorted(first))
    assert first["caps_applied"] == (
        "immature_profile_history",
        "single_concrete_anchor",
    )


def test_stage1242_log_odds_accepts_immutable_rolling_weight_meta() -> None:
    rolling = adaptive_learned_model_weight_from_confidence(
        0.4,
        concrete_count=2,
        profile_files_seen=5,
        static_anchor_score=10.0,
    )

    score, meta = calibrated_log_odds_score_100(
        10.0,
        attack_mapping_result=unavailable_attack_mapping_fixture(),
        chain_evidence=adaptive_chain_evidence_fixture(tags=[], api_calls=None, ordered_events=None),
        tags=[],
        yara_hits=[],
        adaptive_learning={"rolling_learned_static": rolling},
    )

    assert 0.0 <= score <= 100.0
    assert 0.0 <= meta["model_weight"] <= 1.0
    assert 0.0 <= meta["static_weight"] <= 1.0
