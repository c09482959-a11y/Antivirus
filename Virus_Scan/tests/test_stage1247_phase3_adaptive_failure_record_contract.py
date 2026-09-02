from __future__ import annotations
from Virus_Scan.tests.support.adaptive_chain_fixtures import adaptive_chain_evidence_fixture
from Virus_Scan.tests.support.attack_mapping_contract_fixtures import unavailable_attack_mapping_fixture
from Virus_Scan.detection.scoring.adaptive.log_odds_probabilities import LogOddsFeatureProbabilitiesRequest

import json
from collections.abc import Mapping

import pytest

from Virus_Scan.detection.scoring.adaptive.model_score import (
    log_odds_feature_probabilities,
    probability_feature_build_failed_bundle,
    calibrated_log_odds_score_100,
)
from Virus_Scan.models.contracts.model_failure import (
    make_cold_start_record,
    make_model_failure_record,
    materialize_model_failure_record,
)
from Virus_Scan.models.contracts.model_feature_bundle import materialize_model_feature_bundle


def test_stage1247_model_failure_records_are_immutable_and_deterministic() -> None:
    details = {"paths": ["b", "a"], "nested": {"tags": {"z", "a"}}}
    failure = make_model_failure_record(
        model_name="adaptive_probability_features",
        failure_type="feature_build_failed",
        reason="probability_feature_build_failed",
        affected_fields={"p_markov", "p_graph", "p_temporal"},
        details=details,
        model_version="stage1247_failure_contract_v1",
    )

    assert isinstance(failure, Mapping)
    assert not isinstance(failure, dict)
    with pytest.raises(TypeError):
        failure["reason"] = "mutated"  # type: ignore[index]
    with pytest.raises(TypeError):
        failure["details"]["paths"] = ()  # type: ignore[index]

    details["paths"].append("caller_mutation")
    materialized = materialize_model_failure_record(failure)
    assert materialized == materialize_model_failure_record(failure)
    assert materialized["affected_fields"] == ("p_graph", "p_markov", "p_temporal")
    assert materialized["details"]["paths"] == ("b", "a")
    assert materialized["details"]["nested"]["tags"] == ("a", "z")
    json.dumps(materialized, sort_keys=True)


def test_stage1247_cold_start_record_is_explicit_failure_evidence() -> None:
    record = make_cold_start_record(
        model_name="markov",
        reason="insufficient_transition_support",
        required_support=3,
        observed_support=1,
        affected_fields=["probability"],
    )

    materialized = materialize_model_failure_record(record)
    assert materialized["failure_type"] == "cold_start"
    assert materialized["degraded"] is True
    assert materialized["output_affecting"] is True
    assert materialized["required_support"] == 3
    assert materialized["observed_support"] == 1
    with pytest.raises(TypeError):
        record["observed_support"] = 99  # type: ignore[index]


def test_stage1247_probability_feature_build_failure_emits_model_failure_record() -> None:
    bundle = probability_feature_build_failed_bundle()
    materialized = materialize_model_feature_bundle(bundle)

    assert materialized["model_version"] == "adaptive_probability_features_v2"
    assert materialized["p_markov"] == 0.0
    assert materialized["p_markov_unavailable_reason"] == "probability_feature_build_failed"
    assert materialized["model_failure"]["reason"] == "probability_feature_build_failed"
    assert materialized["model_failure"]["output_affecting"] is True
    assert "p_markov" in materialized["model_failure"]["affected_fields"]

    projected = log_odds_feature_probabilities(LogOddsFeatureProbabilitiesRequest(
        bundle,
        profile_meta={},
        markov_meta={},
        cluster_meta={},
        bv_bucket={},
        bv_vector={},
        bv_timeline={},
        layer_probs={},
    ))
    assert projected["model_failure"]["failure_type"] == "feature_build_failed"
    json.dumps(projected["model_failure"], sort_keys=True)


def test_stage1247_normal_log_odds_metadata_has_model_failure_field_without_failure() -> None:
    _score, meta = calibrated_log_odds_score_100(
        20.0,
        attack_mapping_result=unavailable_attack_mapping_fixture(),
        chain_evidence=adaptive_chain_evidence_fixture(tags=["contextual_identity"], api_calls=None, ordered_events=[]),
        tags=["contextual_identity"],
        yara_hits=[],
        node=None,
        prev_stage="unknown",
        curr_stage="unknown",
        ordered_events=[],
    )

    assert "model_failure" in meta["feature_probabilities"]
    assert meta["feature_probabilities"]["model_failure"] is None
