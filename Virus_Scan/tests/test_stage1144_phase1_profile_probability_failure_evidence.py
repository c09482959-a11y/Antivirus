from Virus_Scan.tests.support.adaptive_chain_fixtures import adaptive_chain_evidence_fixture
from Virus_Scan.tests.support.attack_mapping_contract_fixtures import unavailable_attack_mapping_fixture
from Virus_Scan.detection.chains.execution.anchors import evaluate_chain_evidence
from Virus_Scan.detection.scoring.adaptive.model_score import (
    build_probability_features,
    calibrated_log_odds_score_100,
)


class _BadModelPath:
    str_calls = 0

    def __str__(self):  # pragma: no cover - must not be invoked
        type(self).str_calls += 1
        raise AssertionError("profile path __str__ was invoked")


def test_probability_features_publish_profile_bucket_vector_failure_evidence():
    _BadModelPath.str_calls = 0
    features = build_probability_features(
        attack_mapping_result=unavailable_attack_mapping_fixture(),
        chain_evidence=evaluate_chain_evidence(),
        tags=["script_execution"],
        yara_hits=[],
        node=None,
        file_structure=_BadModelPath(),
        ordered_events=["script_execution"],
    )

    assert features["p_engine"] == 0.0
    assert features["p_profile"] == 0.0
    assert features["p_bucket"] == 0.0
    assert features["p_vector"] == 0.0
    assert features["p_engine_unavailable_reason"] == "engine_context_probability_failed"
    assert features["p_profile_unavailable_reason"] == "profile_probability_failed"
    assert features["p_bucket_unavailable_reason"] == "bucket_probability_failed"
    assert features["p_vector_unavailable_reason"] == "vector_probability_failed"
    assert _BadModelPath.str_calls == 0


def test_log_odds_metadata_preserves_profile_bucket_vector_failure_evidence():
    _BadModelPath.str_calls = 0
    _score, meta = calibrated_log_odds_score_100(
        10.0,
        attack_mapping_result=unavailable_attack_mapping_fixture(),
        chain_evidence=adaptive_chain_evidence_fixture(tags=["script_execution"], api_calls=None, ordered_events=["script_execution"]),
        tags=["script_execution"],
        yara_hits=[],
        node=_BadModelPath(),
        prev_stage="unknown",
        curr_stage="script",
        ordered_events=["script_execution"],
    )

    features = meta["feature_probabilities"]
    assert features["profile"] == 0.0
    assert features["bucket"] == 0.0
    assert features["vector"] == 0.0
    assert features["engine_unavailable_reason"] == "engine_context_probability_failed"
    assert features["profile_unavailable_reason"] == "profile_probability_failed"
    assert features["bucket_unavailable_reason"] == "bucket_probability_failed"
    assert features["vector_unavailable_reason"] == "vector_probability_failed"
    assert _BadModelPath.str_calls == 0
