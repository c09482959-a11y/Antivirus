from Virus_Scan.tests.support.adaptive_chain_fixtures import adaptive_chain_evidence_fixture
from Virus_Scan.tests.support.attack_mapping_contract_fixtures import unavailable_attack_mapping_fixture
from Virus_Scan.detection.scoring.adaptive.model_score import (
    calibrated_log_odds_score_100,
    learn_adaptive_layer_weights,
)


class _BadModelPath:
    def __str__(self):
        raise ValueError("adaptive learning path coercion failed")


def test_adaptive_learning_bucket_vector_failure_keeps_evidence_metadata():
    _weights, meta = learn_adaptive_layer_weights(
        _BadModelPath(),
        ["script_execution"],
        
        {"score": 0.0},
        {"score": 0.0},
        {"score": 0.0},
        {"score": 0.0},
        ordered_events=["script_execution"],
    )

    bucket_vector = meta["bucket_vector"]
    assert bucket_vector["ready"] is False
    assert bucket_vector["reason"] == "coordinated_model_validation_failed"
    assert bucket_vector["bucket_validation"]["bucket_anomaly"] == 0.0
    assert bucket_vector["bucket_validation"]["unavailable_reason"] == "coordinated_model_validation_failed"
    assert bucket_vector["vector_validation"]["anomaly"] == 0.0
    assert bucket_vector["vector_validation"]["unavailable_reason"] == "coordinated_model_validation_failed"
    assert bucket_vector["timeline_validation"]["anomaly"] == 0.0
    assert bucket_vector["timeline_validation"]["unavailable_reason"] == "coordinated_model_validation_failed"


def test_log_odds_metadata_preserves_adaptive_learning_failure_reasons():
    _weights, adaptive_learning = learn_adaptive_layer_weights(
        _BadModelPath(),
        ["script_execution"],
        
        {"score": 0.0},
        {"score": 0.0},
        {"score": 0.0},
        {"score": 0.0},
        ordered_events=["script_execution"],
    )

    _score, meta = calibrated_log_odds_score_100(
        5.0,
        attack_mapping_result=unavailable_attack_mapping_fixture(),
        chain_evidence=adaptive_chain_evidence_fixture(tags=["script_execution"], api_calls=None, ordered_events=["script_execution"]),
        tags=["script_execution"],
        yara_hits=[],
        node="stable_model_node.py",
        prev_stage="unknown",
        curr_stage="script",
        adaptive_learning=adaptive_learning,
        ordered_events=["script_execution"],
    )

    features = meta["feature_probabilities"]
    assert features["bucket_unavailable_reason"] == "coordinated_model_validation_failed"
    assert features["vector_unavailable_reason"] == "coordinated_model_validation_failed"
    assert features["temporal_unavailable_reason"] == "coordinated_model_validation_failed"
