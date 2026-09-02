from __future__ import annotations

from tools.evaluation.evaluate_chain_model import evaluate_chain_model


def test_chain_evaluation_matrix_clears_quality_and_runtime_gates() -> None:
    report = evaluate_chain_model()
    assert report["positive_detection_recall"] == 1.0
    assert report["confirmed_chain_recall"] == 1.0
    assert report["confirmed_chain_precision_on_fixture_matrix"] == 1.0
    assert report["candidate_partial_conversion_accuracy"] == 1.0
    assert report["unordered_cooccurrence_confirmed_false_positives"] == 0
    assert report["unordered_cooccurrence_status"] == "candidate"
    assert report["benign_confirmed_false_positives"] == 0
    assert report["benign_scoreable_false_positives"] == 0
    assert report["duplicate_root_multi_signal_inflation_count"] == 0
    assert report["deterministic_replay"] is True
    assert report["maximum_decision_count"] <= report["decision_bound"]
    assert report["runtime_within_bound"] is True
