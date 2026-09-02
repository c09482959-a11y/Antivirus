"""Stage2636.10006 deterministic temporal statistical evaluation gate."""
from __future__ import annotations

from tools.evaluation.evaluate_temporal_model import evaluate_temporal_model


def test_stage2636_10006_temporal_evaluation_acceptance() -> None:
    report = evaluate_temporal_model()
    assert report["source_packages_are_group_isolated"] is True
    assert report["holdout"]["delayed_execution_recall"] >= 0.95
    assert report["holdout"]["benign_installer_updater_false_positive_rate"] <= 0.05
    assert report["holdout"]["recall_improvement_over_fixed_only"] >= 0.25
    assert (
        report["holdout"]["benign_installer_updater_false_positive_rate"]
        <= report["holdout"]["fixed_only_benign_false_positive_rate"]
    )
    assert report["synthetic_order_separation"]["separated"] is True
    assert report["dwell_calibration"]["engine_fallback"]["dwell_fallback_level"] == "engine"
    assert report["dwell_calibration"]["global_fallback"]["fallback_level"] == "global"
    assert report["hidden_state"]["deterministic"] is True
    assert report["hidden_state"]["half_life_error"] <= 1e-6
    assert report["burst_precision"]["precision"] == 1.0
    assert report["replay_determinism"]["deterministic"] is True
    assert report["one_shot_poisoning"]["bounded"] is True
    assert report["all_acceptance_passed"] is True
