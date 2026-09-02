from __future__ import annotations

from tools.evaluation.evaluate_profile_learning import evaluate_profile_learning


def test_phase9_profile_learning_evaluation_clears_quality_and_runtime_gates() -> None:
    report = evaluate_profile_learning()
    assert report["clean_commit_success"] is True
    assert report["duplicate_learning_rate"] == 0.0
    assert report["process_equivalence"] is True
    assert report["unsafe_cohort"]["malicious_to_benign_contamination_rate"] == 0.0
    assert report["malicious_suppression_rate"] == 0.0
    dangerous = next(
        row for row in report["unsafe_cohort"]["records"]
        if row["cohort"] == "dangerous_anchor"
    )
    assert dangerous["decision_disposition"] == "quarantined"
    assert dangerous["reason"] == "dangerous_anchor_learning_blocked"
    assert report["engine_success_rate"] == 1.0
    assert report["benign_anomaly_false_positive_rate"] == 0.0
    assert report["maturity_matrix"]["cold"]["suppression_authority"] == 0.0
    assert report["maturity_matrix"]["warming"]["suppression_authority"] == 0.35
    assert report["maturity_matrix"]["mature"]["suppression_authority"] == 1.0
    assert report["drift_cohort"]["detected"] is True
    assert report["drift_cohort"]["trusted_count_unchanged"] is True
    assert report["corruption_restart_cohort"]["transaction_rolled_back"] is True
    assert report["corruption_restart_cohort"]["exact_restart_state"] is True
    assert report["corruption_restart_cohort"]["integrity_ok"] is True
    assert report["corruption_restart_cohort"]["sqlite_only"] is True
    assert report["runtime_within_bound"] is True
