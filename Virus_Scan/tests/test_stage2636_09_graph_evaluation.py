"""Stage2636.09 labeled graph-model evaluation acceptance gates."""
from __future__ import annotations

from tools.evaluation.evaluate_graph_model import evaluate_graph_model


def test_stage2636_09_graph_evaluation_acceptance() -> None:
    report = evaluate_graph_model()
    holdout = report["holdout"]

    assert report["partition_evidence"]["source_package_overlap_count"] == 0
    assert report["selected_validation_candidate"]["candidate"] == "selected_production"
    assert holdout["accuracy"] >= 0.95
    assert holdout["malicious_recall"] >= 0.95
    assert holdout["false_positive_rate"] <= 0.05
    assert holdout["separation_margin"] > 0.0
    assert report["execution_detection_recall"] >= 0.90
    assert all(value > 0.0 for value in report["incremental_component_value"].values())
    assert report["cache_correctness"]["hit_correct"] is True
    assert report["cache_correctness"]["mutation_invalidated"] is True
    assert report["corruption_behavior"]["reason"] == "graph_snapshot_digest_mismatch"
    assert report["duplicate_evidence_stability"]["stable"] is True
    assert report["replay_determinism"]["exact_replay_deterministic"] is True
    assert report["replay_determinism"]["order_metric_deterministic"] is True
    assert report["process_determinism"]["deterministic"] is True
    assert report["resource_bounds"]["bounded"] is True
    assert report["all_acceptance_passed"] is True
