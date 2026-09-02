"""Stage2636.04 labeled clustering evaluation acceptance gates."""
from __future__ import annotations

from dataclasses import FrozenInstanceError

import pytest

from tools.evaluation.evaluate_clustering_model import evaluate_clustering_model
from Virus_Scan.models.clustering.policy import CLUSTER_POLICY


def test_stage2636_04_clustering_evaluation_acceptance() -> None:
    report = evaluate_clustering_model()
    holdout = report["holdout"]

    assert report["partition_evidence"]["source_package_overlap_count"] == 0
    assert report["partition_evidence"]["family_source_overlap_count"] == 0
    assert report["selected_validation_candidate"]["name"] == "selected_production"
    assert holdout["false_merge_rate"] <= 0.05
    assert holdout["false_split_rate"] <= 0.10
    assert holdout["pair_precision"] >= 0.95
    assert holdout["pair_recall"] >= 0.90
    assert holdout["cluster_purity"] >= 0.95
    assert holdout["adjusted_rand_index"] >= 0.90
    assert holdout["normalized_mutual_information"] >= 0.90
    assert holdout["benign_suppression_false_positive_rate"] <= 0.05
    assert holdout["benign_suppression_false_negative_rate"] <= 0.05
    assert holdout["malicious_family_grouping_recall"] >= 0.90
    assert holdout["unknown_outlier_rejection_rate"] >= 0.90
    assert report["poisoning_resistance"]["quarantine_centroid_unchanged"] is True
    assert report["poisoning_resistance"]["trusted_outlier_centroid_unchanged"] is True
    assert report["poisoning_resistance"]["trusted_outlier_update_applied"] is False
    assert report["replay_determinism"]["deterministic"] is True
    assert report["order_determinism"]["deterministic"] is True
    assert report["all_acceptance_passed"] is True


def test_stage2636_04_selected_threshold_manifest_is_immutable() -> None:
    with pytest.raises(FrozenInstanceError):
        CLUSTER_POLICY.benign_reuse_threshold = 0.0
