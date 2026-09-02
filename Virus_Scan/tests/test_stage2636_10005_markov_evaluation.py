"""Stage2636.01 deterministic Markov evaluation acceptance tests."""
from __future__ import annotations

import ast
from pathlib import Path

from tools.evaluation.evaluate_markov_model import evaluate_markov_model


def test_markov_holdout_evaluation_clears_statistical_acceptance() -> None:
    report = evaluate_markov_model()

    assert report["all_acceptance_checks_pass"] is True
    assert all(report["acceptance"].values())
    assert report["corpus"]["group_overlap_count"] == 0
    assert report["corpus"]["source_package_overlap_count"] == 0
    assert report["corpus"]["exact_flow_overlap_count"] == 0
    assert report["holdout"]["roc_auc"] >= 0.90
    assert report["holdout"]["pr_auc"] >= 0.90
    assert report["holdout"]["classification"]["false_positive_rate"] <= 0.05
    assert report["holdout"]["malicious_minus_benign_nll"] > 0.0
    assert report["holdout"]["cold_start_benign_false_positive_rate"] == 0.0
    assert report["support_policy"][0]["pair_ready"] is False
    assert report["support_policy"][1]["pair_ready"] is False
    assert report["support_policy"][2]["pair_ready"] is True
    assert report["one_shot_poisoning"]["maximum_confidence_avoided"] is True
    assert report["persistence_replay"]["identical_holdout_evidence_after_reload"] is True


def test_markov_evaluator_uses_canonical_owners_without_detector_duplication() -> None:
    path = Path("tools/evaluation/evaluate_markov_model.py")
    source = path.read_text(encoding="utf-8")
    tree = ast.parse(source, filename=str(path))
    imported_modules: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module:
            imported_modules.add(node.module)
        elif isinstance(node, ast.Import):
            imported_modules.update(alias.name for alias in node.names)

    assert "Virus_Scan.models.markov.posterior" not in imported_modules
    assert "Virus_Scan.models.markov.probability" not in imported_modules
    assert "Virus_Scan.models.markov.features" not in imported_modules
    assert "Virus_Scan.models.markov.learning" not in imported_modules
    assert "Virus_Scan.models.profiles.learning_decision" in imported_modules
    assert "from Virus_Scan.models import markov" in source
    assert "monkeypatch" not in source.lower()
    assert "setattr(" not in source
    assert "__dict__" not in source
    assert "MARKOV_SMOOTHING_ALPHA =" not in source
