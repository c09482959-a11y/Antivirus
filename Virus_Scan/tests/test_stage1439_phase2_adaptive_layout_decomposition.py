from __future__ import annotations

import ast
from pathlib import Path

from Virus_Scan.detection.scoring.adaptive import model_score

ADAPTIVE = Path("Virus_Scan/detection/scoring/adaptive")


def _source(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _functions(path: Path) -> set[str]:
    tree = ast.parse(_source(path), filename=str(path))
    return {node.name for node in ast.walk(tree) if isinstance(node, ast.FunctionDef)}


def _import_modules(path: Path) -> set[str]:
    tree = ast.parse(_source(path), filename=str(path))
    modules: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module:
            modules.add(node.module)
        elif isinstance(node, ast.Import):
            modules.update(alias.name for alias in node.names)
    return modules


def test_stage1439_adaptive_model_score_is_public_projection_not_monolith() -> None:
    model_score = ADAPTIVE / "model_score.py"
    assert model_score.exists()
    assert len(_source(model_score).splitlines()) <= 120
    assert _functions(model_score) == set()


def test_stage1439_adaptive_behavior_lives_in_bounded_owner_modules() -> None:
    owners = {
        "availability.py": {"probability_feature_unavailable_reason", "available_feature_probability"},
        "confidence.py": {"adaptive_learned_model_confidence", "adaptive_learned_model_weight_from_confidence"},
        "evidence_projection.py": {"build_probability_features"},
        "layer_weights.py": {"learn_adaptive_layer_weights"},
        "log_odds_fusion.py": {"calibrated_log_odds_score_100"},
        "log_odds_weights.py": {"derive_log_odds_weights", "apply_log_odds_concrete_caps"},
        "model_caps.py": {"hybrid_static_model_evidence_fusion"},
        "model_inputs.py": {"cluster_probability_feature", "graph_chain_probability_from_layer"},
        "settings.py": set(),
    }
    for filename, expected in owners.items():
        path = ADAPTIVE / filename
        assert path.exists(), filename
        assert len(_source(path).splitlines()) <= 260, filename
        assert expected <= _functions(path), filename


def test_stage1439_adaptive_owners_do_not_import_model_internals_directly() -> None:
    offenders: list[str] = []
    for path in ADAPTIVE.glob("*.py"):
        if path.name == "feature_bundle.py":
            continue
        for module in _import_modules(path):
            if module.startswith("Virus_Scan.models"):
                offenders.append(f"{path}:{module}")
    assert offenders == []


def test_stage1439_adaptive_public_api_preserves_existing_scoring_exports() -> None:
    assert model_score.build_probability_features.__module__.endswith("evidence_projection")
    assert model_score.calibrated_log_odds_score_100.__module__.endswith("log_odds_fusion")
    assert model_score.hybrid_static_model_evidence_fusion.__module__.endswith("model_caps")
    assert model_score.learn_adaptive_layer_weights.__module__.endswith("layer_weights")
