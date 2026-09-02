from __future__ import annotations

import ast
from pathlib import Path


def _import_modules(path: Path) -> tuple[str, ...]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    modules: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            modules.append("." * node.level + (node.module or ""))
        elif isinstance(node, ast.Import):
            modules.extend(alias.name for alias in node.names)
    return tuple(modules)


def test_stage1214_adaptive_model_score_uses_feature_bundle_boundary() -> None:
    imports = _import_modules(Path("Virus_Scan/detection/scoring/adaptive/evidence_projection.py"))
    assert "Virus_Scan.detection.scoring.adaptive.feature_bundle" in imports
    assert not [module for module in imports if module.startswith("Virus_Scan.models")]


def test_stage1214_context_confidence_uses_feature_bundle_boundary() -> None:
    imports = _import_modules(Path("Virus_Scan/detection/scoring/weighting/context_confidence.py"))
    assert "Virus_Scan.detection.scoring.adaptive.feature_bundle" in imports
    assert not [module for module in imports if module.startswith("Virus_Scan.models")]


def test_stage1214_feature_bundle_is_the_only_adaptive_scoring_model_import_boundary() -> None:
    scoring_paths = (
        Path("Virus_Scan/detection/scoring/adaptive/model_score.py"),
        Path("Virus_Scan/detection/scoring/adaptive/evidence_projection.py"),
        Path("Virus_Scan/detection/scoring/adaptive/model_caps.py"),
        Path("Virus_Scan/detection/scoring/adaptive/log_odds_fusion.py"),
        Path("Virus_Scan/detection/scoring/weighting/context_confidence.py"),
    )
    offenders: list[str] = []
    for path in scoring_paths:
        for module in _import_modules(path):
            if module.startswith("Virus_Scan.models"):
                offenders.append(f"{path}:{module}")
    assert offenders == []


def test_stage1214_feature_bundle_imports_public_model_sources_only() -> None:
    imports = _import_modules(Path("Virus_Scan/detection/scoring/adaptive/feature_bundle.py"))
    expected = {
        "Virus_Scan.models.api.adaptive_signals",
        "Virus_Scan.models.api.temporal_contracts",
    }
    forbidden = {
        "Virus_Scan.models.clustering",
        "Virus_Scan.models.graph",
        "Virus_Scan.models.markov",
        "Virus_Scan.models.profiles",
        "Virus_Scan.models.temporal",
    }
    assert expected.issubset(set(imports))
    assert not forbidden.intersection(imports)
    assert not [module for module in imports if module.startswith("Virus_Scan.models.") and "._" in module]
