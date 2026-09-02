from __future__ import annotations

import ast
from pathlib import Path


def _imports_from(path: Path) -> list[tuple[str, tuple[str, ...]]]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    imports: list[tuple[str, tuple[str, ...]]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            module = "." * node.level + (node.module or "")
            imports.append((module, tuple(alias.name for alias in node.names)))
    return imports


def test_detection_scoring_uses_public_model_signal_contracts() -> None:
    scoring_files = [
        Path("Virus_Scan/detection/scoring/adaptive/model_score.py"),
        Path("Virus_Scan/detection/scoring/weighting/context_confidence.py"),
    ]
    private_model_signals = {
        "_adaptive_markov_signal",
        "_adaptive_cluster_signal",
        "_adaptive_profile_signal",
        "_context_cluster_quality",
    }
    offenders: list[str] = []
    for path in scoring_files:
        for module, names in _imports_from(path):
            if module.startswith("Virus_Scan.models"):
                leaked = private_model_signals.intersection(names)
                if leaked:
                    offenders.append(f"{path}:{module}:{sorted(leaked)}")
    assert offenders == []


def test_production_cross_domain_imports_do_not_reach_private_symbols() -> None:
    domains = {"runtime", "routing", "scanners", "detection", "scheduler", "publication", "models"}
    offenders: list[str] = []
    for path in Path("Virus_Scan").rglob("*.py"):
        if "__pycache__" in path.parts or "tests" in path.parts:
            continue
        parts = path.parts
        if len(parts) < 3:
            continue
        source_domain = parts[1]
        if source_domain not in domains:
            continue
        for module, names in _imports_from(path):
            if module.startswith(".") or not module.startswith("Virus_Scan."):
                continue
            module_parts = module.split(".")
            if len(module_parts) < 2:
                continue
            target_domain = module_parts[1]
            if target_domain == source_domain or target_domain not in domains:
                continue
            leaked = [name for name in names if name.startswith("_")]
            if leaked:
                offenders.append(f"{path}:{module}:{sorted(leaked)}")
    assert offenders == []
