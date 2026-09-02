"""Stage 1212: filetype validation contracts must not depend on scoring policy modules."""
from __future__ import annotations

import ast
from pathlib import Path

from Virus_Scan.detection.contracts.filetype_context import filetype_validation_context
from Virus_Scan.detection.contracts.tag_validation import validate_tags_for_path


def test_filetype_context_preserves_nonexec_high_risk_bucket_contract() -> None:
    context = filetype_validation_context("media", "soundtrack.ogg")
    assert context["active_bucket"] == "asset_audio"
    assert context["execution_capability"] == "none"
    assert {"os_execution", "credential", "persistence", "injection", "evasion"}.issubset(
        context["high_risk_buckets"]
    )


def test_filetype_context_does_not_import_scoring_policy_constants() -> None:
    path = Path("Virus_Scan/detection/contracts/filetype_context.py")
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    imports = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            imports.append(node.module or "")
        elif isinstance(node, ast.Import):
            imports.extend(alias.name for alias in node.names)
    assert "Virus_Scan.detection.scoring.weighting.policy_constants" not in imports
    assert not any(module.startswith("Virus_Scan.detection.scoring") for module in imports)


def test_tag_validation_contract_does_not_import_scoring_policy_constants() -> None:
    path = Path("Virus_Scan/detection/contracts/tag_validation.py")
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    imports = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            imports.append(node.module or "")
        elif isinstance(node, ast.Import):
            imports.extend(alias.name for alias in node.names)
    assert "Virus_Scan.detection.scoring.weighting.policy_constants" not in imports
    assert not any(module.startswith("Virus_Scan.detection.scoring") for module in imports)


def test_tag_validation_preserves_broad_unvalidated_suppression() -> None:
    assert validate_tags_for_path(["network_activity"], "plain.txt", "plain text", source="raw") == []


def test_model_projections_do_not_import_scoring_policy_constants_for_registry_values() -> None:
    path = Path("Virus_Scan/detection/correlation/multi_signal/model_projections.py")
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    imports = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            imports.append(node.module or "")
        elif isinstance(node, ast.Import):
            imports.extend(alias.name for alias in node.names)
    assert "Virus_Scan.detection.scoring.weighting.policy_constants" not in imports
