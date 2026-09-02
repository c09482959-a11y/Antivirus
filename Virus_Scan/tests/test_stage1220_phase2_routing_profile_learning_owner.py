from __future__ import annotations

import ast
from pathlib import Path

from Virus_Scan.models import profiles as profile_model

ENGINE_DETECT = Path("Virus_Scan/routing/engine_detect.py")
PROFILE_MODEL = Path("Virus_Scan/models/profiles/learning_gate.py")


def _function_names(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=path.as_posix())
    return {node.name for node in ast.walk(tree) if isinstance(node, ast.FunctionDef)}


def _imported_names_from(path: Path, module: str) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=path.as_posix())
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module == module:
            names.update(alias.name for alias in node.names)
    return names


def test_stage1220_routing_no_longer_owns_profile_learning_rejection() -> None:
    assert "record_learning_rejection" not in _function_names(ENGINE_DETECT)
    assert "record_learning_rejection" in _function_names(PROFILE_MODEL)


def test_stage1220_engine_detect_does_not_import_profile_save_mutator() -> None:
    imported = _imported_names_from(ENGINE_DETECT, "Virus_Scan.models.profiles")
    assert "save_engine_profile" not in imported
    assert "record_learning_rejection" not in imported


def test_stage1220_profile_model_retains_learning_rejection_owner() -> None:
    assert callable(profile_model.record_learning_rejection)
    assert profile_model.record_learning_rejection.__module__ == "Virus_Scan.models.profiles.learning_gate"
