from __future__ import annotations

import ast
from pathlib import Path

from Virus_Scan.orchestration.model_state_loader import load_runtime_model_state
from Virus_Scan.runtime.config_state import configure_profiles_dir
from Virus_Scan.storage import sqlite_lifecycle


REPO = Path(__file__).resolve().parents[2]


def _imports_from(path: str) -> set[str]:
    tree = ast.parse((REPO / path).read_text(encoding="utf-8"))
    imports: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imports.add(node.module)
    return imports


def test_orchestration_model_state_loader_uses_public_clustering_contract() -> None:
    imports = _imports_from("Virus_Scan/orchestration/model_state_loader.py")
    assert "Virus_Scan.models.clustering" not in imports
    assert "Virus_Scan.models.api.clustering_contracts" in imports


def test_public_clustering_runtime_loader_has_no_snapshot_fallback(tmp_path: Path) -> None:
    sqlite_lifecycle().close()
    configure_profiles_dir(str(tmp_path / "profiles"))
    assert load_runtime_model_state() is False
    sqlite_lifecycle().close()
