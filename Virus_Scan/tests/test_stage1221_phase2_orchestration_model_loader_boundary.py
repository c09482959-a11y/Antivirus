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


def test_orchestration_lifecycle_uses_runtime_model_loader_boundary() -> None:
    imports = _imports_from("Virus_Scan/orchestration/lifecycle.py")
    assert "Virus_Scan.models.clustering" not in imports

    source = (REPO / "Virus_Scan/orchestration/lifecycle.py").read_text(encoding="utf-8")
    assert "load_runtime_model_state()" in source
    assert "from Virus_Scan.orchestration.model_state_loader import load_runtime_model_state" in source


def test_orchestration_model_state_loader_uses_public_clustering_contract() -> None:
    imports = _imports_from("Virus_Scan/orchestration/model_state_loader.py")
    assert "Virus_Scan.models.clustering" not in imports
    assert "Virus_Scan.models.api.clustering_contracts" in imports


def test_runtime_model_loader_preserves_missing_database_snapshot_result(tmp_path: Path) -> None:
    sqlite_lifecycle().close()
    configure_profiles_dir(str(tmp_path / "profiles"))
    assert load_runtime_model_state() is False
    sqlite_lifecycle().close()
