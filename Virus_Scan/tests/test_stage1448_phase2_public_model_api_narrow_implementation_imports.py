"""Stage 1448 Phase 2 public model API import boundary regressions."""
from __future__ import annotations

import ast
from pathlib import Path


PUBLIC_API_FILES = (
    "Virus_Scan/models/api/adaptive_signals.py",
    "Virus_Scan/models/api/clustering_contracts.py",
    "Virus_Scan/models/api/graph_contracts.py",
    "Virus_Scan/models/api/temporal_contracts.py",
)

FORBIDDEN_PACKAGE_ROOT_IMPORTS = (
    "Virus_Scan.models.clustering",
    "Virus_Scan.models.graph",
    "Virus_Scan.models.temporal",
)


def _imports(path: str) -> set[str]:
    tree = ast.parse(Path(path).read_text(encoding="utf-8"))
    modules: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            modules.update(alias.name for alias in node.names)
        if isinstance(node, ast.ImportFrom) and node.module:
            modules.add(node.module)
    return modules


def test_stage1448_public_model_api_does_not_import_package_root_implementation_surfaces() -> None:
    for path in PUBLIC_API_FILES:
        imported = _imports(path)
        assert not (set(FORBIDDEN_PACKAGE_ROOT_IMPORTS) & imported), (path, imported)


def test_stage1448_public_model_api_imports_canonical_bounded_owner_modules() -> None:
    assert "Virus_Scan.models.clustering.assignment" in _imports("Virus_Scan/models/api/clustering_contracts.py")
    assert "Virus_Scan.models.graph.relationships" in _imports("Virus_Scan/models/api/graph_contracts.py")
    assert "Virus_Scan.models.temporal.api" in _imports("Virus_Scan/models/api/temporal_contracts.py")
    adaptive_imports = _imports("Virus_Scan/models/api/adaptive_signals.py")
    assert "Virus_Scan.models.clustering.anomaly" in adaptive_imports
    assert "Virus_Scan.models.graph.relationships" in adaptive_imports
