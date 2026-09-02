from __future__ import annotations

import ast
from pathlib import Path

import Virus_Scan.models.graph as graph
import Virus_Scan.models.graph.api as graph_api
from Virus_Scan.models.api.bootstrap_registration import MODEL_BOOTSTRAP_MODULE_NAMES


def _imported_modules(path: str) -> tuple[str, ...]:
    tree = ast.parse(Path(path).read_text(encoding="utf-8"))
    modules: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module:
            modules.append(node.module)
        elif isinstance(node, ast.Import):
            modules.extend(alias.name for alias in node.names)
    return tuple(modules)


def test_stage1451_graph_api_is_canonical_public_surface() -> None:
    assert "Virus_Scan.models.graph.api" in MODEL_BOOTSTRAP_MODULE_NAMES
    assert graph.__all__ == graph_api.__all__
    assert graph.scan_cs is graph_api.scan_cs
    assert graph.compute_graph_relationship_layer is graph_api.compute_graph_relationship_layer
    assert graph.link_temporal_to_graph is graph_api.link_temporal_to_graph


def test_stage1451_graph_package_root_imports_api_not_implementation_modules() -> None:
    imports = _imported_modules("Virus_Scan/models/graph/__init__.py")
    assert "Virus_Scan.models.graph.api" in imports
    assert all(
        not module.startswith("Virus_Scan.models.graph.") or module == "Virus_Scan.models.graph.api"
        for module in imports
    )
