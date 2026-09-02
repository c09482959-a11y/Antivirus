"""Stage 1438 Phase 2 regression tests for graph package ownership."""
from __future__ import annotations

import ast
from pathlib import Path

from Virus_Scan.models import graph
from Virus_Scan.models.graph import attention, evidence, relationships, scan

GRAPH_PACKAGE = Path("Virus_Scan/models/graph")


def _all_graph_imports() -> set[str]:
    imports: set[str] = set()
    for path in sorted(GRAPH_PACKAGE.glob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module:
                imports.add(node.module)
            elif isinstance(node, ast.Import):
                imports.update(alias.name for alias in node.names)
    return imports


def test_stage1438_graph_is_package_not_mixed_monolith() -> None:
    assert not Path("Virus_Scan/models/graph.py").exists()
    expected = {
        "__init__.py",
        "attention.py",
        "cache.py",
        "chains.py",
        "cluster_projection.py",
        "common.py",
        "evidence.py",
        "features.py",
        "influence.py",
        "links.py",
        "method_graph.py",
        "relationships.py",
        "risk.py",
        "scan.py",
        "stage.py",
        "state.py",
    }
    assert expected.issubset({path.name for path in GRAPH_PACKAGE.glob("*.py")})
    assert all(len(path.read_text(encoding="utf-8").splitlines()) < 260 for path in GRAPH_PACKAGE.glob("*.py"))


def test_stage1438_graph_public_exports_resolve_to_canonical_owner_modules() -> None:
    assert graph.compute_graph_relationship_layer is relationships.compute_graph_relationship_layer
    assert graph.propagate_graph_attention is attention.propagate_graph_attention
    assert graph.causal_entity_lineage_overlay is evidence.causal_entity_lineage_overlay
    assert graph.scan_cs is scan.scan_cs


def test_stage1438_graph_package_uses_public_contracts_without_forbidden_imports() -> None:
    imports = _all_graph_imports()
    assert "Virus_Scan.runtime.scan_dependencies" not in imports
    assert "Virus_Scan.models.temporal" not in imports
    assert "Virus_Scan.models.markov" not in imports
    assert "Virus_Scan.models.api.markov_contracts" in imports
    assert "Virus_Scan.contracts.yara_hits" not in imports
